package storage

import (
	"context"
	"time"
)

// Only the private instance ledger records directory maintenance outcomes.
type RootNameReceipt struct {
	Status    string
	CheckedAt time.Time
}

func (s *Service) resolveDriver(ctx context.Context, i Instance) (Driver, error) {
	driver, err := s.resolver.Resolve(ctx, i)
	if err == nil {
		s.migrateRootName(ctx, i, false)
	}
	return driver, err
}

// Both callers have already opened the session as part of a normal operation.
// Only periodic quota observation revisits a failed migration.
func (s *Service) migrateRootName(ctx context.Context, i Instance, periodic bool) {
	if i.Adapter != "bhpan" || i.Ownership != "contributor" || !i.Authorized || i.State == "revoked" ||
		i.ClosureDraining || !i.ExpiresAt.After(s.now()) || i.RootNameReceipt.Status == "confirmed" ||
		(!periodic && i.RootNameReceipt.Status != "") {
		return
	}
	driver, ok := s.verifier.(interface {
		MigrateRootName(context.Context, Instance) error
	})
	if !ok {
		return
	}
	work, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	err := driver.MigrateRootName(work, i)
	status := "confirmed"
	if err != nil {
		status = diagnosticCategory(err)
		s.observe("contribution_root_name", i.ID, "", err)
	}
	record, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer stop()
	err = s.repo.Transaction(record, func(tx Transaction) error {
		current, err := tx.Instance(i.ID)
		if err != nil {
			return err
		}
		if current.CredentialRevision != i.CredentialRevision || current.Root != i.Root || current.AccountDomain != i.AccountDomain || current.RootNameReceipt.Status == "confirmed" {
			return nil
		}
		current.RootNameReceipt = RootNameReceipt{Status: status, CheckedAt: s.now().UTC()}
		return tx.SaveInstance(current)
	})
	s.observe("contribution_root_name", i.ID, "", err)
}
