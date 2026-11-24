package storage

import (
	"context"
	"errors"
	"slices"
	"time"
)

// FallbackConfig comes from private operator configuration. The hard cap applies
// to physical bytes including reservations from all schools and content classes.
type FallbackConfig struct {
	ID            string
	AccountDomain string
	Root          string
	Limit         int64
	AlertPercent  int
	Scopes        []string
}

// ConfigureFallback registers exactly one private COS budget. Reopening the
// host does not resume a paused or revoked instance or reset its byte ledger.
func (s *Service) ConfigureFallback(ctx context.Context, actor Principal, c FallbackConfig) error {
	if !validID(c.ID) || !validID(c.AccountDomain) || c.Root == "" || c.Limit < 1 || c.Limit > 1<<53-1 ||
		c.AlertPercent < 1 || c.AlertPercent > 100 || len(c.Scopes) == 0 || !validIDList(c.Scopes, 32) {
		return ErrInput
	}
	if err := s.authorize(ctx, actor, "storage.instances.manage", c.ID, Protection{}); err != nil {
		return err
	}
	until := time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)
	schools := slices.Sorted(slices.Values(c.Scopes))
	var admissions []Admission
	for _, scope := range schools {
		for _, class := range []string{"public", "quarantine", "restricted"} {
			admissions = append(admissions, Admission{Class: class, Scope: scope, Plaintext: true, ExpiresAt: until})
		}
	}
	return s.repo.Transaction(ctx, func(tx Transaction) error {
		if err := tx.Lock("instance-registry"); err != nil {
			return err
		}
		i, err := tx.Instance(c.ID)
		if errors.Is(err, ErrNotFound) {
			items, e := tx.Instances(100, "")
			if e != nil {
				return e
			}
			if len(items) >= 100 {
				return ErrCapacity
			}
			for _, other := range items {
				if other.IsFallback() {
					return ErrConflict
				}
			}
			i = Instance{ID: c.ID, Ownership: "fallback", Adapter: "cos", OwnerDomain: "fallback", AccountDomain: c.AccountDomain,
				Root: c.Root, CredentialRef: c.ID, CredentialRevision: 1, Authorized: true, State: "active", ExpiresAt: until,
				QuotaExpiresAt: until, ProviderFree: c.Limit, Limit: c.Limit}
		} else if err != nil {
			return err
		} else {
			if !i.IsFallback() || i.AccountDomain != c.AccountDomain || i.Root != c.Root || i.Used+i.Reserved > c.Limit {
				return ErrConflict
			}
			if i.FallbackLimit == c.Limit && i.AlertPercent == c.AlertPercent && slices.Equal(i.Admissions, admissions) {
				return nil
			}
			if i.Limit == i.FallbackLimit || i.Limit > c.Limit {
				i.Limit = c.Limit
			}
		}
		i.Admissions, i.FallbackLimit, i.AlertPercent, i.ProviderFree = admissions, c.Limit, c.AlertPercent, c.Limit
		i.Revision++
		if err := tx.SaveInstance(i); err != nil {
			return err
		}
		return s.emit(ctx, tx, actor, "storage.instance.fallback_configured", i.ID, i.Revision)
	})
}

type FallbackBudget struct {
	At           time.Time `json:"at"`
	Limit        int64     `json:"limit_bytes"`
	Used         int64     `json:"used_bytes"`
	Reserved     int64     `json:"reserved_bytes"`
	AlertPercent int       `json:"alert_percent"`
	Warning      bool      `json:"warning"`
}

func (s *Service) FallbackBudget(ctx context.Context, p Principal, id string) (FallbackBudget, error) {
	var out FallbackBudget
	if err := s.authorize(ctx, p, "storage.operations.read", "", Protection{}); err != nil {
		return out, err
	}
	err := s.readTx(ctx, func(tx Transaction) error {
		i, err := tx.InstanceSnapshot(id)
		if err != nil {
			return err
		}
		if !i.IsFallback() {
			return ErrNotFound
		}
		out = FallbackBudget{s.now(), i.FallbackLimit, i.Used, i.Reserved, i.AlertPercent, i.capacityWarning()}
		return nil
	})
	return out, err
}
