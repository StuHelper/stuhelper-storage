package storage

import (
	"context"
	"errors"
	"sort"
	"time"
)

// plan locks the bounded candidate set in a stable order before reserving any
// bytes. Every process shares the same PostgreSQL ledger and uniqueness checks.
func (s *Service) plan(tx Transaction, o Object, maximum int) ([]Replica, error) {
	if o.State == "deleting" || o.State == "deleted" {
		return nil, ErrConflict
	}
	replicas, err := tx.Replicas(o.ID)
	if err != nil {
		return nil, err
	}
	candidates, err := tx.Instances(100, "")
	if err != nil {
		return nil, err
	}
	ids := map[string]bool{}
	for _, i := range candidates {
		ids[i.ID] = true
	}
	for _, r := range replicas {
		ids[r.InstanceID] = true
	}
	keys := make([]string, 0, len(ids))
	for id := range ids {
		keys = append(keys, id)
	}
	sort.Strings(keys)
	instances := map[string]Instance{}
	for _, id := range keys {
		i, err := tx.Instance(id)
		if err != nil {
			return nil, err
		}
		instances[id] = i
	}
	accounts := map[string]bool{}
	owners := map[string]bool{}
	byInstance := map[string]Replica{}
	count := 0
	for _, r := range replicas {
		byInstance[r.InstanceID] = r
		i := instances[r.InstanceID]
		if r.State == "deleted" {
			continue
		}
		accounts[i.AccountDomain] = true
		if i.Ownership == "contributor" {
			owners[i.OwnerDomain] = true
		}
		if (r.State == "healthy" || r.State == "reserved" || r.State == "writing" || r.State == "unknown") && !i.Draining(s.now()) && r.ObjectRevision == o.Revision && i.Allows(o.Protection, s.now()) && r.CredentialRevision == i.CredentialRevision {
			count++
		}
	}
	out := []Replica{}
	for _, candidate := range candidates {
		if count >= o.Policy.Target || len(out) >= maximum {
			break
		}
		i := instances[candidate.ID]
		if accounts[i.AccountDomain] || (i.Ownership == "contributor" && owners[i.OwnerDomain]) || !i.CanWrite(o.Protection, o.Size, s.now()) {
			continue
		}
		r, exists := byInstance[i.ID]
		if exists && r.State != "deleted" {
			continue
		}
		if !exists {
			r.ID = newID()
		}
		r.ObjectID = o.ID
		r.InstanceID = i.ID
		r.Intent = newID()
		r.Remote = Locator{}
		r.State = "reserved"
		r.ObjectRevision = o.Revision
		r.InstanceRevision = i.Revision
		r.CredentialRevision = i.CredentialRevision
		r.Size = o.Size
		r.Reserved = true
		r.Accounted = false
		r.IssuedWrite = false
		i.Reserved += o.Size
		if err := tx.SaveInstance(i); err != nil {
			return nil, err
		}
		if err := tx.SaveReplica(r); err != nil {
			return nil, err
		}
		accounts[i.AccountDomain] = true
		if i.Ownership == "contributor" {
			owners[i.OwnerDomain] = true
		}
		out = append(out, r)
		count++
	}
	return out, nil
}

type MaintenanceResult struct {
	Processed  int    `json:"processed"`
	NextCursor string `json:"next_cursor"`
}

// Reconcile is bounded and resumable. Expired unreferenced uploads are tombstoned;
// no operation recursively deletes a provider directory or personal files.
func (s *Service) Reconcile(ctx context.Context, p Principal, limit int, after string) (MaintenanceResult, error) {
	result := MaintenanceResult{}
	if limit < 1 || limit > 100 {
		return result, ErrInput
	}
	if err := s.authorize(ctx, p, "storage.maintenance", "", Protection{}); err != nil {
		return result, err
	}
	var cleanupErr error
	if after == "" {
		cleanupErr = s.cleanupContents(ctx, p, limit)
	}
	var objects []Object
	err := s.repo.Transaction(ctx, func(tx Transaction) error { var err error; objects, err = tx.Objects(limit, after); return err })
	if err != nil {
		return result, err
	}
	for _, snapshot := range objects {
		err = s.repo.Transaction(ctx, func(tx Transaction) error {
			if err := tx.Lock("object:" + snapshot.ID); err != nil {
				return err
			}
			o, err := tx.Object(snapshot.ID)
			if err != nil {
				return err
			}
			if err := s.authorize(ctx, p, "storage.maintenance", o.ID, o.Protection); err != nil {
				return err
			}
			replicas, err := tx.Replicas(o.ID)
			if err != nil {
				return err
			}
			// Acquire the full bounded candidate set before any per-instance reads,
			// including instances already used by this object but outside the page.
			candidates, err := tx.Instances(100, "")
			if err != nil {
				return err
			}
			ids := map[string]bool{}
			for _, candidate := range candidates {
				ids[candidate.ID] = true
			}
			for _, replica := range replicas {
				ids[replica.InstanceID] = true
			}
			ordered := make([]string, 0, len(ids))
			for id := range ids {
				ordered = append(ordered, id)
			}
			sort.Strings(ordered)
			for _, id := range ordered {
				if _, err := tx.Instance(id); err != nil {
					return err
				}
			}
			if o.State != "deleted" && o.State != "deleting" && o.ContentGroup == "" && len(o.References) == 0 && s.now().Sub(o.CreatedAt) >= 24*time.Hour {
				o.State = "deleting"
				if len(replicas) == 0 {
					o.State = "deleted"
				}
				o.Revision++
				if err := tx.SaveObject(o); err != nil {
					return err
				}
				if err := s.emit(tx, p, "storage.object.expired", o.ID, o.Revision); err != nil {
					return err
				}
			}
			for n, r := range replicas {
				if r.State == "deleted" {
					continue
				}
				i, err := tx.Instance(r.InstanceID)
				if err != nil {
					return err
				}
				if i.Authorized && i.State != "revoked" && i.ExpiresAt.After(s.now()) && (i.CredentialRevision != r.CredentialRevision || i.Revision != r.InstanceRevision) {
					r.CredentialRevision = i.CredentialRevision
					r.InstanceRevision = i.Revision
					if r.State == "healthy" {
						r.State = "checking"
					}
					if err := tx.SaveReplica(r); err != nil {
						return err
					}
					replicas[n] = r
					if r.State == "reserved" || r.State == "writing" || r.State == "unknown" {
						kind := "replicate"
						if r.IssuedWrite {
							kind = "ingest"
						}
						if err := s.enqueue(tx, o.ID, r.ID, kind); err != nil {
							return err
						}
					}
				}
				if o.State == "deleting" || o.State == "deleted" || r.State == "cleanup" || r.State == "corrupt" {
					if r.State == "corrupt" {
						r.State = "cleanup"
						replicas[n] = r
						if err := tx.SaveReplica(r); err != nil {
							return err
						}
					}
					if err := s.enqueue(tx, o.ID, r.ID, "delete"); err != nil {
						return err
					}
					continue
				}
				if i.Allows(o.Protection, s.now()) && ((r.State == "healthy" && !r.VerifiedAt.After(s.now().Add(-s.cfg.VerificationAge/2))) || r.State == "checking") {
					if err := s.enqueue(tx, o.ID, r.ID, "verify"); err != nil {
						return err
					}
				}
			}
			if o.State == "deleting" || o.State == "deleted" {
				return nil
			}
			// Reserve only when at least one validated source is still available.
			// Ingest jobs without a source are reconciled, never fabricated from metadata.
			status, err := s.status(tx, o)
			if err != nil {
				return err
			}
			if status.Healthy == 0 {
				return nil
			}
			if err := tx.Lock("queue-budget"); err != nil {
				return err
			}
			queued, err := tx.OutstandingJobs("", s.cfg.MaxOutstandingJobs)
			if err != nil {
				return err
			}
			planned, err := s.plan(tx, o, min(o.Policy.Target, s.cfg.MaxOutstandingJobs-queued))
			if err != nil {
				return err
			}
			for _, r := range planned {
				if err := s.enqueue(tx, o.ID, r.ID, "replicate"); err != nil {
					return err
				}
			}
			// Drain only after replacements are healthy. Revocation can happen sooner,
			// but does not grant permission to keep using the withdrawn credentials.
			replacements := 0
			for _, r := range replicas {
				i, err := tx.Instance(r.InstanceID)
				if err != nil {
					return err
				}
				if r.State == "healthy" && !i.Draining(s.now()) && i.Allows(o.Protection, s.now()) && r.CredentialRevision == i.CredentialRevision && r.ObjectRevision == o.Revision && !r.VerifiedAt.Before(s.now().Add(-s.cfg.VerificationAge)) {
					replacements++
				}
			}
			if replacements >= o.Policy.Target {
				for _, r := range replicas {
					i, err := tx.Instance(r.InstanceID)
					if err != nil {
						return err
					}
					if i.Draining(s.now()) && r.State == "healthy" {
						r.State = "cleanup"
						if err := tx.SaveReplica(r); err != nil {
							return err
						}
						if err := s.enqueue(tx, o.ID, r.ID, "delete"); err != nil {
							return err
						}
					}
				}
			}
			return nil
		})
		if err != nil {
			result.NextCursor = snapshot.ID
			return result, err
		}
		result.Processed++
		result.NextCursor = snapshot.ID
	}
	if len(objects) < limit {
		result.NextCursor = ""
	}
	return result, cleanupErr
}

// RefreshInstance samples capacity only without outstanding writes. This avoids
// counting the same in-flight write both in provider usage and local reservations.
func (s *Service) RefreshInstance(ctx context.Context, p Principal, id string) error {
	if err := s.authorize(ctx, p, "storage.instances.manage", id, Protection{}); err != nil {
		return err
	}
	var snapshot Instance
	if err := s.repo.Transaction(ctx, func(tx Transaction) error {
		var err error
		snapshot, err = tx.Instance(id)
		if err != nil {
			return err
		}
		if !snapshot.Authorized || snapshot.State == "revoked" || !snapshot.ExpiresAt.After(s.now()) {
			return ErrDenied
		}
		if snapshot.Reserved != 0 {
			return ErrConflict
		}
		return nil
	}); err != nil {
		return err
	}
	evidence, err := s.verifier.Verify(ctx, snapshot)
	if err != nil {
		return err
	}
	if evidence.AccountDomain != snapshot.AccountDomain || evidence.ProviderFree < 0 || evidence.VerifiedAt.Before(s.now().Add(-time.Minute)) || evidence.VerifiedAt.After(s.now().Add(time.Minute)) {
		return ErrConflict
	}
	return s.repo.Transaction(ctx, func(tx Transaction) error {
		if err := s.authorize(ctx, p, "storage.instances.manage", id, Protection{}); err != nil {
			return err
		}
		i, err := tx.Instance(id)
		if err != nil {
			return err
		}
		if !i.Authorized || i.State == "revoked" || !i.ExpiresAt.After(s.now()) {
			return ErrDenied
		}
		if i.Revision != snapshot.Revision || i.Reserved != 0 || i.QuotaRevision != snapshot.QuotaRevision {
			return ErrConflict
		}
		i.ProviderFree = evidence.ProviderFree
		i.QuotaExpiresAt = s.now().Add(s.cfg.QuotaValidity)
		i.QuotaRevision++
		return tx.SaveInstance(i)
	})
}

func isMissing(err error) bool { return errors.Is(err, ErrNotFound) }
