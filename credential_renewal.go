package storage

import (
	"context"
	"time"
)

type CredentialRenewal struct {
	ID                 string
	ExpectedRevision   int64
	CredentialRef      string
	CredentialRevision int64
	Until              time.Time
}

// ReauthorizeInstance changes only custody facts. Current contribution, quota,
// state, ownership and admissions are copied inside the committing transaction.
func (s *Service) ReauthorizeInstance(ctx context.Context, p Principal, key string, q CredentialRenewal) (Instance, error) {
	var out, old Instance
	if !validID(q.ID) || !validID(q.CredentialRef) || q.ExpectedRevision < 1 || q.CredentialRevision < 2 || !q.Until.After(s.now()) {
		return out, ErrInput
	}
	if e := s.authorize(ctx, p, "storage.instances.manage", q.ID, Protection{}); e != nil {
		return out, e
	}
	e := s.repo.Transaction(ctx, func(tx Transaction) error { var e error; old, e = tx.Instance(q.ID); return e })
	if e != nil {
		return out, e
	}
	replay := old.CredentialRevision == q.CredentialRevision && old.CredentialRef == q.CredentialRef && old.ExpiresAt.Equal(q.Until)
	if !replay {
		if old.Revision < q.ExpectedRevision || old.CredentialRef != q.CredentialRef || q.CredentialRevision != old.CredentialRevision+1 || old.State == "revoked" {
			return out, ErrConflict
		}
		candidate := old
		candidate.CredentialRevision = q.CredentialRevision
		candidate.ExpiresAt = q.Until
		candidate.Authorized = true
		evidence, e := s.verifier.Verify(ctx, candidate)
		if e != nil {
			return out, e
		}
		if evidence.AccountDomain != old.AccountDomain || evidence.VerifiedAt.Before(s.now().Add(-time.Minute)) || evidence.VerifiedAt.After(s.now().Add(time.Minute)) {
			return out, ErrDenied
		}
	}
	e = s.mutation(ctx, p, "storage.instances.reauthorize", q.ID, key, q, func(tx Transaction) error { return s.authorize(ctx, p, "storage.instances.manage", q.ID, Protection{}) }, func(tx Transaction) (any, error) {
		if replay {
			return nil, ErrConflict
		}
		current, e := tx.Instance(q.ID)
		if e != nil {
			return nil, e
		}
		if current.Revision < q.ExpectedRevision || current.CredentialRevision != old.CredentialRevision || current.State == "revoked" {
			return nil, ErrConflict
		}
		current.CredentialRevision = q.CredentialRevision
		current.ExpiresAt = q.Until
		current.Authorized = true
		current.Revision++
		if e = tx.SaveInstance(current); e != nil {
			return nil, e
		}
		return current, s.emit(tx, p, "storage.instance.reauthorized", current.ID, current.Revision)
	}, &out)
	return out, e
}
