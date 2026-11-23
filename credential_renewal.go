package storage

import (
	"context"
	"time"
)

type CredentialRenewal struct {
	OwnerDomain        string `json:",omitempty"`
	AccountDomain      string `json:",omitempty"`
	Root               string `json:",omitempty"`
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
	if !validID(q.ID) || !validID(q.CredentialRef) || q.ExpectedRevision < 1 || q.CredentialRevision < 2 {
		return out, ErrInput
	}
	guard := func(Transaction) error { return s.authorize(ctx, p, "storage.instances.manage", q.ID, Protection{}) }
	if hit, e := s.checkIdempotency(ctx, p, "storage.instances.reauthorize", q.ID, key, q, guard, &out); e != nil || hit {
		return out, e
	}
	if !q.Until.After(s.now()) {
		return out, ErrInput
	}
	e := s.repo.Transaction(ctx, func(tx Transaction) error { var e error; old, e = tx.Instance(q.ID); return e })
	if e != nil {
		return out, e
	}
	if q.OwnerDomain != "" && (old.Ownership != "contributor" || old.OwnerDomain != q.OwnerDomain || old.AccountDomain != q.AccountDomain || old.Root != q.Root) {
		return out, ErrDenied
	}
	replay := old.State != "revoked" && old.Authorized && old.Revision >= q.ExpectedRevision && old.CredentialRevision == q.CredentialRevision && old.CredentialRef == q.CredentialRef && old.ExpiresAt.Equal(q.Until)
	var evidence InstanceEvidence
	verified := false
	if !replay {
		if old.Revision < q.ExpectedRevision || old.CredentialRef != q.CredentialRef || q.CredentialRevision != old.CredentialRevision+1 || old.State == "revoked" {
			return out, ErrConflict
		}
		candidate := old
		candidate.CredentialRevision = q.CredentialRevision
		candidate.ExpiresAt = q.Until
		candidate.Authorized = true
		evidence, e = s.verifier.Verify(ctx, candidate)
		if e != nil {
			return out, e
		}
		if evidence.AccountDomain != old.AccountDomain || evidence.VerifiedAt.Before(s.now().Add(-time.Minute)) || evidence.VerifiedAt.After(s.now().Add(time.Minute)) {
			return out, ErrDenied
		}
		verified = true
	}
	e = s.mutation(ctx, p, "storage.instances.reauthorize", q.ID, key, q, guard, func(tx Transaction) (any, error) {
		current, e := tx.Instance(q.ID)
		if e != nil {
			return nil, e
		}
		if current.OwnerDomain != old.OwnerDomain || current.AccountDomain != old.AccountDomain || current.Root != old.Root || current.Ownership != old.Ownership {
			return nil, ErrDenied
		}
		if current.State != "revoked" && current.Authorized && current.Revision >= q.ExpectedRevision && current.CredentialRevision == q.CredentialRevision && current.CredentialRef == q.CredentialRef && current.ExpiresAt.Equal(q.Until) {
			return current, nil
		}
		if replay || current.Revision < q.ExpectedRevision || current.CredentialRevision != old.CredentialRevision || current.State == "revoked" {
			return nil, ErrConflict
		}
		if q.OwnerDomain != "" && (!current.quotaLedgerMatches(old) || !evidence.validQuota(s.now())) {
			return nil, ErrConflict
		}
		current.CredentialRevision = q.CredentialRevision
		current.ExpiresAt = q.Until
		current.Authorized = true
		if verified {
			s.applyQuotaEvidence(&current, old, evidence)
		}
		current.Revision++
		if e = tx.SaveInstance(current); e != nil {
			return nil, e
		}
		return current, s.emit(ctx, tx, p, "storage.instance.reauthorized", current.ID, current.Revision)
	}, &out)
	return out, e
}
