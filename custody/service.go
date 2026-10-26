package custody

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	storage "github.com/StuHelper/stuhelper-storage"
)

func (s *Service) List(ctx context.Context, p storage.Principal, n int, after string, admin bool) (Page, error) {
	out := Page{Items: []View{}}
	if n < 1 || n > 100 || (after != "" && !uuid.MatchString(after)) {
		return out, storage.ErrInput
	}
	action := "storage.custody.read"
	owner := p
	if admin {
		action = "storage.custody.operations.read"
		owner = storage.Principal{}
	}
	if e := s.authorize(ctx, p, action, ""); e != nil {
		return out, e
	}
	e := s.repo.Transaction(ctx, func(tx Tx) error {
		rows, e := tx.List(owner, n+1, after)
		if e != nil {
			return e
		}
		if len(rows) > n {
			rows = rows[:n]
			out.NextCursor = rows[n-1].ID
		}
		for _, b := range rows {
			out.Items = append(out.Items, b.View)
		}
		return s.authorize(ctx, p, action, "")
	})
	return out, e
}
func (s *Service) GetRequest(ctx context.Context, p storage.Principal, key string) (View, error) {
	var out View
	if !uuid.MatchString(key) {
		return out, storage.ErrInput
	}
	if e := s.authorize(ctx, p, "storage.custody.read", ""); e != nil {
		return out, e
	}
	e := s.repo.Transaction(ctx, func(tx Tx) error {
		o, e := tx.Operation(key)
		if e != nil {
			return e
		}
		if o.Owner != p {
			return storage.ErrDenied
		}
		b, e := tx.Binding(o.BindingID)
		if e != nil {
			return e
		}
		out = b.View
		return s.authorize(ctx, p, "storage.custody.read", b.ID)
	})
	return out, e
}
func (s *Service) Submit(ctx context.Context, p storage.Principal, target, key string, q Request) (View, error) {
	var out View
	if !uuid.MatchString(key) || (target != "" && !uuid.MatchString(target)) || q.Adapter != "bhpan" || !q.Until.After(s.cfg.Clock().Add(time.Minute)) || q.Until.After(s.cfg.Clock().Add(time.Duration(s.cfg.Policy.MaxTermSeconds)*time.Second)) || !q.Consent.Accepted || q.Consent.Version != s.cfg.Policy.Version || q.Consent.Digest != s.cfg.Policy.Digest || target == "" && q.Revision != 0 || target != "" && q.Revision < 1 {
		return out, storage.ErrInput
	}
	if e := s.authorize(ctx, p, "storage.custody.manage", target); e != nil {
		return out, e
	}
	if e := s.provider.ValidateInput(q.Adapter, q.Credential); e != nil {
		return out, e
	}
	// Canonicalize credential JSON before the keyed fingerprint; whitespace is
	// not a different request. No raw password or public password hash is stored.
	var fields map[string]string
	if json.Unmarshal(q.Credential, &fields) != nil {
		return out, storage.ErrInput
	}
	canonical, e := json.Marshal(fields)
	if e != nil {
		return out, storage.ErrInput
	}
	defer clear(canonical)
	q.Credential = canonical
	payload, e := json.Marshal(struct {
		Target  string
		Request Request
	}{target, q})
	if e != nil {
		return out, storage.ErrInput
	}
	defer clear(payload)
	fingerprint, e := s.provider.Fingerprint(payload)
	if e != nil {
		return out, e
	}
	e = s.repo.Transaction(ctx, func(tx Tx) error {
		if old, e := tx.Operation(key); e == nil {
			if old.Owner != p || old.Fingerprint != fingerprint {
				return storage.ErrConflict
			}
			b, e := tx.Binding(old.BindingID)
			out = b.View
			return e
		} else if !errors.Is(e, storage.ErrNotFound) {
			return e
		}
		count, e := tx.OperationCount()
		if e != nil {
			return e
		}
		if count >= 1000 {
			return storage.ErrCapacity
		}
		var b Binding
		if target == "" {
			count, e = tx.Count(storage.Principal{})
			if e != nil {
				return e
			}
			owned, e := tx.Count(p)
			if e != nil {
				return e
			}
			if count >= 100 || owned >= 5 {
				return storage.ErrCapacity
			}
			target = key
			b = Binding{View: View{ID: target, Adapter: q.Adapter}, Owner: p}
		} else {
			b, e = tx.Binding(target)
			if e != nil {
				return e
			}
			if b.Owner != p {
				return storage.ErrDenied
			}
			if b.Revision != q.Revision || b.State == "pending" || b.State == "blocked" {
				return storage.ErrConflict
			}
		}
		b.Revision++
		b.State = "pending"
		b.Until = q.Until
		b.RequestID = key
		b.LastError = ""
		o := Operation{ID: key, BindingID: target, Owner: p, Fingerprint: fingerprint, Consent: q.Consent, Until: q.Until}
		if e = s.authorize(ctx, p, "storage.custody.manage", target); e != nil {
			return e
		}
		if e = tx.SaveBinding(b); e != nil {
			return e
		}
		if e = tx.SaveOperation(o); e != nil {
			return e
		}
		out = b.View
		return s.event(tx, p, b, "requested")
	})
	if e != nil {
		return out, e
	}
	if out.RequestID != key {
		return out, storage.ErrConflict
	}
	return s.run(ctx, p, out.ID, ResumeRequest{key, out.Revision}, q.Credential, false)
}
func (s *Service) Resume(ctx context.Context, p storage.Principal, target string, q ResumeRequest, admin bool) (View, error) {
	return s.run(ctx, p, target, q, nil, admin)
}

func (s *Service) run(ctx context.Context, p storage.Principal, target string, q ResumeRequest, input json.RawMessage, admin bool) (View, error) {
	var out View
	var b Binding
	var op Operation
	if !uuid.MatchString(target) || !uuid.MatchString(q.RequestID) || q.Revision < 1 {
		return out, storage.ErrInput
	}
	action := "storage.custody.manage"
	if admin {
		action = "storage.custody.operations.resume"
	}
	if e := s.authorize(ctx, p, action, target); e != nil {
		return out, e
	}
	e := s.repo.Transaction(ctx, func(tx Tx) error {
		var e error
		b, e = tx.Binding(target)
		if e != nil {
			return e
		}
		if !admin && b.Owner != p {
			return storage.ErrDenied
		}
		if b.Revision != q.Revision || b.RequestID != q.RequestID {
			return storage.ErrConflict
		}
		op, e = tx.Operation(q.RequestID)
		if e != nil {
			return e
		}
		out = b.View
		if op.Complete {
			return nil
		}
		if op.LeaseUntil.After(s.cfg.Clock()) {
			return storage.ErrUnavailable
		}
		if op.Attempts >= 5 {
			return storage.ErrCapacity
		}
		op.Attempts++
		op.LeaseUntil = s.cfg.Clock().Add(2 * time.Minute)
		return tx.SaveOperation(op)
	})
	if e != nil || op.Complete {
		return out, e
	}
	work, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	claim := func(account string) error {
		if !id.MatchString(account) {
			return storage.ErrDenied
		}
		instances, e := s.store.Instances(work, s.cfg.Actor, 100, "")
		if e != nil {
			return e
		}
		for _, i := range instances {
			if i.AccountDomain == account && i.ID != target {
				return storage.ErrConflict
			}
		}
		return s.repo.Transaction(work, func(tx Tx) error {
			current, e := tx.Binding(target)
			if e != nil {
				return e
			}
			if current.RequestID != op.ID {
				return storage.ErrConflict
			}
			if current.AccountDomain != "" && current.AccountDomain != account {
				return storage.ErrDenied
			}
			current.AccountDomain = account
			return tx.SaveBinding(current)
		})
	}
	var current *storage.Instance
	instances, e := s.store.Instances(work, s.cfg.Actor, 100, "")
	if e == nil {
		for _, i := range instances {
			if i.ID == target {
				copy := i
				current = &copy
				break
			}
		}
	}
	if e == nil && current != nil && (current.Ownership != "contributor" || current.OwnerDomain != OwnerDomain(b.Owner)) {
		e = storage.ErrDenied
	}
	if e == nil && op.Result == nil {
		var candidate storage.Instance
		if len(input) > 0 {
			candidate, e = s.provider.Prepare(work, target, op.Until, input, current, claim)
		} else {
			candidate, e = s.provider.Resume(work, target, op.Until, current, claim)
		}
		if e == nil {
			candidate.ID = target
			candidate.Ownership = "contributor"
			candidate.OwnerDomain = OwnerDomain(b.Owner)
			if current == nil {
				candidate.State = "paused"
				candidate.Authorized = true
				candidate.Limit = 0
				candidate.Admissions = []storage.Admission{}
				for _, scope := range s.cfg.PublicScopes {
					candidate.Admissions = append(candidate.Admissions, storage.Admission{Class: "public", Scope: scope, Plaintext: true, ExpiresAt: op.Until})
				}
			}
			op.Result = &candidate
			if current != nil {
				op.ExpectedRevision = current.Revision
			}
			e = s.repo.Transaction(work, func(tx Tx) error { return tx.SaveOperation(op) })
		}
	}
	var applied storage.Instance
	if e == nil {
		e = s.authorize(work, p, action, target)
	}
	if e == nil {
		if op.ExpectedRevision == 0 {
			// A lost registration response is reconciled by its stable instance ID.
			if current != nil {
				if current.CredentialRef != op.Result.CredentialRef || current.Root != op.Result.Root || current.AccountDomain != op.Result.AccountDomain {
					e = storage.ErrConflict
				} else {
					applied = *current
				}
			} else {
				applied, e = s.store.Register(work, s.cfg.Actor, "custody:"+op.ID, *op.Result)
			}
		} else {
			applied, e = s.store.ReauthorizeInstance(work, s.cfg.Actor, "custody:"+op.ID, storage.CredentialRenewal{ID: target, ExpectedRevision: op.ExpectedRevision, CredentialRef: op.Result.CredentialRef, CredentialRevision: op.Result.CredentialRevision, Until: op.Until})
		}
	}
	if e == nil {
		e = s.provider.Commit(work, applied)
	}
	// Persist a safe outcome even when the caller has disconnected. No provider
	// request is made with this cleanup context, and shutdown can recover the lease.
	finish, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	resultErr := e
	e = s.repo.Transaction(finish, func(tx Tx) error {
		latest, err := tx.Operation(op.ID)
		if err != nil {
			return err
		}
		if latest.Attempts != op.Attempts {
			return storage.ErrConflict
		}
		b, err = tx.Binding(target)
		if err != nil {
			return err
		}
		if b.RequestID != op.ID {
			return storage.ErrConflict
		}
		op.LeaseUntil = time.Time{}
		b.LastError = safeCode(resultErr)
		b.State = "blocked"
		if resultErr == nil {
			op.Complete = true
			b.State = "ready"
			b.Instance = applied
		} else if op.Result == nil && (errors.Is(resultErr, storage.ErrDenied) || errors.Is(resultErr, storage.ErrNotFound)) {
			b.State = "credentials_required"
		}
		if err = tx.SaveOperation(op); err != nil {
			return err
		}
		if err = tx.SaveBinding(b); err != nil {
			return err
		}
		out = b.View
		return s.event(tx, p, b, b.State)
	})
	return out, e
}
func (s *Service) event(tx Tx, p storage.Principal, b Binding, kind string) error {
	var nonce [16]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return storage.ErrUnavailable
	}
	return tx.Event(storage.Event{ID: hex.EncodeToString(nonce[:]), Type: "storage.custody." + kind, ObjectID: b.ID, Revision: b.Revision, Time: s.cfg.Clock(), Actor: p})
}
func safeCode(e error) string {
	switch {
	case e == nil:
		return ""
	case errors.Is(e, storage.ErrDenied):
		return "authorization_rejected"
	case errors.Is(e, storage.ErrNotFound):
		return "credentials_required"
	case errors.Is(e, storage.ErrConflict):
		return "conflict"
	case errors.Is(e, storage.ErrUnknown):
		return "result_unknown"
	case errors.Is(e, storage.ErrCapacity):
		return "attempts_exhausted"
	default:
		return "dependency_unavailable"
	}
}
