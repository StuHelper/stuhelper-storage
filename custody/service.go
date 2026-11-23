package custody

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	storage "github.com/StuHelper/stuhelper-storage"
	protocol "github.com/StuHelper/stuhelper-storage-bhpan"
)

func (s *Service) bindingView(ctx context.Context, b Binding) View {
	view := b.View
	view.AccountHint = ""
	view.CanWithdraw = b.Instance.ID == "" && b.AccountDomain == "" && b.State == "credentials_required"
	source, ok := s.provider.(storage.AccountHintSource)
	i := b.Instance
	if ok && i.ID == b.ID && i.Ownership == "contributor" && i.OwnerDomain == OwnerDomain(b.Owner) && i.Authorized {
		view.AccountHint = source.AccountHint(ctx, i)
		if recovery, ok := s.provider.(storage.CustodyRecoverySource); ok && view.State == "ready" && recovery.CredentialsRequired(ctx, i) {
			view.State = "credentials_required"
			view.LastError = "credentials_required"
		}
	}
	return view
}

func (s *Service) List(ctx context.Context, p storage.Principal, n int, after string, admin bool) (Page, error) {
	out := Page{Items: []View{}}
	if n < 1 || n > 100 || (after != "" && !id.MatchString(after)) {
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
	var bindings []Binding
	e := s.repo.Transaction(ctx, func(tx Tx) error {
		rows, e := tx.List(owner, n+1, after)
		if e != nil {
			return e
		}
		if len(rows) > n {
			rows = rows[:n]
			out.NextCursor = rows[n-1].ID
		}
		bindings = rows
		return s.authorize(ctx, p, action, "")
	})
	if e != nil {
		return Page{}, e
	}
	for _, b := range bindings {
		out.Items = append(out.Items, s.bindingView(ctx, b))
	}
	return out, nil
}
func (s *Service) GetRequest(ctx context.Context, p storage.Principal, key string) (View, error) {
	var out View
	if !uuid.MatchString(key) {
		return out, storage.ErrInput
	}
	if e := s.authorize(ctx, p, "storage.custody.read", ""); e != nil {
		return out, e
	}
	var b Binding
	e := s.repo.Transaction(ctx, func(tx Tx) error {
		o, e := tx.Operation(key)
		if e != nil {
			return e
		}
		if o.Owner != p {
			return storage.ErrDenied
		}
		b, e = tx.Binding(o.BindingID)
		if e != nil {
			return e
		}
		if b.Owner != p {
			return storage.ErrDenied
		}
		return s.authorize(ctx, p, "storage.custody.read", b.ID)
	})
	if e != nil {
		return out, e
	}
	return s.bindingView(ctx, b), nil
}
func (s *Service) Submit(ctx context.Context, p storage.Principal, target, key string, q Request) (View, error) {
	var out View
	if !uuid.MatchString(key) || (target != "" && !id.MatchString(target)) || q.Adapter != "bhpan" || !q.Until.After(s.cfg.Clock().Add(time.Minute)) || q.Until.After(s.cfg.Clock().Add(time.Duration(s.cfg.Policy.MaxTermSeconds)*time.Second)) || !q.Consent.Accepted || q.Consent.Version != s.cfg.Policy.Version || q.Consent.Digest != s.cfg.Policy.Digest || target == "" && q.Revision != 0 || target != "" && q.Revision < 1 {
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
	if json.Unmarshal(q.Credential, &fields) != nil || len(fields) != 2 || len(fields["username"]) < 1 || len(fields["username"]) > 128 || len(fields["password"]) < 1 || len(fields["password"]) > 1024 {
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
		var b Binding
		if target == "" {
			// Binding IDs outlive their completed request receipts.
			if _, err := tx.Binding(key); err == nil {
				return storage.ErrConflict
			} else if !errors.Is(err, storage.ErrNotFound) {
				return err
			}
			target = key
			b = Binding{View: View{ID: target, Adapter: q.Adapter}, Owner: p}
		} else {
			b, e = tx.Binding(target)
			if errors.Is(e, storage.ErrNotFound) {
				b, e = tx.OwnedBinding(p, target)
			}
			if e != nil {
				return e
			}
			if b.Owner != p {
				return storage.ErrDenied
			}
			if b.Revision != q.Revision {
				return storage.ErrConflict
			}
			if b.State == "blocked" || b.State == "pending" {
				now := s.cfg.Clock()
				prevOp, opErr := tx.Operation(b.RequestID)
				if opErr != nil {
					return opErr
				}
				if prevOp.LeaseUntil.After(now) {
					return storage.ErrConflict
				}
				canResume := !prevOp.Complete && prevOp.Attempts < 5 && prevOp.Until.After(now)
				if canResume && (b.State == "pending" || prevOp.Result != nil || unknownPreparation(b)) {
					return storage.ErrConflict
				}
				if b.Instance.ID == "" && prevOp.Result == nil {
					b.AccountDomain = ""
				}
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
		if e := checkCapacity(tx, b.Owner); e != nil {
			return e
		}
		out = b.View
		return s.event(ctx, tx, p, b, "requested", "success")
	})
	if e != nil {
		return out, e
	}
	if out.RequestID != key {
		return out, storage.ErrConflict
	}
	return s.run(ctx, p, out.ID, ResumeRequest{key, out.Revision}, q.Credential, false)
}

// The provider may have created a root after claiming the account and before
// returning a candidate. Recover that operation before accepting new credentials.
func unknownPreparation(b Binding) bool {
	return b.Instance.ID == "" && b.AccountDomain != "" && (b.LastError == "result_unknown" || b.State == "pending")
}

// Check after recording the pending state inside the registry transaction.
// Replacing or resuming a failed request must reserve its released slot again.
func checkCapacity(tx Tx, owner storage.Principal) error {
	for _, scope := range []struct {
		principal storage.Principal
		limit     int
	}{{owner, 5}, {storage.Principal{}, 100}} {
		count, err := tx.Count(scope.principal)
		if err != nil {
			return err
		}
		if count > scope.limit {
			return storage.ErrCapacity
		}
	}
	count, err := tx.OperationCount()
	if err != nil {
		return err
	}
	if count > 1000 {
		return storage.ErrCapacity
	}
	return nil
}

func (s *Service) Resume(ctx context.Context, p storage.Principal, target string, q ResumeRequest, admin bool) (View, error) {
	return s.run(ctx, p, target, q, nil, admin)
}

func (s *Service) run(ctx context.Context, p storage.Principal, target string, q ResumeRequest, input json.RawMessage, admin bool) (View, error) {
	var out View
	var b Binding
	var op Operation
	var recoverClaim bool
	if !id.MatchString(target) || !uuid.MatchString(q.RequestID) || q.Revision < 1 {
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
		now := s.cfg.Clock()
		windowStart := now.Add(-5 * time.Minute)
		recent, e := tx.RecentAttempts(op.Owner, windowStart)
		if e != nil {
			return e
		}
		if recent >= 5 {
			retryAfter := 300
			if oldest, err := tx.OldestRecentAttempt(op.Owner, windowStart); err == nil && oldest.After(time.Unix(0, 0)) {
				remaining := oldest.Add(5 * time.Minute).Sub(now)
				retryAfter = max(1, min(300, int((remaining+time.Second-1)/time.Second)))
			}
			return storage.RetryAfterError{Err: storage.ErrCapacity, RetryAfterSeconds: retryAfter}
		}
		recoverClaim = op.Result == nil && unknownPreparation(b)
		if b.State != "pending" {
			b.State = "pending"
			if e := tx.SaveBinding(b); e != nil {
				return e
			}
			if e := checkCapacity(tx, b.Owner); e != nil {
				return e
			}
		}
		// Old records only have the last attempt time. Preserve their previous
		// conservative window until those attempts have aged out.
		if len(op.AttemptTimes) == 0 && op.Attempts > 0 {
			for range op.Attempts {
				op.AttemptTimes = append(op.AttemptTimes, op.AttemptedAt.UTC())
			}
		}
		op.AttemptedAt = now
		op.AttemptTimes = append(op.AttemptTimes, now.UTC())
		op.Attempts++
		op.LeaseUntil = now.Add(2 * time.Minute)
		return tx.SaveOperation(op)
	})
	if e != nil {
		return out, e
	}
	if op.Complete {
		return s.bindingView(ctx, b), nil
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
			latest, e := tx.Operation(op.ID)
			if e != nil {
				return e
			}
			if latest.Attempts != op.Attempts || !latest.LeaseUntil.After(s.cfg.Clock()) {
				return storage.ErrStale
			}
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
		if len(input) > 0 && !recoverClaim {
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
			e = s.repo.Transaction(work, func(tx Tx) error {
				latest, e := tx.Operation(op.ID)
				if e != nil {
					return e
				}
				if latest.Attempts != op.Attempts || !latest.LeaseUntil.After(s.cfg.Clock()) {
					return storage.ErrStale
				}
				return tx.SaveOperation(op)
			})
		}
	}
	var applied storage.Instance
	if e == nil {
		e = s.authorize(work, p, action, target)
	}
	if e == nil {
		e = s.repo.Transaction(work, func(tx Tx) error {
			latest, e := tx.Operation(op.ID)
			if e != nil {
				return e
			}
			if latest.Attempts != op.Attempts || !latest.LeaseUntil.After(s.cfg.Clock()) {
				return storage.ErrStale
			}
			return nil
		})
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
			applied, e = s.store.ReauthorizeInstance(work, s.cfg.Actor, "custody:"+op.ID, storage.CredentialRenewal{ID: target, OwnerDomain: OwnerDomain(b.Owner), AccountDomain: op.Result.AccountDomain, Root: op.Result.Root, ExpectedRevision: op.ExpectedRevision, CredentialRef: op.Result.CredentialRef, CredentialRevision: op.Result.CredentialRevision, Until: op.Until})
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
	if resultErr != nil {
		storage.EmitDiagnostic(s.cfg.Observer, storage.Diagnostic{
			Component: "custody",
			Operation: "execute",
			ObjectID:  target,
			JobID:     op.ID,
			Category:  safeCode(resultErr),
		})
	}
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
			op.CompletedAt = s.cfg.Clock()
			b.State = "ready"
			b.Instance = applied
		} else if recoverClaim && op.Result == nil && op.Attempts < 5 && op.Until.After(s.cfg.Clock()) {
			b.LastError = "result_unknown"
		} else if op.Result == nil && (errors.Is(resultErr, storage.ErrDenied) || errors.Is(resultErr, storage.ErrNotFound) || isChallenge(resultErr)) {
			b.State = "credentials_required"
			if b.Instance.ID == "" {
				b.AccountDomain = ""
			}
		} else if b.Instance.ID == "" && op.Result == nil && (!errors.Is(resultErr, storage.ErrUnknown) || op.Attempts >= 5 || !op.Until.After(s.cfg.Clock())) {
			b.AccountDomain = ""
		}
		if err = tx.SaveOperation(op); err != nil {
			return err
		}
		if err = tx.SaveBinding(b); err != nil {
			return err
		}
		out = b.View
		auditResult := "failed"
		switch {
		case resultErr == nil:
			auditResult = "success"
		case errors.Is(resultErr, storage.ErrUnknown):
			auditResult = "unknown"
		case errors.Is(resultErr, storage.ErrDenied):
			auditResult = "denied"
		}
		return s.event(ctx, tx, p, b, b.State, auditResult)
	})
	if e != nil {
		return out, e
	}
	return s.bindingView(ctx, b), nil
}
func (s *Service) event(ctx context.Context, tx Tx, p storage.Principal, b Binding, kind, result string) error {
	var nonce [16]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return storage.ErrUnavailable
	}
	return tx.Event(storage.Event{ID: hex.EncodeToString(nonce[:]), Type: "storage.custody." + kind, ObjectID: b.ID, Revision: b.Revision, Time: s.cfg.Clock(), Actor: p, TraceParent: storage.TraceParentFromContext(ctx), AuditResult: result, AuditSchool: "*"})
}
func (s *Service) Delete(ctx context.Context, p storage.Principal, target, key string) (View, error) {
	var out View
	if !id.MatchString(target) || !uuid.MatchString(key) {
		return out, storage.ErrInput
	}
	if e := s.authorize(ctx, p, "storage.custody.manage", target); e != nil {
		return out, e
	}
	idempRaw, _ := json.Marshal([]string{"custody.delete", p.Issuer, p.Subject, key})
	idempSum := sha256.Sum256(idempRaw)
	idempKey := hex.EncodeToString(idempSum[:])
	replayed := false
	var initial View
	e := s.repo.Transaction(ctx, func(tx Tx) error {
		now := s.cfg.Clock()
		if prev, err := tx.Idempotency(idempKey); err == nil && prev.ExpiresAt.After(now) {
			if prev.Digest != target {
				return storage.ErrConflict
			}
			if err := s.authorize(ctx, p, "storage.custody.manage", target); err != nil {
				return err
			}
			if json.Unmarshal(prev.Result, &out) != nil {
				return storage.ErrUnavailable
			}
			replayed = true
			return nil
		} else if err != nil && !errors.Is(err, storage.ErrNotFound) {
			return err
		}
		b, err := tx.Binding(target)
		if err != nil {
			return err
		}
		if b.Owner != p {
			return storage.ErrDenied
		}
		initial = b.View
		if b.Instance.ID == "" {
			if b.AccountDomain != "" {
				return storage.ErrConflict
			}
			pending, err := tx.HasPendingWrites(b.ID, now)
			if err != nil {
				return err
			}
			if pending {
				return storage.ErrConflict
			}
		}
		if op, opErr := tx.Operation(b.RequestID); opErr == nil {
			if !op.Complete && (op.LeaseUntil.After(now) || op.Result != nil || unknownPreparation(b) && op.Attempts < 5 && op.Until.After(now)) {
				return storage.ErrConflict
			}
		} else if !errors.Is(opErr, storage.ErrNotFound) {
			return opErr
		}
		return nil
	})
	if e != nil || replayed {
		return out, e
	}

	instances, e := s.store.Instances(ctx, s.cfg.Actor, 100, "")
	if e != nil {
		return out, e
	}
	var live *storage.Instance
	for _, i := range instances {
		if i.ID == target {
			copy := i
			live = &copy
			break
		}
	}
	if live == nil {
		if src, ok := s.provider.(interface {
			HasProvisioningMaterial(context.Context, string) (bool, error)
		}); ok {
			present, err := src.HasProvisioningMaterial(ctx, target)
			if err != nil {
				return out, err
			}
			if present {
				return out, storage.ErrConflict
			}
		}
	}
	if live != nil {
		if live.Ownership != "contributor" || live.OwnerDomain != OwnerDomain(p) {
			return out, storage.ErrDenied
		}
		if live.Authorized || live.State != "revoked" || live.Used != 0 || live.Reserved != 0 {
			return out, storage.ErrConflict
		}
		purger, ok := s.store.(InstancePurger)
		if !ok {
			return out, storage.ErrUnavailable
		}
		if e = purger.PurgeRevokedCustodyInstance(ctx, s.cfg.Actor, target, OwnerDomain(p), "custody-delete:"+key); e != nil {
			return out, e
		}
	}

	e = s.repo.Transaction(ctx, func(tx Tx) error {
		now := s.cfg.Clock()
		if prev, err := tx.Idempotency(idempKey); err == nil && prev.ExpiresAt.After(now) {
			if prev.Digest != target {
				return storage.ErrConflict
			}
			if err := s.authorize(ctx, p, "storage.custody.manage", target); err != nil {
				return err
			}
			if json.Unmarshal(prev.Result, &out) != nil {
				return storage.ErrUnavailable
			}
			return nil
		}
		b, err := tx.Binding(target)
		if err != nil {
			return err
		}
		if b.Owner != p {
			return storage.ErrDenied
		}
		// Resume can finish during the store lookup without increasing Revision.
		if b.View != initial {
			return storage.ErrConflict
		}
		if err = s.authorize(ctx, p, "storage.custody.manage", target); err != nil {
			return err
		}
		if b.Instance.ID == "" {
			if b.AccountDomain != "" {
				return storage.ErrConflict
			}
			pending, err := tx.HasPendingWrites(b.ID, now)
			if err != nil {
				return err
			}
			if pending {
				return storage.ErrConflict
			}
		}
		if op, opErr := tx.Operation(b.RequestID); opErr == nil {
			if !op.Complete && (op.LeaseUntil.After(now) || op.Result != nil || unknownPreparation(b) && op.Attempts < 5 && op.Until.After(now)) {
				return storage.ErrConflict
			}
		} else if !errors.Is(opErr, storage.ErrNotFound) {
			return opErr
		}
		if err = tx.DeleteBinding(target, p, now.Add(-5*time.Minute)); err != nil {
			return err
		}
		b.Revision++
		out = b.View
		encoded, err := json.Marshal(out)
		if err != nil {
			return storage.ErrUnavailable
		}
		if err = tx.SaveIdempotency(storage.Idempotency{Key: idempKey, Digest: target, ObjectID: target, Result: encoded, ExpiresAt: now.Add(24 * time.Hour)}); err != nil {
			return err
		}
		return s.event(ctx, tx, p, b, "deleted", "success")
	})
	return out, e
}

func isChallenge(e error) bool {
	return errors.Is(e, storage.ErrChallenge) || errors.Is(e, protocol.ErrChallenge)
}

func safeCode(e error) string {
	switch {
	case e == nil:
		return ""
	case isChallenge(e):
		return "interactive_verification_required"
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
