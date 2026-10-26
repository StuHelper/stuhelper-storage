package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

type Config struct {
	Clock                 func() time.Time
	MaxObjectSize         int64
	TemporaryDirectory    string
	ParallelTransfers     int
	Lease                 time.Duration
	VerificationAge       time.Duration
	MaxAttempts           int
	TemporaryBytes        int64
	MaxOutstandingJobs    int
	AccountTransfers      int
	BytesPerSecond        int64
	AccountBytesPerSecond int64
}
type Service struct {
	repo      Repository
	auth      Authorizer
	resolver  Resolver
	verifier  Verifier
	cfg       Config
	now       func() time.Time
	slots     chan struct{}
	staging   *staging
	lifecycle sync.Mutex
	stopping  bool
	active    int
	stopCtx   context.Context
	cancel    context.CancelFunc
	closed    chan struct{}
	closeErr  error
	bandwidth *pacer
}

func New(repo Repository, auth Authorizer, resolver Resolver, verifier Verifier, cfg Config) (*Service, error) {
	if repo == nil || auth == nil || resolver == nil || verifier == nil || cfg.MaxObjectSize < 1 || cfg.MaxObjectSize > 1<<30 || cfg.TemporaryDirectory == "" || cfg.ParallelTransfers < 1 || cfg.ParallelTransfers > 16 || cfg.Lease < time.Minute || cfg.Lease > 30*time.Minute || cfg.VerificationAge < time.Minute || cfg.MaxAttempts < 1 || cfg.MaxAttempts > 100 {
		return nil, ErrInput
	}
	if cfg.TemporaryBytes == 0 {
		cfg.TemporaryBytes = 2 * (cfg.MaxObjectSize + 1) * int64(cfg.ParallelTransfers)
	}
	if cfg.MaxOutstandingJobs == 0 {
		cfg.MaxOutstandingJobs = 10000
	}
	if cfg.AccountTransfers == 0 {
		cfg.AccountTransfers = 1
	}
	if cfg.BytesPerSecond == 0 {
		cfg.BytesPerSecond = 64 << 20
	}
	if cfg.AccountBytesPerSecond == 0 {
		cfg.AccountBytesPerSecond = 16 << 20
	}
	if cfg.TemporaryBytes < 2*(cfg.MaxObjectSize+1) || cfg.MaxOutstandingJobs < 1 || cfg.MaxOutstandingJobs > 100000 || cfg.AccountTransfers < 1 || cfg.AccountTransfers > cfg.ParallelTransfers || cfg.BytesPerSecond < 1 || cfg.AccountBytesPerSecond < 1 {
		return nil, ErrInput
	}
	staging, err := openStaging(cfg.TemporaryDirectory, cfg.TemporaryBytes)
	if err != nil {
		return nil, err
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	stopCtx, cancel := context.WithCancel(context.Background())
	bandwidth := newPacer(cfg.BytesPerSecond)
	resolver = &limitedResolver{inner: resolver, parallel: cfg.AccountTransfers, global: bandwidth, accountRate: cfg.AccountBytesPerSecond, accounts: map[string]*accountLimit{}}
	return &Service{repo: repo, auth: auth, resolver: resolver, verifier: verifier, cfg: cfg, now: clock, slots: make(chan struct{}, cfg.ParallelTransfers), staging: staging, stopCtx: stopCtx, cancel: cancel, closed: make(chan struct{}), bandwidth: bandwidth}, nil
}
func (s *Service) authorize(ctx context.Context, p Principal, action, id string, protection Protection) error {
	if s.stopCtx.Err() != nil {
		return ErrUnavailable
	}
	if !p.Valid() {
		return ErrDenied
	}
	return s.auth.Authorize(ctx, p, action, id, protection)
}
func requestHash(value any) string {
	b, _ := json.Marshal(value)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func validKey(key string) bool {
	if len(key) < 1 || len(key) > 128 {
		return false
	}
	for _, c := range []byte(key) {
		if c < 32 || c > 126 {
			return false
		}
	}
	return true
}

// mutation persists the exact replay response with its audit/outbox effects.
// Current authorization is checked even when returning an earlier response.
func (s *Service) mutation(ctx context.Context, p Principal, action, id, key string, request any, guard func(Transaction) error, apply func(Transaction) (any, error), out any) error {
	if !validKey(key) || !p.Valid() {
		return ErrInput
	}
	operation := requestHash([]string{p.Issuer, p.Subject, action, id, key})
	hash := requestHash(request)
	return s.repo.Transaction(ctx, func(tx Transaction) error {
		if err := tx.Lock("operation:" + operation); err != nil {
			return err
		}
		if err := guard(tx); err != nil {
			return err
		}
		previous, err := tx.Idempotency(operation)
		if err == nil && previous.ExpiresAt.After(s.now()) {
			if previous.Digest != hash {
				return ErrConflict
			}
			if json.Unmarshal(previous.Result, out) != nil {
				return ErrUnavailable
			}
			return nil
		}
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		result, err := apply(tx)
		if err != nil {
			return err
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			return ErrUnavailable
		}
		if err = tx.SaveIdempotency(Idempotency{Key: operation, Digest: hash, Result: encoded, ExpiresAt: s.now().Add(24 * time.Hour)}); err != nil {
			return err
		}
		return json.Unmarshal(encoded, out)
	})
}
func (s *Service) emit(tx Transaction, p Principal, kind, id string, revision int64) error {
	return tx.Event(Event{ID: newID(), Type: kind, ObjectID: id, Revision: revision, Time: s.now(), Actor: p})
}

func validateInstance(v Instance, now time.Time) bool {
	if v.PersonalReserve < 0 || v.PersonalReserve > 1<<60 || v.SafetyMargin < 0 || v.SafetyMargin > 1<<60 {
		return false
	}
	if !validID(v.ID) || !validID(v.Adapter) || !validID(v.OwnerDomain) || !validID(v.CredentialRef) || len(v.Root) < 1 || len(v.Root) > 1024 || v.Limit < 0 || v.Limit > 1<<60 || v.CredentialRevision < 1 || (v.State != "revoked" && !v.ExpiresAt.After(now)) || len(v.Admissions) > 64 {
		return false
	}
	if v.Ownership != "platform" && v.Ownership != "contributor" {
		return false
	}
	if v.State != "active" && v.State != "paused" && v.State != "draining" && v.State != "revoked" {
		return false
	}
	seen := map[string]bool{}
	for _, a := range v.Admissions {
		k := a.Class + "/" + a.Scope
		if !validID(a.Class) || !validID(a.Scope) || seen[k] || (v.State != "revoked" && !a.ExpiresAt.After(now)) || a.ExpiresAt.After(v.ExpiresAt) {
			return false
		}
		seen[k] = true
		if v.Ownership == "contributor" && (a.Class != "public" || !a.Plaintext) {
			return false
		}
	}
	return true
}

// Register verifies account identity before accepting administrative placement
// claims. An alias or a second directory under the same account cannot add capacity.
func (s *Service) Register(ctx context.Context, p Principal, key string, v Instance) (Instance, error) {
	var result Instance
	if !validateInstance(v, s.now()) || v.Revision != 0 {
		return result, ErrInput
	}
	if err := s.authorize(ctx, p, "storage.instances.manage", v.ID, Protection{}); err != nil {
		return result, err
	}
	evidence, err := s.verifier.Verify(ctx, v)
	if err != nil {
		return result, err
	}
	if evidence.AccountDomain == "" || len(evidence.AccountDomain) > 256 || evidence.ProviderFree < 0 || evidence.VerifiedAt.Before(s.now().Add(-time.Minute)) || evidence.VerifiedAt.After(s.now().Add(time.Minute)) {
		return result, ErrUnavailable
	}
	request := v
	err = s.mutation(ctx, p, "storage.instances.register", v.ID, key, request, func(tx Transaction) error { return s.authorize(ctx, p, "storage.instances.manage", v.ID, Protection{}) }, func(tx Transaction) (any, error) {
		if err := tx.Lock("instance-registry"); err != nil {
			return nil, err
		}
		instances, err := tx.Instances(100, "")
		if err != nil {
			return nil, err
		}
		if len(instances) >= 100 {
			return nil, ErrCapacity
		}
		if err := tx.Lock("instance:" + v.ID); err != nil {
			return nil, err
		}
		_, err = tx.Instance(v.ID)
		if err == nil {
			return nil, ErrConflict
		}
		if !errors.Is(err, ErrNotFound) {
			return nil, err
		}
		v.AccountDomain = evidence.AccountDomain
		v.ProviderFree = evidence.ProviderFree
		v.Used = 0
		v.Reserved = 0
		v.Revision = 1
		v.QuotaRevision = 1
		v.QuotaExpiresAt = s.now().Add(5 * time.Minute)
		if err := tx.SaveInstance(v); err != nil {
			return nil, err
		}
		return v, s.emit(tx, p, "storage.instance.registered", v.ID, v.Revision)
	}, &result)
	return result, err
}

func (s *Service) UpdateInstance(ctx context.Context, p Principal, key string, v Instance) (Instance, error) {
	var result Instance
	if !validateInstance(v, s.now()) || v.Revision < 1 {
		return result, ErrInput
	}
	if err := s.authorize(ctx, p, "storage.instances.manage", v.ID, Protection{}); err != nil {
		return result, err
	}
	// Every renewal or credential change is revalidated with the provider. A
	// caller cannot extend authorization by changing only a timestamp.
	if v.Authorized && v.State != "revoked" {
		evidence, err := s.verifier.Verify(ctx, v)
		if err != nil {
			return result, err
		}
		if evidence.AccountDomain != v.AccountDomain || evidence.VerifiedAt.Before(s.now().Add(-time.Minute)) || evidence.VerifiedAt.After(s.now().Add(time.Minute)) {
			return result, ErrDenied
		}
	}
	err := s.mutation(ctx, p, "storage.instances.update", v.ID, key, v, func(tx Transaction) error { return s.authorize(ctx, p, "storage.instances.manage", v.ID, Protection{}) }, func(tx Transaction) (any, error) {
		old, err := tx.Instance(v.ID)
		if err != nil {
			return nil, err
		}
		if old.Revision != v.Revision {
			return nil, ErrConflict
		}
		if old.Adapter != v.Adapter || old.AccountDomain != v.AccountDomain || old.Root != v.Root || old.Ownership != v.Ownership || old.OwnerDomain != v.OwnerDomain || v.CredentialRevision < old.CredentialRevision || (old.CredentialRef != v.CredentialRef && v.CredentialRevision == old.CredentialRevision) {
			return nil, ErrInput
		}
		v.ProviderFree = old.ProviderFree
		v.QuotaRevision = old.QuotaRevision
		v.Used = old.Used
		v.Reserved = old.Reserved
		v.QuotaExpiresAt = old.QuotaExpiresAt
		v.Revision++
		if v.Limit < v.Used+v.Reserved && v.State == "active" {
			v.State = "paused"
		}
		if err := tx.SaveInstance(v); err != nil {
			return nil, err
		}
		return v, s.emit(tx, p, "storage.instance.updated", v.ID, v.Revision)
	}, &result)
	return result, err
}

func (s *Service) Instances(ctx context.Context, p Principal, limit int, after string) ([]Instance, error) {
	if limit < 1 || limit > 100 {
		return nil, ErrInput
	}
	if err := s.authorize(ctx, p, "storage.instances.read", "", Protection{}); err != nil {
		return nil, err
	}
	var out []Instance
	err := s.repo.Transaction(ctx, func(tx Transaction) error { var err error; out, err = tx.Instances(limit, after); return err })
	return out, err
}

type CreateRequest struct {
	Size       int64      `json:"size"`
	SHA256     string     `json:"sha256"`
	Protection Protection `json:"protection"`
	Policy     Policy     `json:"policy"`
}
type Status struct {
	ID         string     `json:"id"`
	Size       int64      `json:"size"`
	SHA256     string     `json:"sha256"`
	Protection Protection `json:"protection"`
	Policy     Policy     `json:"policy"`
	Revision   int64      `json:"revision"`
	State      string     `json:"state"`
	Published  bool       `json:"published"`
	Healthy    int        `json:"healthy"`
	Desired    int        `json:"desired"`
}

func (s *Service) Create(ctx context.Context, p Principal, key string, r CreateRequest) (Status, error) {
	var out Status
	if r.Policy == (Policy{}) {
		r.Policy = DefaultPolicy()
	}
	if r.Size < 1 || r.Size > s.cfg.MaxObjectSize || !digest.MatchString(r.SHA256) || !r.Protection.Valid() || !r.Policy.Valid() {
		return out, ErrInput
	}
	err := s.mutation(ctx, p, "storage.objects.create", "", key, r, func(tx Transaction) error { return s.authorize(ctx, p, "storage.objects.create", "", r.Protection) }, func(tx Transaction) (any, error) {
		o := Object{ID: newID(), Owner: p, Size: r.Size, SHA256: r.SHA256, Protection: r.Protection, Policy: r.Policy, Revision: 1, State: "pending", CreatedAt: s.now(), References: []Reference{}}
		if err := tx.SaveObject(o); err != nil {
			return nil, err
		}
		if err := s.emit(tx, p, "storage.object.created", o.ID, o.Revision); err != nil {
			return nil, err
		}
		return s.status(tx, o)
	}, &out)
	return out, err
}
func (s *Service) objectGuard(ctx context.Context, tx Transaction, p Principal, action, id string) (Object, error) {
	if !validID(id) {
		return Object{}, ErrInput
	}
	if err := tx.Lock("object:" + id); err != nil {
		return Object{}, err
	}
	o, err := tx.Object(id)
	if err != nil {
		return o, err
	}
	return o, s.authorize(ctx, p, action, id, o.Protection)
}
func (s *Service) status(tx Transaction, o Object) (Status, error) {
	replicas, err := tx.Replicas(o.ID)
	if err != nil {
		return Status{}, err
	}
	count := 0
	accounts := map[string]bool{}
	owners := map[string]bool{}
	for _, r := range replicas {
		if r.State != "healthy" || r.ObjectRevision != o.Revision || r.VerifiedAt.Before(s.now().Add(-s.cfg.VerificationAge)) {
			continue
		}
		i, err := tx.Instance(r.InstanceID)
		if err != nil {
			return Status{}, err
		}
		if !i.Allows(o.Protection, s.now()) || r.CredentialRevision != i.CredentialRevision || accounts[i.AccountDomain] || (i.Ownership == "contributor" && owners[i.OwnerDomain]) {
			continue
		}
		accounts[i.AccountDomain] = true
		if i.Ownership == "contributor" {
			owners[i.OwnerDomain] = true
		}
		count++
	}
	state := o.State
	if state != "deleting" && state != "deleted" {
		state = "pending"
		if count >= o.Policy.Target {
			state = "ready"
		} else if o.Published || count >= o.Policy.Publish {
			state = "degraded"
		}
		if o.Published && count == 0 {
			state = "unavailable"
		}
	}
	return Status{o.ID, o.Size, o.SHA256, o.Protection, o.Policy, o.Revision, state, o.Published, count, o.Policy.Target}, nil
}
func (s *Service) Status(ctx context.Context, p Principal, id string) (Status, error) {
	var out Status
	err := s.repo.Transaction(ctx, func(tx Transaction) error {
		o, err := s.objectGuard(ctx, tx, p, "storage.objects.read", id)
		if err != nil {
			return err
		}
		out, err = s.status(tx, o)
		return err
	})
	return out, err
}
func (s *Service) Reference(ctx context.Context, p Principal, id, key string, ref Reference, attach bool) (Status, error) {
	var out Status
	var o Object
	if !validID(ref.Module) || !validID(ref.ID) {
		return out, ErrInput
	}
	action := "storage.references.release"
	if attach {
		action = "storage.references.attach"
	}
	err := s.mutation(ctx, p, action, id, key, ref, func(tx Transaction) error {
		var err error
		o, err = s.objectGuard(ctx, tx, p, action, id)
		if err != nil {
			return err
		}
		return s.authorize(ctx, p, action, ref.Module+":"+ref.ID, o.Protection)
	}, func(tx Transaction) (any, error) {
		if o.State == "deleted" || o.State == "deleting" {
			return nil, ErrConflict
		}
		// The module owning the reference must be authorized independently of the object.
		if err := s.authorize(ctx, p, action, ref.Module+":"+ref.ID, o.Protection); err != nil {
			return nil, err
		}
		index := -1
		for n, r := range o.References {
			if r == ref {
				index = n
				break
			}
		}
		status, err := s.status(tx, o)
		if err != nil {
			return nil, err
		}
		if attach {
			if status.Healthy < o.Policy.Publish {
				return nil, ErrUnavailable
			}
			if len(o.References) >= 1000 && index < 0 {
				return nil, ErrCapacity
			}
			if index < 0 {
				o.References = append(o.References, ref)
			}
			o.Published = true
		} else if index >= 0 {
			o.References = append(o.References[:index], o.References[index+1:]...)
		}
		if err := tx.SaveObject(o); err != nil {
			return nil, err
		}
		if err := s.emit(tx, p, action, o.ID, o.Revision); err != nil {
			return nil, err
		}
		return s.status(tx, o)
	}, &out)
	return out, err
}

func (s *Service) Delete(ctx context.Context, p Principal, id, key string, revision int64) (Status, error) {
	var out Status
	var o Object
	err := s.mutation(ctx, p, "storage.objects.delete", id, key, revision, func(tx Transaction) error {
		var err error
		o, err = s.objectGuard(ctx, tx, p, "storage.objects.delete", id)
		return err
	}, func(tx Transaction) (any, error) {
		if o.Revision != revision || len(o.References) > 0 {
			return nil, ErrConflict
		}
		if o.State == "deleted" || o.State == "deleting" {
			return s.status(tx, o)
		}
		o.State = "deleting"
		o.Revision++
		if err := tx.SaveObject(o); err != nil {
			return nil, err
		}
		replicas, err := tx.Replicas(id)
		if err != nil {
			return nil, err
		}
		for _, r := range replicas {
			if r.State == "deleted" {
				continue
			}
			r.State = "cleanup"
			if err := tx.SaveReplica(r); err != nil {
				return nil, err
			}
			if err := s.enqueue(tx, o.ID, r.ID, "delete"); err != nil {
				return nil, err
			}
		}
		if len(replicas) == 0 {
			o.State = "deleted"
			if err := tx.SaveObject(o); err != nil {
				return nil, err
			}
		}
		if err := s.emit(tx, p, "storage.object.deleting", o.ID, o.Revision); err != nil {
			return nil, err
		}
		return s.status(tx, o)
	}, &out)
	return out, err
}
func (s *Service) ChangeProtection(ctx context.Context, p Principal, id, key string, revision int64, protection Protection) (Status, error) {
	var out Status
	var o Object
	if !protection.Valid() {
		return out, ErrInput
	}
	err := s.mutation(ctx, p, "storage.protection.change", id, key, struct {
		Revision   int64
		Protection Protection
	}{revision, protection}, func(tx Transaction) error {
		var err error
		o, err = s.objectGuard(ctx, tx, p, "storage.protection.change", id)
		if err != nil {
			return err
		}
		return s.authorize(ctx, p, "storage.protection.assign", id, protection)
	}, func(tx Transaction) (any, error) {
		if o.Revision != revision || o.State == "deleting" || o.State == "deleted" {
			return nil, ErrConflict
		}
		// Cross-business references require a separate object/version before changing requirements.
		if len(o.References) > 0 {
			return nil, ErrConflict
		}
		o.Protection = protection
		o.Revision++
		o.Published = false
		replicas, err := tx.Replicas(id)
		if err != nil {
			return nil, err
		}
		for _, r := range replicas {
			i, err := tx.Instance(r.InstanceID)
			if err != nil {
				return nil, err
			}
			if r.State == "healthy" && i.Allows(protection, s.now()) {
				r.ObjectRevision = o.Revision
			} else if r.State != "deleted" {
				r.State = "cleanup"
			}
			if err := tx.SaveReplica(r); err != nil {
				return nil, err
			}
			if r.State == "cleanup" {
				if err := s.enqueue(tx, o.ID, r.ID, "delete"); err != nil {
					return nil, err
				}
			}
		}
		if err := tx.SaveObject(o); err != nil {
			return nil, err
		}
		if err := s.emit(tx, p, "storage.protection.changed", o.ID, o.Revision); err != nil {
			return nil, err
		}
		return s.status(tx, o)
	}, &out)
	return out, err
}
func (s *Service) enqueue(tx Transaction, objectID, replicaID, kind string) error {
	id := requestHash([]string{objectID, replicaID, kind})
	replicas, err := tx.Replicas(objectID)
	if err != nil {
		return err
	}
	r, err := findReplica(replicas, replicaID)
	if err != nil {
		return err
	}
	existing, err := tx.Job(id)
	if err == nil && (existing.State == "pending" || existing.State == "running" || existing.State == "blocked") && existing.Intent == r.Intent && existing.ObjectRevision == r.ObjectRevision && existing.InstanceRevision == r.InstanceRevision && existing.CredentialRevision == r.CredentialRevision {
		return nil
	}
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	err = s.queue(tx, Job{ID: id, ObjectID: objectID, ReplicaID: replicaID, Intent: r.Intent, ObjectRevision: r.ObjectRevision, InstanceRevision: r.InstanceRevision, CredentialRevision: r.CredentialRevision, Kind: kind, State: "pending", Generation: existing.Generation + 1, AvailableAt: s.now()})
	// Cleanup and verification intent lives in object/replica state. A full
	// runnable queue must not undo a deletion or classification change.
	if errors.Is(err, ErrCapacity) {
		return nil
	}
	return err
}

func (s *Service) queue(tx Transaction, j Job) error {
	if err := tx.Lock("queue-budget"); err != nil {
		return err
	}
	count, err := tx.OutstandingJobs(j.ID, s.cfg.MaxOutstandingJobs)
	if err != nil {
		return err
	}
	if count >= s.cfg.MaxOutstandingJobs {
		return ErrCapacity
	}
	return tx.SaveJob(j)
}
func findReplica(replicas []Replica, id string) (Replica, error) {
	for _, r := range replicas {
		if r.ID == id {
			return r, nil
		}
	}
	return Replica{}, ErrNotFound
}
func sortedInstances(instances []Instance) {
	sort.Slice(instances, func(i, j int) bool { return instances[i].ID < instances[j].ID })
}
func errorCode(err error) string {
	for _, e := range []error{ErrInput, ErrDenied, ErrNotFound, ErrConflict, ErrCapacity, ErrIntegrity, ErrStale, ErrUnknown} {
		if errors.Is(err, e) {
			return e.Error()
		}
	}
	if errors.Is(err, context.Canceled) {
		return "storage_cancelled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "storage_timeout"
	}
	return ErrUnavailable.Error()
}
func (s Status) String() string {
	return fmt.Sprintf("storage object %s: %s (%d/%d)", s.ID, s.State, s.Healthy, s.Desired)
}
