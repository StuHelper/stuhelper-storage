// Package storage owns provider-independent placement, replicas and recovery.
// Callers supply current authorization; credentials are resolved outside this package.
package storage

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"time"
)

var (
	ErrInput       = errors.New("storage_invalid_input")
	ErrDenied      = errors.New("storage_permission_denied")
	ErrUnavailable = errors.New("storage_unavailable")
	ErrNotFound    = errors.New("storage_not_found")
	ErrConflict    = errors.New("storage_conflict")
	ErrCapacity    = errors.New("storage_capacity_unavailable")
	ErrIntegrity   = errors.New("storage_integrity_failed")
	ErrStale       = errors.New("storage_stale_operation")
	ErrUnknown     = errors.New("storage_remote_result_unknown")
)

var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`)
var digest = regexp.MustCompile(`^[a-f0-9]{64}$`)

func validID(s string) bool { return identifier.MatchString(s) }
func newID() string {
	var b [16]byte
	_, err := rand.Read(b[:])
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

type Principal struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
}

func (p Principal) Valid() bool {
	return p.Issuer != "" && p.Subject != "" && len(p.Issuer) <= 512 && len(p.Subject) <= 256
}

// Authorizer must check the current actor, action, object and protection scope.
// HTTP headers and previously issued publication events are not authorization facts.
type Authorizer interface {
	Authorize(context.Context, Principal, string, string, Protection) error
}

type Protection struct {
	Class     string `json:"class"`
	Scope     string `json:"scope"`
	Public    bool   `json:"public"`
	Encrypted bool   `json:"encrypted"`
}

func (p Protection) Valid() bool {
	return validID(p.Class) && validID(p.Scope) && !p.Encrypted && (!p.Public || p.Class == "public")
}

type Admission struct {
	Class     string    `json:"class"`
	Scope     string    `json:"scope"`
	Plaintext bool      `json:"plaintext"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Instance struct {
	ContributionControl *ContributionControl `json:"contribution_control,omitempty"`
	ID                  string               `json:"id"`
	Adapter             string               `json:"adapter"`
	AccountDomain       string               `json:"account_domain"`
	OwnerDomain         string               `json:"owner_domain"`
	Ownership           string               `json:"ownership"`
	CredentialRef       string               `json:"credential_ref"`
	CredentialRevision  int64                `json:"credential_revision"`
	Root                string               `json:"root"`
	Revision            int64                `json:"revision"`
	State               string               `json:"state"`
	Authorized          bool                 `json:"authorized"`
	Limit               int64                `json:"limit"`
	Used                int64                `json:"used"`
	Reserved            int64                `json:"reserved"`
	ProviderFree        int64                `json:"provider_free"`
	PersonalReserve     int64                `json:"personal_reserve"`
	SafetyMargin        int64                `json:"safety_margin"`
	QuotaRevision       int64                `json:"quota_revision"`
	QuotaExpiresAt      time.Time            `json:"quota_expires_at"`
	ExpiresAt           time.Time            `json:"expires_at"`
	Admissions          []Admission          `json:"admissions"`
}

func (i Instance) Allows(p Protection, now time.Time) bool {
	if i.ContributionControl != nil && i.ContributionControl.State == "revoked" {
		return false
	}
	if !i.Authorized || !i.ExpiresAt.After(now) || i.State == "revoked" || p.Encrypted {
		return false
	}
	// Plaintext restricted custody on user-controlled accounts is deferred.
	if !p.Public && i.Ownership != "platform" {
		return false
	}
	for _, a := range i.Admissions {
		if a.Class == p.Class && a.Scope == p.Scope && a.Plaintext && a.ExpiresAt.After(now) {
			return true
		}
	}
	return false
}
func (i Instance) CanWrite(p Protection, size int64, now time.Time) bool {
	if i.ContributionControl != nil && (i.ContributionControl.State != "active" || !i.ContributionControl.Until.After(now)) {
		return false
	}
	providerBudget := i.ProviderFree - i.PersonalReserve - i.SafetyMargin
	return i.Allows(p, now) && i.State == "active" && i.QuotaExpiresAt.After(now) && size >= 0 &&
		i.Used <= i.Limit && i.Reserved <= i.Limit-i.Used && size <= i.Limit-i.Used-i.Reserved &&
		i.Reserved <= providerBudget && size <= providerBudget-i.Reserved
}

func (i Instance) Draining(now time.Time) bool {
	return i.State == "draining" || (i.ContributionControl != nil && (i.ContributionControl.State == "draining" || !i.ContributionControl.Until.After(now)) && i.State != "revoked")
}

type Policy struct {
	Target  int `json:"target"`
	Publish int `json:"publish"`
}

func DefaultPolicy() Policy  { return Policy{Target: 3, Publish: 2} }
func (p Policy) Valid() bool { return p.Publish >= 2 && p.Target >= p.Publish && p.Target <= 10 }

type Object struct {
	CreationHash string      `json:"creation_hash,omitempty"`
	ID           string      `json:"id"`
	Owner        Principal   `json:"owner"`
	Size         int64       `json:"size"`
	SHA256       string      `json:"sha256"`
	Protection   Protection  `json:"protection"`
	Policy       Policy      `json:"policy"`
	Revision     int64       `json:"revision"`
	State        string      `json:"state"`
	Published    bool        `json:"published"`
	CreatedAt    time.Time   `json:"created_at"`
	References   []Reference `json:"references"`
}

type Reference struct {
	Module string `json:"module"`
	ID     string `json:"id"`
}
type Locator struct {
	ID       string `json:"id"`
	Revision string `json:"revision"`
}
type Replica struct {
	ID                 string    `json:"id"`
	ObjectID           string    `json:"object_id"`
	InstanceID         string    `json:"instance_id"`
	Intent             string    `json:"intent"`
	Remote             Locator   `json:"remote"`
	State              string    `json:"state"`
	InstanceRevision   int64     `json:"instance_revision"`
	CredentialRevision int64     `json:"credential_revision"`
	ObjectRevision     int64     `json:"object_revision"`
	VerifiedAt         time.Time `json:"verified_at"`
	Size               int64     `json:"size"`
	Reserved           bool      `json:"reserved"`
	Accounted          bool      `json:"accounted"`
	IssuedWrite        bool      `json:"issued_write"`
}

type Job struct {
	Intent             string    `json:"intent"`
	ObjectRevision     int64     `json:"object_revision"`
	InstanceRevision   int64     `json:"instance_revision"`
	CredentialRevision int64     `json:"credential_revision"`
	ID                 string    `json:"id"`
	ObjectID           string    `json:"object_id"`
	ReplicaID          string    `json:"replica_id"`
	Kind               string    `json:"kind"`
	State              string    `json:"state"`
	Generation         int64     `json:"generation"`
	LeaseOwner         string    `json:"lease_owner"`
	LeaseUntil         time.Time `json:"lease_until"`
	AvailableAt        time.Time `json:"available_at"`
	Attempts           int       `json:"attempts"`
	ErrorCode          string    `json:"error_code"`
}

type Event struct {
	SpecVersion     string    `json:"specversion"`
	Source          string    `json:"source"`
	Subject         string    `json:"subject"`
	DataContentType string    `json:"datacontenttype"`
	Data            EventData `json:"data"`
	ID              string    `json:"id"`
	Type            string    `json:"type"`
	ObjectID        string    `json:"-"`
	Revision        int64     `json:"-"`
	Time            time.Time `json:"time"`
	Actor           Principal `json:"-"`
	JobID           string    `json:"-"`
}

type EventData struct {
	JobID          string `json:"job_id,omitempty"`
	Revision       int64  `json:"revision"`
	PolicyRevision int64  `json:"policy_revision"`
	ObjectID       string `json:"object_id"`
}
type Idempotency struct {
	Key, Digest, ObjectID string
	Result                json.RawMessage
	ExpiresAt             time.Time
}

type InstanceEvidence struct {
	AccountDomain string
	ProviderFree  int64
	VerifiedAt    time.Time
}

// Verifier resolves the provider's stable account identity and validates the
// isolated root. Caller-supplied aliases must never establish replica independence.
type Verifier interface {
	Verify(context.Context, Instance) (InstanceEvidence, error)
}

// Driver's intent is a unique, platform-owned name in an isolated root. Find
// reconciles a write whose result was lost. Checkpoint must run before data write.
// Errors must be sanitized; absence must be explicit ErrNotFound.
type Driver interface {
	Find(context.Context, Instance, string, Locator) (Locator, error)
	Write(context.Context, Instance, string, int64, io.Reader, func(Locator) error) (Locator, error)
	Read(context.Context, Instance, Locator, io.Writer) (int64, error)
	Remove(context.Context, Instance, Locator) error
}

// Resolver uses credential references and revisions, never credentials in jobs.
type Resolver interface {
	Resolve(context.Context, Instance) (Driver, error)
}

type Repository interface {
	Transaction(context.Context, func(Transaction) error) error
	Claim(context.Context, string, time.Time, time.Duration) (Job, error)
	PendingEvents(context.Context, int) ([]Event, error)
	AcknowledgeEvent(context.Context, string) error
}

// Locks are acquired object -> instances in sorted ID order -> job. Claim only
// locks a job and commits before execution, so it cannot invert that order.
type Transaction interface {
	Lock(string) error
	Instance(string) (Instance, error)
	Instances(int, string) ([]Instance, error)
	ContributionCandidates(string, int, string) ([]Instance, error)
	SaveInstance(Instance) error
	InstanceReplicas(string) (int64, error)
	Object(string) (Object, error)
	Objects(int, string) ([]Object, error)
	SaveObject(Object) error
	Replicas(string) ([]Replica, error)
	SaveReplica(Replica) error
	Job(string) (Job, error)
	// JobSnapshot reads a binding without a row lock, for instance-before-job locking.
	JobSnapshot(string) (Job, error)
	SaveJob(Job) error
	OutstandingJobs(string, int) (int, error)
	ActiveWrites(string, time.Time) (bool, error)
	JobTotals() (JobTotals, error)
	FailedJobs(int, string) ([]Job, error)
	Idempotency(string) (Idempotency, error)
	SaveIdempotency(Idempotency) error
	Event(Event) error
}
