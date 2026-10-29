// Package custody coordinates explicit provider custody separately from storage
// contribution. Secret persistence and provider authentication belong to Provider.
package custody

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"regexp"
	"time"

	storage "github.com/StuHelper/stuhelper-storage"
)

type Consent struct {
	Accepted bool   `json:"accepted"`
	Version  string `json:"version"`
	Digest   string `json:"digest"`
}
type Policy struct {
	Version        string `json:"version"`
	Digest         string `json:"digest"`
	URL            string `json:"url"`
	MaxTermSeconds int64  `json:"max_term_seconds"`
}
type Request struct {
	Adapter    string          `json:"adapter"`
	Credential json.RawMessage `json:"credential"`
	Until      time.Time       `json:"until"`
	Consent    Consent         `json:"consent"`
	Revision   int64           `json:"revision,omitempty"`
}

func (Request) String() string     { return "[custody request redacted]" }
func (r Request) GoString() string { return r.String() }

type View struct {
	ID        string    `json:"id"`
	Adapter   string    `json:"adapter"`
	Revision  int64     `json:"revision"`
	State     string    `json:"state"`
	Until     time.Time `json:"authorization_expires_at"`
	RequestID string    `json:"request_id"`
	LastError string    `json:"last_error"`
}
type Page struct {
	Items      []View `json:"items"`
	NextCursor string `json:"next_cursor"`
}
type ResumeRequest struct {
	RequestID string `json:"request_id"`
	Revision  int64  `json:"revision"`
}

// Binding and Operation are private ledger models, never HTTP responses.
type Binding struct {
	View
	Owner         storage.Principal
	AccountDomain string
	Instance      storage.Instance
}
type Operation struct {
	ID               string
	BindingID        string
	Owner            storage.Principal
	Fingerprint      string
	Consent          Consent
	Until            time.Time
	ExpectedRevision int64
	Attempts         int
	AttemptedAt      time.Time
	LeaseUntil       time.Time
	Result           *storage.Instance
	Complete         bool
}
type Tx interface {
	Binding(string) (Binding, error)
	SaveBinding(Binding) error
	Operation(string) (Operation, error)
	SaveOperation(Operation) error
	List(storage.Principal, int, string) ([]Binding, error)
	Count(storage.Principal) (int, error)
	RecentAttempts(storage.Principal, time.Time) (int, error)
	OperationCount() (int, error)
	Event(storage.Event) error
}
type Repository interface {
	Transaction(context.Context, func(Tx) error) error
}
type Store interface {
	Instances(context.Context, storage.Principal, int, string) ([]storage.Instance, error)
	Register(context.Context, storage.Principal, string, storage.Instance) (storage.Instance, error)
	ReauthorizeInstance(context.Context, storage.Principal, string, storage.CredentialRenewal) (storage.Instance, error)
}
type Provider interface {
	// Fingerprint must use a private key: public password hashes are forbidden.
	Fingerprint([]byte) (string, error)
	ValidateInput(string, json.RawMessage) error
	Prepare(context.Context, string, time.Time, json.RawMessage, *storage.Instance, func(string) error) (storage.Instance, error)
	Resume(context.Context, string, time.Time, *storage.Instance, func(string) error) (storage.Instance, error)
	Commit(context.Context, storage.Instance) error
}
type Config struct {
	Policy       Policy
	Actor        storage.Principal
	PublicScopes []string
	Clock        func() time.Time
	Timeout      time.Duration
}
type Service struct {
	repo     Repository
	auth     storage.Authorizer
	store    Store
	provider Provider
	cfg      Config
}

var uuid = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
var id = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`)
var digest = regexp.MustCompile(`^[a-f0-9]{64}$`)

func OwnerDomain(p storage.Principal) string {
	b, _ := json.Marshal(p)
	sum := sha256.Sum256(b)
	return "owner:" + hex.EncodeToString(sum[:])
}
func New(r Repository, a storage.Authorizer, s Store, p Provider, c Config) (*Service, error) {
	u, e := url.Parse(c.Policy.URL)
	if r == nil || a == nil || s == nil || p == nil || !c.Actor.Valid() || !id.MatchString(c.Policy.Version) || !digest.MatchString(c.Policy.Digest) || e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || c.Policy.MaxTermSeconds < 3600 || c.Policy.MaxTermSeconds > 366*86400 || c.Timeout < time.Second || c.Timeout > time.Minute || len(c.PublicScopes) < 1 || len(c.PublicScopes) > 64 {
		return nil, storage.ErrInput
	}
	for _, s := range c.PublicScopes {
		if !id.MatchString(s) {
			return nil, storage.ErrInput
		}
	}
	if c.Clock == nil {
		c.Clock = time.Now
	}
	return &Service{r, a, s, p, c}, nil
}
func (s *Service) Policy() Policy { return s.cfg.Policy }
func (s *Service) authorize(ctx context.Context, p storage.Principal, action, resource string) error {
	if !p.Valid() || p == s.cfg.Actor {
		return storage.ErrDenied
	}
	return s.auth.Authorize(ctx, p, action, resource, storage.Protection{})
}
