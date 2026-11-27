// Package bhpan connects the independent BHpan protocol library to storage.
// It never stores passwords, serializes sessions, or grants business access.
package bhpan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	storage "github.com/StuHelper/stuhelper-storage"
	protocol "github.com/StuHelper/stuhelper-storage-bhpan"
)

// Client is satisfied by the protocol client; no wire credentials enter storage.
type Client interface {
	Identity(context.Context) (protocol.Identity, error)
	Libraries(context.Context) ([]protocol.Library, error)
	Quota(context.Context) (protocol.Quota, error)
	List(context.Context, string) (protocol.Directory, error)
	CreateDirectory(context.Context, string, string) (string, error)
	FileInfo(context.Context, string) (protocol.FileMetadata, error)
	BeginUpload(context.Context, string, string, int64) (protocol.Upload, error)
	WriteUpload(context.Context, protocol.Upload, io.Reader) (string, error)
	FinishUpload(context.Context, string, string) error
	Download(context.Context, string, io.Writer) (int64, error)
	Delete(context.Context, string) error
	RecycleBin(context.Context, string, int, int) (protocol.Directory, error)
	Purge(context.Context, string) error
	Close()
}

// Older clients provide only the single-upload protocol.
type multipartClient interface {
	MultipartOptions(context.Context) (protocol.MultipartOptions, error)
	BeginMultipart(context.Context, string, string, int64) (protocol.MultipartUpload, error)
	PartGrants(context.Context, protocol.MultipartUpload, int, int) ([]protocol.PartGrant, error)
	WritePart(context.Context, protocol.PartGrant, io.Reader, int64) (protocol.Part, error)
	CompleteMultipart(context.Context, protocol.MultipartUpload, []protocol.Part) error
}

type session struct {
	pool                        *Pool
	client                      Client
	root, library, account, ref string
	revision                    int64
	expires                     time.Time
	ctx                         context.Context
	cancel                      context.CancelFunc
	timer                       *time.Timer
	shardMu                     sync.Mutex
	shards                      map[string]string
}

type provisionOperation struct {
	revision int64
	cancel   context.CancelFunc
}

const DefaultMultipartThreshold int64 = 16 << 20

// Pool holds sessions until an explicit operator-authorized deadline. That
// deadline limits local use; it does not assert a provider token's lifetime.
// Credential retention and renewal belong to the composition layer.
type Pool struct {
	mu                 sync.Mutex
	sessions           map[string]*session
	versions           map[string]uint64
	revoked            map[string]int64
	provisioning       map[string]*provisionOperation
	inFlight           map[string]int
	closed             bool
	observer           atomic.Pointer[storage.Observer]
	multipartThreshold int64
}

func NewPool() *Pool {
	return &Pool{
		sessions:           map[string]*session{},
		versions:           map[string]uint64{},
		revoked:            map[string]int64{},
		provisioning:       map[string]*provisionOperation{},
		multipartThreshold: DefaultMultipartThreshold,
		inFlight:           map[string]int{},
	}
}

// SetObserver installs or clears the sanitized diagnostic observer for provider errors.
func (p *Pool) SetObserver(obs storage.Observer) {
	if obs == nil {
		p.observer.Store(nil)
		return
	}
	p.observer.Store(&obs)
}

// SetMultipartThreshold configures the byte size above which Write switches to
// multipart uploads. Values <= 0 reset to DefaultMultipartThreshold (16 MiB).
func (p *Pool) SetMultipartThreshold(threshold int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if threshold <= 0 {
		threshold = DefaultMultipartThreshold
	}
	p.multipartThreshold = threshold
}

var token = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`)
var intentPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
var shardPattern = regexp.MustCompile(`^[a-f0-9]{2}$`)

// ErrSessionExpired distinguishes an invalid provider session from an operation
// permission denial. Callers may schedule a fresh login, but must not replay a
// possibly completed write merely because this error was returned.
var ErrSessionExpired = errors.New("bhpan_session_expired")

func accountDomain(id string) string {
	h := sha256.Sum256([]byte("bhpan.buaa.edu.cn\x00" + id))
	return "bhpan:" + hex.EncodeToString(h[:])
}

// AccountDomain derives the ledger's provider-scoped identifier. Its input must
// come from a verified Identity response, never a caller's claimed login name.
func AccountDomain(id string) string { return accountDomain(id) }
func leaf(id string) string          { return id[strings.LastIndex(id, "/")+1:] }
func child(root, id string) bool {
	suffix, ok := strings.CutPrefix(id, root+"/")
	return ok && suffix != "" && !strings.Contains(suffix, "/")
}
func ownedFile(root, id string) bool {
	suffix, ok := strings.CutPrefix(id, root+"/")
	if !ok || suffix == "" {
		return false
	}
	if !strings.Contains(suffix, "/") {
		return true
	}
	shard, file, ok := strings.Cut(suffix, "/")
	return ok && shard != "" && file != "" && !strings.Contains(file, "/")
}

func (p *Pool) cleanupRefLocked(ref string) {
	if p.sessions[ref] == nil && p.provisioning[ref] == nil && p.inFlight[ref] == 0 {
		delete(p.versions, ref)
		delete(p.provisioning, ref)
		delete(p.inFlight, ref)
	}
}

// Provision creates a new isolated directory. It never adopts a caller-selected
// personal directory. On success the pool owns the client and closes it on expiry.
func (p *Pool) Provision(ctx context.Context, ref string, revision int64, client Client, expires time.Time) (storage.Instance, error) {
	if !token.MatchString(ref) || revision < 1 || client == nil || !expires.After(time.Now()) {
		return storage.Instance{}, storage.ErrInput
	}
	p.mu.Lock()
	_, tracked := p.versions[ref]
	if _, ok := p.sessions[ref]; ok || p.provisioning[ref] != nil || p.closed || (!tracked && len(p.versions) >= 100) || revision <= p.revoked[ref] {
		p.mu.Unlock()
		return storage.Instance{}, storage.ErrConflict
	}
	opCtx, opCancel := context.WithDeadline(ctx, expires)
	p.versions[ref]++
	version := p.versions[ref]
	p.provisioning[ref] = &provisionOperation{revision: revision, cancel: opCancel}
	p.inFlight[ref]++
	p.mu.Unlock()

	root, library, account, err := p.provisionRemote(opCtx, client)

	p.mu.Lock()
	delete(p.provisioning, ref)
	p.inFlight[ref]--
	revoked := p.closed || revision <= p.revoked[ref] || p.versions[ref] != version || !expires.After(time.Now())
	if err != nil || revoked || ctx.Err() != nil {
		p.cleanupRefLocked(ref)
		p.mu.Unlock()
		opCancel()
		if revoked {
			client.Close()
			return storage.Instance{}, storage.ErrDenied
		}
		if err != nil {
			return storage.Instance{}, err
		}
		return storage.Instance{}, ctx.Err()
	}
	opCancel()
	sessionCtx, cancel := context.WithDeadline(context.Background(), expires)
	s := &session{pool: p, client: client, root: root, library: library, account: account, ref: ref, revision: revision, expires: expires, ctx: sessionCtx, cancel: cancel, shards: map[string]string{}}
	p.sessions[ref] = s
	s.timer = time.AfterFunc(time.Until(expires), func() { p.expire(s) })
	p.mu.Unlock()
	return storage.Instance{Adapter: "bhpan", AccountDomain: s.account, Root: root, CredentialRef: ref, CredentialRevision: revision, ExpiresAt: expires}, nil
}

func (p *Pool) provisionRemote(ctx context.Context, client Client) (string, string, string, error) {
	identity, err := client.Identity(ctx)
	if err != nil {
		return "", "", "", p.safe("identity", err)
	}
	if identity.ID == "" {
		return "", "", "", storage.ErrDenied
	}
	libraries, err := client.Libraries(ctx)
	if err != nil {
		return "", "", "", p.safe("libraries", err)
	}
	library := ""
	for _, item := range libraries {
		if item.Type == "user_doc_lib" {
			if library != "" {
				return "", "", "", storage.ErrConflict
			}
			library = item.ID
		}
	}
	if library == "" {
		return "", "", "", storage.ErrDenied
	}
	name, err := NewRootName()
	if err != nil {
		return "", "", "", err
	}
	root, err := client.CreateDirectory(ctx, library, name)
	if err != nil {
		return "", "", "", p.safe("create-directory", err)
	}
	if !child(library, root) {
		return "", "", "", storage.ErrUnknown
	}
	return root, library, accountDomain(identity.ID), nil
}

func (p *Pool) Revoke(ref string, revision int64) {
	p.mu.Lock()
	var cancelProvision context.CancelFunc
	if token.MatchString(ref) && revision > 0 {
		p.revoked[ref] = max(p.revoked[ref], revision)
		if work := p.provisioning[ref]; work != nil && work.revision <= revision {
			cancelProvision = work.cancel
		}
	}
	s, ok := p.sessions[ref]
	if ok && s.revision <= revision {
		delete(p.sessions, ref)
		s.cancel()
		if s.timer != nil {
			s.timer.Stop()
		}
	} else {
		s = nil
	}
	p.cleanupRefLocked(ref)
	p.mu.Unlock()
	if cancelProvision != nil {
		cancelProvision()
	}
	if s != nil {
		s.client.Close()
	}
}
func (p *Pool) Close() {
	p.mu.Lock()
	p.closed = true
	snapshots := make([]*session, 0, len(p.sessions))
	for _, s := range p.sessions {
		snapshots = append(snapshots, s)
	}
	cancels := make([]context.CancelFunc, 0, len(p.provisioning))
	for _, work := range p.provisioning {
		cancels = append(cancels, work.cancel)
	}
	p.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	for _, s := range snapshots {
		p.Revoke(s.ref, s.revision)
	}
}

// expire targets the actual session, so an old timer cannot revoke a replacement
// that uses the same credential revision after a fresh provider login.
func (p *Pool) expire(expected *session) {
	p.mu.Lock()
	if p.sessions[expected.ref] != expected {
		p.mu.Unlock()
		return
	}
	delete(p.sessions, expected.ref)
	p.versions[expected.ref]++
	expected.cancel()
	p.cleanupRefLocked(expected.ref)
	p.mu.Unlock()
	expected.client.Close()
}
func (p *Pool) get(i storage.Instance) (*session, error) {
	s, _, err := p.getWithThreshold(i)
	return s, err
}
func (s *session) operation(ctx context.Context) (context.Context, func()) {
	opCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.ctx, cancel)
	if s.ctx.Err() != nil {
		cancel()
	}
	return opCtx, func() { stop(); cancel() }
}
func (s *session) checkContext(ctx context.Context) error {
	if s.ctx.Err() != nil {
		return storage.ErrDenied
	}
	return ctx.Err()
}
func (s *session) safeErr(ctx context.Context, op string, err error) error {
	if err == nil {
		return nil
	}
	if s.ctx.Err() != nil {
		return storage.ErrDenied
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		if ctxErr := ctx.Err(); ctxErr != nil {
			err = ctxErr
		}
	}
	return s.pool.safe(op, err)
}
func (s *session) cacheShards(dirs []protocol.Entry) error {
	seen := map[string]string{}
	for _, d := range dirs {
		if !shardPattern.MatchString(d.Name) {
			continue
		}
		if !child(s.root, d.ID) || seen[d.Name] != "" {
			return storage.ErrUnknown
		}
		seen[d.Name] = d.ID
	}
	s.shardMu.Lock()
	defer s.shardMu.Unlock()
	if s.shards == nil {
		s.shards = map[string]string{}
	}
	for name, id := range seen {
		if existing := s.shards[name]; existing != "" && existing != s.root && existing != id {
			return storage.ErrUnknown
		}
		s.shards[name] = id
	}
	return nil
}
func (s *session) lookupShard(prefix string) string {
	s.shardMu.Lock()
	defer s.shardMu.Unlock()
	return s.shards[prefix]
}

// A verified flat root is also a valid write parent for legacy accounts.
func (s *session) rememberParent(prefix, parent string) string {
	s.shardMu.Lock()
	defer s.shardMu.Unlock()
	if known := s.shards[prefix]; known != "" {
		return known
	}
	s.shards[prefix] = parent
	return parent
}

func (s *session) ensureShard(ctx context.Context, opCtx context.Context, prefix string) (string, error) {
	if id := s.lookupShard(prefix); id != "" {
		return id, nil
	}
	created, err := s.client.CreateDirectory(opCtx, s.root, prefix)
	if err == nil {
		if !child(s.root, created) {
			return "", storage.ErrUnknown
		}
		return s.rememberParent(prefix, created), nil
	}
	if errors.Is(err, protocol.ErrConflict) {
		dir, listErr := s.client.List(opCtx, s.root)
		if errors.Is(listErr, protocol.ErrProtocol) && s.checkContext(ctx) == nil {
			// An oversized legacy root cannot reveal the existing shard ID.
			// New intents can still write to the verified root with a durable locator.
			return s.rememberParent(prefix, s.root), nil
		}
		if listErr != nil {
			return "", s.safeErr(ctx, "list", listErr)
		}
		if cacheErr := s.cacheShards(dir.Directories); cacheErr != nil {
			return "", cacheErr
		}
		if id := s.lookupShard(prefix); id != "" {
			return id, nil
		}
	}
	return "", s.safeErr(ctx, "create-directory", err)
}

func (p *Pool) Verify(ctx context.Context, i storage.Instance) (storage.InstanceEvidence, error) {
	s, err := p.get(i)
	if err != nil {
		return storage.InstanceEvidence{}, err
	}
	opCtx, done := s.operation(ctx)
	defer done()
	identity, err := s.client.Identity(opCtx)
	if err != nil {
		return storage.InstanceEvidence{}, s.safeErr(ctx, "identity", err)
	}
	if accountDomain(identity.ID) != s.account {
		p.observe("identity", "bhpan_identity_mismatch", 0)
		return storage.InstanceEvidence{}, storage.ErrDenied
	}
	dir, err := s.client.List(opCtx, s.library)
	if err != nil {
		return storage.InstanceEvidence{}, s.safeErr(ctx, "list", err)
	}
	found := false
	for _, e := range dir.Directories {
		if e.ID == s.root {
			found = true
		}
	}
	if !found {
		p.observe("list", "bhpan_root_missing", 0)
		return storage.InstanceEvidence{}, storage.ErrDenied
	}
	quota, err := s.client.Quota(opCtx)
	if err != nil {
		return storage.InstanceEvidence{}, s.safeErr(ctx, "quota", err)
	}
	return storage.InstanceEvidence{
		AccountDomain: s.account,
		ProviderFree:  quota.Available(),
		VerifiedAt:    time.Now(),
		Quota:         &storage.ProviderQuotaSample{TotalBytes: quota.Allocated, UsedBytes: quota.Used},
	}, nil
}
func (p *Pool) Resolve(ctx context.Context, i storage.Instance) (storage.Driver, error) {
	if _, err := p.get(i); err != nil {
		return nil, err
	}
	return p, nil
}

// Find follows a persisted stable object identity through recycle-bin moves.
// A missing name alone never proves a previously issued write did not happen.
func (p *Pool) Find(ctx context.Context, i storage.Instance, intent string, expected storage.Locator) (storage.Locator, error) {
	if !intentPattern.MatchString(intent) {
		return storage.Locator{}, storage.ErrInput
	}
	s, err := p.get(i)
	if err != nil {
		return storage.Locator{}, err
	}
	opCtx, done := s.operation(ctx)
	defer done()
	if expected.ID != "" {
		if !ownedFile(s.root, expected.ID) {
			return storage.Locator{}, storage.ErrDenied
		}
		m, err := s.client.FileInfo(opCtx, leaf(expected.ID))
		if err != nil {
			return storage.Locator{}, s.safeErr(ctx, "file-info", err)
		}
		if m.ObjectID != leaf(expected.ID) {
			return storage.Locator{}, storage.ErrIntegrity
		}
		// Keep the original locator as the immutable ownership record. Remove
		// resolves its current document ID and confirms exact recycle membership.
		return expected, nil
	}
	prefix := intent[:2]
	var out storage.Locator
	// Only recovery without a persisted ID needs a name lookup. Check both
	// layouts even when the session already knows a shard for this prefix.
	dir, err := s.client.List(opCtx, s.root)
	if err != nil {
		return out, s.safeErr(ctx, "list", err)
	}
	if err := s.cacheShards(dir.Directories); err != nil {
		return out, err
	}
	match := func(parent string, files []protocol.Entry) error {
		for _, e := range files {
			if e.Name != intent {
				continue
			}
			if out.ID != "" || !child(parent, e.ID) {
				return storage.ErrUnknown
			}
			out = storage.Locator{ID: e.ID, Revision: e.Revision}
		}
		return nil
	}
	if err := match(s.root, dir.Files); err != nil {
		return storage.Locator{}, err
	}
	if shard := s.lookupShard(prefix); shard != "" && shard != s.root {
		dir, err := s.client.List(opCtx, shard)
		if err != nil {
			return storage.Locator{}, s.safeErr(ctx, "list", err)
		}
		if err := match(shard, dir.Files); err != nil {
			return storage.Locator{}, err
		}
	}
	if out.ID == "" {
		return out, storage.ErrNotFound
	}
	return out, nil
}
func (p *Pool) Write(ctx context.Context, i storage.Instance, intent string, size int64, src io.Reader, checkpoint func(storage.Locator) error) (storage.Locator, error) {
	return p.WriteWithFence(ctx, i, intent, size, src, func() error { return nil }, checkpoint)
}

// WriteWithFence records the durable upload intent after shard setup and before
// BeginUpload, the first call that may create the remote file.
func (p *Pool) WriteWithFence(ctx context.Context, i storage.Instance, intent string, size int64, src io.Reader, issue func() error, checkpoint func(storage.Locator) error) (storage.Locator, error) {
	if !intentPattern.MatchString(intent) || size < 1 || src == nil || issue == nil || checkpoint == nil {
		return storage.Locator{}, storage.ErrInput
	}
	s, threshold, err := p.getWithThreshold(i)
	if err != nil {
		return storage.Locator{}, err
	}
	opCtx, done := s.operation(ctx)
	defer done()
	if err := s.checkContext(ctx); err != nil {
		return storage.Locator{}, err
	}
	shard, err := s.ensureShard(ctx, opCtx, intent[:2])
	if err != nil {
		return storage.Locator{}, err
	}
	if err := s.checkContext(ctx); err != nil {
		return storage.Locator{}, err
	}
	if multipart, ok := s.client.(multipartClient); ok && size > threshold {
		opts, err := multipart.MultipartOptions(opCtx)
		if err != nil {
			return storage.Locator{}, s.safeErr(ctx, "multipart-options", err)
		}
		if opts.MinimumSize <= 0 || opts.MaximumSize < opts.MinimumSize || opts.MaximumParts <= 0 {
			return storage.Locator{}, storage.ErrUnavailable
		}
		if size > opts.MinimumSize {
			return s.writeMultipart(opCtx, multipart, shard, intent, size, src, issue, checkpoint, opts, threshold)
		}
	}
	if err := issue(); err != nil {
		return storage.Locator{}, err
	}
	u, err := s.client.BeginUpload(opCtx, shard, intent, size)
	remote := storage.Locator{ID: u.DocumentID, Revision: u.Revision}
	// Even an invalid grant may have allocated a remote file. Persist a valid
	// object identity before returning the protocol error to recovery.
	if child(shard, u.DocumentID) {
		if e := checkpoint(remote); e != nil {
			return remote, e
		}
	}
	if err != nil {
		return remote, s.safeErr(ctx, "begin-upload", err)
	}
	if !child(shard, u.DocumentID) {
		return remote, storage.ErrUnknown
	}
	if err := s.checkContext(ctx); err != nil {
		return remote, err
	}
	if _, err = s.client.WriteUpload(opCtx, u, src); err != nil {
		return remote, s.safeErr(ctx, "write-upload", err)
	}
	// Recheck object, policy, instance and lease before metadata finalization.
	if err := checkpoint(remote); err != nil {
		return remote, err
	}
	if err := s.checkContext(ctx); err != nil {
		return remote, err
	}
	if err = s.client.FinishUpload(opCtx, u.DocumentID, u.Revision); err != nil {
		return remote, s.safeErr(ctx, "finish-upload", err)
	}
	return remote, nil
}

func (p *Pool) getWithThreshold(i storage.Instance) (*session, int64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.sessions[i.CredentialRef]
	if s == nil || i.Adapter != "bhpan" || i.CredentialRevision != s.revision || i.Root != s.root || (i.AccountDomain != "" && i.AccountDomain != s.account) || !s.expires.After(time.Now()) || i.ExpiresAt.After(s.expires) {
		return nil, 0, storage.ErrDenied
	}
	threshold := p.multipartThreshold
	if threshold <= 0 {
		threshold = DefaultMultipartThreshold
	}
	return s, threshold, nil
}

func (s *session) writeMultipart(ctx context.Context, client multipartClient, parent, intent string, size int64, src io.Reader, issue func() error, checkpoint func(storage.Locator) error, opts protocol.MultipartOptions, threshold int64) (storage.Locator, error) {
	maxParts := min(opts.MaximumParts, 10000)
	partSize := min(max(threshold, opts.MinimumSize), opts.MaximumSize)
	if minForParts := 1 + (size-1)/int64(maxParts); partSize < minForParts {
		partSize = minForParts
	}
	if partSize > opts.MaximumSize {
		return storage.Locator{}, storage.ErrInput
	}
	totalParts := int(1 + (size-1)/partSize)
	if err := s.checkContext(ctx); err != nil {
		return storage.Locator{}, err
	}
	if err := issue(); err != nil {
		return storage.Locator{}, err
	}
	u, err := client.BeginMultipart(ctx, parent, intent, size)
	remote := storage.Locator{ID: u.DocumentID, Revision: u.Revision}
	if child(parent, u.DocumentID) {
		if e := checkpoint(remote); e != nil {
			return remote, e
		}
	}
	if err != nil {
		return remote, s.safeErr(ctx, "begin-multipart", err)
	}
	if !child(parent, u.DocumentID) || u.UploadID == "" {
		return remote, storage.ErrUnknown
	}
	parts := make([]protocol.Part, 0, totalParts)
	remaining := size
	for first := 1; first <= totalParts; first += 100 {
		if err := s.checkContext(ctx); err != nil {
			return remote, err
		}
		last := min(totalParts, first+99)
		grants, err := client.PartGrants(ctx, u, first, last)
		if err != nil {
			return remote, s.safeErr(ctx, "part-grants", err)
		}
		if len(grants) != last-first+1 {
			return remote, storage.ErrUnavailable
		}
		for idx, g := range grants {
			if err := s.checkContext(ctx); err != nil {
				return remote, err
			}
			num := first + idx
			partLen := min(partSize, remaining)
			part, err := client.WritePart(ctx, g, io.LimitReader(src, partLen), partLen)
			if err != nil {
				return remote, s.safeErr(ctx, "write-part", err)
			}
			if part.Number != num || part.Size != partLen || part.ETag == "" {
				return remote, storage.ErrIntegrity
			}
			parts = append(parts, part)
			remaining -= partLen
		}
	}
	if remaining != 0 {
		return remote, storage.ErrIntegrity
	}
	if err := checkpoint(remote); err != nil {
		return remote, err
	}
	if err := s.checkContext(ctx); err != nil {
		return remote, err
	}
	if err := client.CompleteMultipart(ctx, u, parts); err != nil {
		return remote, s.safeErr(ctx, "complete-multipart", err)
	}
	return remote, nil
}
func (p *Pool) Read(ctx context.Context, i storage.Instance, r storage.Locator, dst io.Writer) (int64, error) {
	s, err := p.get(i)
	if err != nil {
		return 0, err
	}
	opCtx, done := s.operation(ctx)
	defer done()
	if !ownedFile(s.root, r.ID) {
		return 0, storage.ErrDenied
	}
	m, err := s.client.FileInfo(opCtx, leaf(r.ID))
	if err != nil {
		return 0, s.safeErr(ctx, "file-info", err)
	}
	if m.ObjectID != leaf(r.ID) || m.DocumentID != r.ID || (r.Revision != "" && m.Revision != r.Revision) {
		return 0, storage.ErrIntegrity
	}
	n, err := s.client.Download(opCtx, r.ID, dst)
	return n, s.safeErr(ctx, "download", err)
}
func (s *session) recycled(ctx context.Context, opCtx context.Context, id string) (bool, error) {
	// Bounded metadata scan. A full bin beyond this bound remains unknown and
	// requires later reconciliation; it never authorizes recursive cleanup.
	for start := 0; start < 10000; start += 1000 {
		dir, err := s.client.RecycleBin(opCtx, s.library, start, 1000)
		if err != nil {
			return false, s.safeErr(ctx, "recycle-bin", err)
		}
		for _, e := range dir.Files {
			if e.ID == id {
				return true, nil
			}
		}
		if len(dir.Files)+len(dir.Directories) < 1000 {
			return false, nil
		}
	}
	return false, storage.ErrUnknown
}
func (p *Pool) Remove(ctx context.Context, i storage.Instance, r storage.Locator) error {
	s, err := p.get(i)
	if err != nil {
		return err
	}
	opCtx, done := s.operation(ctx)
	defer done()
	if !ownedFile(s.root, r.ID) {
		return storage.ErrDenied
	}
	m, err := s.client.FileInfo(opCtx, leaf(r.ID))
	if errors.Is(err, protocol.ErrNotFound) {
		return nil
	}
	if err != nil {
		return s.safeErr(ctx, "file-info", err)
	}
	if m.ObjectID != leaf(r.ID) {
		return storage.ErrIntegrity
	}
	if m.DocumentID == r.ID {
		if err = s.client.Delete(opCtx, r.ID); err != nil {
			return s.safeErr(ctx, "delete", err)
		}
		m, err = s.client.FileInfo(opCtx, leaf(r.ID))
		if errors.Is(err, protocol.ErrNotFound) {
			return nil
		}
		if err != nil {
			return s.safeErr(ctx, "file-info", err)
		}
	}
	confirmed, err := s.recycled(ctx, opCtx, m.DocumentID)
	if err != nil {
		return err
	}
	if !confirmed {
		return storage.ErrUnknown
	}
	if err := s.checkContext(ctx); err != nil {
		return err
	}
	if err = s.client.Purge(opCtx, m.DocumentID); err != nil {
		return s.safeErr(ctx, "purge", err)
	}
	_, err = s.client.FileInfo(opCtx, leaf(r.ID))
	if errors.Is(err, protocol.ErrNotFound) {
		return nil
	}
	if err != nil {
		return s.safeErr(ctx, "file-info", err)
	}
	return storage.ErrUnknown
}
func (p *Pool) safe(op string, err error) error {
	if err == nil {
		return nil
	}
	if !errors.Is(err, protocol.ErrNotFound) {
		status := 0
		var pe *protocol.Error
		if errors.As(err, &pe) {
			if pe.Operation != "" {
				op = pe.Operation
			}
			status = pe.Status
		}
		p.observe(op, bhpanCategory(err), status)
	}
	return safe(err)
}
func (p *Pool) observe(op, category string, status int) {
	if p == nil {
		return
	}
	if obsPtr := p.observer.Load(); obsPtr != nil {
		storage.EmitDiagnostic(*obsPtr, storage.Diagnostic{
			Component:  "bhpan",
			Operation:  op,
			Category:   category,
			HTTPStatus: status,
		})
	}
}
func bhpanCategory(err error) string {
	switch {
	case errors.Is(err, protocol.ErrSession):
		return "bhpan_session"
	case errors.Is(err, protocol.ErrChallenge):
		return "bhpan_challenge"
	case errors.Is(err, protocol.ErrCredentials):
		return "bhpan_credentials"
	case errors.Is(err, protocol.ErrPermission):
		return "bhpan_permission"
	case errors.Is(err, protocol.ErrInput):
		return "bhpan_invalid_input"
	case errors.Is(err, protocol.ErrConflict):
		return "bhpan_conflict"
	case errors.Is(err, protocol.ErrProtocol):
		return "bhpan_protocol"
	case errors.Is(err, protocol.ErrDestination):
		return "bhpan_untrusted_destination"
	case errors.Is(err, protocol.ErrRejected):
		return "bhpan_rejected"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	case errors.Is(err, context.Canceled):
		return "canceled"
	default:
		return "bhpan_unavailable"
	}
}
func safe(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, protocol.ErrSession):
		return errors.Join(storage.ErrDenied, ErrSessionExpired)
	case errors.Is(err, protocol.ErrChallenge):
		return storage.ErrChallenge
	case errors.Is(err, protocol.ErrNotFound):
		return storage.ErrNotFound
	case errors.Is(err, protocol.ErrPermission), errors.Is(err, protocol.ErrCredentials):
		return storage.ErrDenied
	case errors.Is(err, protocol.ErrInput):
		return storage.ErrInput
	case errors.Is(err, protocol.ErrConflict):
		return storage.ErrConflict
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	default:
		return storage.ErrUnavailable
	}
}
