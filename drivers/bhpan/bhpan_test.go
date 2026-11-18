package bhpan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	storage "github.com/StuHelper/stuhelper-storage"
	protocol "github.com/StuHelper/stuhelper-storage-bhpan"
)

type fake struct {
	root, current, currentName, revision string
	shards                               map[string]string
	data                                 []byte
	deleted, closed, forbid, invisible   bool
	writes, purges                       int
	beforeWrite                          func()
	beforeIdentity                       func(context.Context) error
	beforeDownload                       func(context.Context) error
}

func (f *fake) Identity(ctx context.Context) (protocol.Identity, error) {
	if f.beforeIdentity != nil {
		if err := f.beforeIdentity(ctx); err != nil {
			return protocol.Identity{}, err
		}
	}
	return protocol.Identity{ID: "stable-user"}, nil
}
func (f *fake) Libraries(ctx context.Context) ([]protocol.Library, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return []protocol.Library{{ID: "gns://library", Type: "user_doc_lib"}}, nil
}
func (f *fake) Quota(ctx context.Context) (protocol.Quota, error) {
	if err := ctx.Err(); err != nil {
		return protocol.Quota{}, err
	}
	return protocol.Quota{Allocated: 1024}, nil
}
func (f *fake) CreateDirectory(ctx context.Context, parent, name string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if parent == "gns://library" {
		f.root = parent + "/owned"
		return f.root, nil
	}
	if f.shards == nil {
		f.shards = map[string]string{}
	}
	if _, exists := f.shards[name]; exists {
		return "", protocol.ErrConflict
	}
	id := parent + "/shard-" + name
	f.shards[name] = id
	return id, nil
}
func (f *fake) List(ctx context.Context, id string) (protocol.Directory, error) {
	if err := ctx.Err(); err != nil {
		return protocol.Directory{}, err
	}
	d := protocol.Directory{Directories: []protocol.Entry{}, Files: []protocol.Entry{}}
	if id == "gns://library" {
		d.Directories = append(d.Directories, protocol.Entry{ID: f.root})
		return d, nil
	}
	if id == f.root {
		for name, shardID := range f.shards {
			d.Directories = append(d.Directories, protocol.Entry{ID: shardID, Name: name})
		}
	}
	if f.current != "" && !f.deleted && strings.HasPrefix(f.current, id+"/") && !strings.Contains(strings.TrimPrefix(f.current, id+"/"), "/") {
		name := f.currentName
		if name == "" {
			name = strings.Repeat("a", 32)
		}
		d.Files = append(d.Files, protocol.Entry{ID: f.current, Name: name, Revision: f.revision})
	}
	return d, nil
}
func (f *fake) FileInfo(ctx context.Context, id string) (protocol.FileMetadata, error) {
	if err := ctx.Err(); err != nil {
		return protocol.FileMetadata{}, err
	}
	if f.forbid {
		return protocol.FileMetadata{}, protocol.ErrPermission
	}
	if f.current == "" {
		return protocol.FileMetadata{}, protocol.ErrNotFound
	}
	name := f.currentName
	if name == "" {
		name = strings.Repeat("a", 32)
	}
	return protocol.FileMetadata{ObjectID: id, DocumentID: f.current, Name: name, Revision: f.revision, Size: int64(len(f.data)), LibraryID: "library"}, nil
}
func (f *fake) BeginUpload(ctx context.Context, parent, name string, _ int64) (protocol.Upload, error) {
	if err := ctx.Err(); err != nil {
		return protocol.Upload{}, err
	}
	f.current = parent + "/object"
	f.currentName = name
	f.revision = "v1"
	return protocol.Upload{DocumentID: f.current, Revision: f.revision}, nil
}
func (f *fake) WriteUpload(ctx context.Context, _ protocol.Upload, src io.Reader) (string, error) {
	if f.beforeWrite != nil {
		f.beforeWrite()
	}
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	f.writes++
	f.data, _ = io.ReadAll(src)
	return "etag", nil
}
func (f *fake) FinishUpload(ctx context.Context, _, _ string) error { return ctx.Err() }
func (f *fake) Download(ctx context.Context, _ string, dst io.Writer) (int64, error) {
	if f.beforeDownload != nil {
		if err := f.beforeDownload(ctx); err != nil {
			return 0, err
		}
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	n, e := dst.Write(f.data)
	return int64(n), e
}
func (f *fake) Delete(context.Context, string) error {
	f.deleted = true
	f.current = "gns://recycle/object"
	return nil
}
func (f *fake) RecycleBin(context.Context, string, int, int) (protocol.Directory, error) {
	d := protocol.Directory{}
	if f.deleted && !f.invisible {
		d.Files = []protocol.Entry{{ID: f.current}}
	}
	return d, nil
}
func (f *fake) Purge(context.Context, string) error { f.purges++; f.current = ""; return nil }
func (f *fake) Close()                              { f.closed = true }
func fixture(t *testing.T) (*Pool, *fake, storage.Instance) {
	t.Helper()
	p := NewPool()
	f := &fake{}
	i, e := p.Provision(context.Background(), "credential", 1, f, time.Now().Add(time.Minute))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(p.Close)
	return p, f, i
}

func TestCheckpointReadAndPermanentDeletion(t *testing.T) {
	p, f, i := fixture(t)
	ctx := context.Background()
	e, err := p.Verify(ctx, i)
	if err != nil || e.AccountDomain != i.AccountDomain {
		t.Fatal(err)
	}
	checkpointed := false
	f.beforeWrite = func() {
		if !checkpointed {
			t.Error("data sent before durable identity")
		}
	}
	r, err := p.Write(ctx, i, strings.Repeat("a", 32), 4, strings.NewReader("test"), func(r storage.Locator) error { checkpointed = r.ID != ""; return nil })
	if err != nil {
		t.Fatal(err)
	}
	var dst bytes.Buffer
	if _, err = p.Read(ctx, i, r, &dst); err != nil || dst.String() != "test" {
		t.Fatal(err)
	}
	if err = p.Remove(ctx, i, r); err != nil || f.purges != 1 {
		t.Fatal(err)
	}
	if _, err = p.Find(ctx, i, strings.Repeat("a", 32), r); !errors.Is(err, storage.ErrNotFound) {
		t.Fatal(err)
	}
}
func TestForeignRootRevisionAndAmbiguousRecycleFailClosed(t *testing.T) {
	p, f, i := fixture(t)
	ctx := context.Background()
	r, err := p.Write(ctx, i, strings.Repeat("a", 32), 1, strings.NewReader("x"), func(storage.Locator) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	f.current = "gns://personal/object"
	if err = p.Remove(ctx, i, r); !errors.Is(err, storage.ErrUnknown) || f.purges != 0 {
		t.Fatal(err)
	}
	if _, err = p.Read(ctx, i, r, io.Discard); !errors.Is(err, storage.ErrIntegrity) {
		t.Fatal(err)
	}
	f.current = r.ID
	f.revision = "replaced"
	if _, err = p.Read(ctx, i, r, io.Discard); !errors.Is(err, storage.ErrIntegrity) {
		t.Fatal(err)
	}
	f.invisible = true
	if err = p.Remove(ctx, i, r); !errors.Is(err, storage.ErrUnknown) || f.purges != 0 {
		t.Fatal(err)
	}
	f.forbid = true
	if err = p.Remove(ctx, i, r); !errors.Is(err, storage.ErrDenied) {
		t.Fatal(err)
	}
	other := i
	other.Root = "gns://personal"
	if _, err = p.Resolve(ctx, other); !errors.Is(err, storage.ErrDenied) {
		t.Fatal(err)
	}
}
func TestRevokedSessionCannotSendGrantedUpload(t *testing.T) {
	p, f, i := fixture(t)
	ctx := context.Background()
	_, err := p.Write(ctx, i, strings.Repeat("a", 32), 1, strings.NewReader("x"), func(storage.Locator) error { p.Revoke(i.CredentialRef, i.CredentialRevision); return nil })
	if !errors.Is(err, storage.ErrDenied) || f.writes != 0 || !f.closed {
		t.Fatalf("revocation error=%v writes=%d", err, f.writes)
	}
	if _, err = p.Resolve(ctx, i); !errors.Is(err, storage.ErrDenied) {
		t.Fatal(err)
	}
}

func TestExplicitSessionDeadline(t *testing.T) {
	ctx := context.Background()
	p := NewPool()
	t.Cleanup(p.Close)
	f := &fake{}
	expires := time.Now().Add(48 * time.Hour)
	i, err := p.Provision(ctx, "managed-credential", 1, f, expires)
	if err != nil || !i.ExpiresAt.Equal(expires) {
		t.Fatalf("explicit authorization deadline rejected: %v", err)
	}
	if _, err = p.Verify(ctx, i); err != nil {
		t.Fatal(err)
	}
	p.Revoke(i.CredentialRef, i.CredentialRevision)
	if _, err = p.Resolve(ctx, i); !errors.Is(err, storage.ErrDenied) || !f.closed {
		t.Fatalf("longer authorization must remain revocable: %v", err)
	}
	for _, expired := range []time.Time{{}, time.Now().Add(-time.Second)} {
		untouched := &fake{}
		if _, err = p.Provision(ctx, "expired", 1, untouched, expired); !errors.Is(err, storage.ErrInput) || untouched.root != "" {
			t.Fatalf("expired authorization contacted provider: %v", err)
		}
	}

	i, err = p.Provision(ctx, "short-credential", 1, &fake{}, time.Now().Add(50*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	<-time.After(time.Until(i.ExpiresAt) + time.Millisecond)
	if _, err = p.Resolve(ctx, i); !errors.Is(err, storage.ErrDenied) {
		t.Fatalf("expired session accepted: %v", err)
	}
}

func TestCallerCancellationAndLeaseDeadlinePreserveSession(t *testing.T) {
	p, f, i := fixture(t)
	ctx := context.Background()
	intent := strings.Repeat("b", 32)
	r, err := p.Write(ctx, i, intent, 4, strings.NewReader("data"), func(storage.Locator) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = p.Read(canceled, i, r, io.Discard); !errors.Is(err, context.Canceled) || errors.Is(err, storage.ErrDenied) {
		t.Fatalf("caller cancel mapped to permission denial: %v", err)
	}
	expiredCtx, stop := context.WithDeadline(ctx, time.Now().Add(-time.Millisecond))
	defer stop()
	f.beforeWrite = nil
	if _, err = p.Write(expiredCtx, i, strings.Repeat("c", 32), 4, strings.NewReader("data"), func(storage.Locator) error { return nil }); !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, storage.ErrDenied) {
		t.Fatalf("caller deadline mapped to permission denial: %v", err)
	}
}

func TestProvisionDoesNotBlockPoolOrLeakRefCapacity(t *testing.T) {
	p, _, active := fixture(t)
	other, err := p.Provision(context.Background(), "other-credential", 1, &fake{}, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	slowCtx, cancelSlow := context.WithCancel(context.Background())
	t.Cleanup(cancelSlow)
	slow := &fake{
		beforeIdentity: func(ctx context.Context) error {
			close(entered)
			<-ctx.Done()
			return ctx.Err()
		},
	}
	provisionDone := make(chan error, 1)
	go func() {
		_, e := p.Provision(slowCtx, "slow-credential", 1, slow, time.Now().Add(time.Minute))
		provisionDone <- e
	}()
	<-entered
	verifyDone := make(chan error, 1)
	go func() {
		_, e := p.Verify(context.Background(), active)
		verifyDone <- e
	}()
	select {
	case err := <-verifyDone:
		if err != nil {
			t.Fatalf("concurrent verify failed: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Provision held global pool lock during network I/O")
	}
	revokeDone := make(chan struct{})
	go func() {
		p.Revoke(other.CredentialRef, other.CredentialRevision)
		p.Revoke("slow-credential", 1)
		close(revokeDone)
	}()
	select {
	case <-revokeDone:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Revoke blocked on slow Provision")
	}
	if err := <-provisionDone; !errors.Is(err, storage.ErrDenied) || !slow.closed {
		t.Fatalf("revoked in-flight provision result=%v closed=%v", err, slow.closed)
	}
	for n := 0; n < 120; n++ {
		bad := &fake{beforeIdentity: func(context.Context) error { return protocol.ErrUnavailable }}
		ref := "transient-failure-" + strings.Repeat("x", 4) + string(rune('a'+n%26)) + string(rune('0'+n/26))
		if _, err := p.Provision(context.Background(), ref, 1, bad, time.Now().Add(time.Minute)); !errors.Is(err, storage.ErrUnavailable) {
			t.Fatalf("unexpected error at %d: %v", n, err)
		}
	}
	if _, err := p.Provision(context.Background(), "valid-after-120-failures", 1, &fake{}, time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("failed attempts leaked versions capacity: %v", err)
	}
}

func TestRevokedReferencesReleasePoolSlots(t *testing.T) {
	p := NewPool()
	defer p.Close()
	until := time.Now().Add(time.Hour)
	for n := 0; n < 105; n++ {
		ref := fmt.Sprintf("withdrawn-%d", n)
		p.Revoke(ref, 1)
		if _, err := p.Provision(context.Background(), ref, 1, &fake{}, until); err == nil {
			t.Fatal("revoked revision accepted")
		}
	}
	if _, err := p.Provision(context.Background(), "replacement", 1, &fake{}, until); err != nil {
		t.Fatalf("withdrawn references still consume active slots: %v", err)
	}
}

func TestFindLegacyIntentAfterShardCached(t *testing.T) {
	p, f, i := fixture(t)
	intent := strings.Repeat("a", 32)
	_, err := p.Write(context.Background(), i, intent, 4, strings.NewReader("data"), func(storage.Locator) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	// The existing account also has a flat-layout upload with a lost response.
	f.current = f.root + "/old-file"
	f.currentName = "aa" + strings.Repeat("0", 30)
	got, err := p.Find(context.Background(), i, f.currentName, storage.Locator{})
	if err != nil || got.ID != f.current {
		t.Fatalf("legacy lookup: %+v, %v", got, err)
	}
}

type oversizedRootClient struct {
	fake
	rootLists int
}

func (f *oversizedRootClient) List(ctx context.Context, id string) (protocol.Directory, error) {
	if id == f.root {
		f.rootLists++
		return protocol.Directory{}, protocol.ErrProtocol
	}
	return f.fake.List(ctx, id)
}

func TestWriteWithExistingShardInOversizedLegacyRoot(t *testing.T) {
	p := NewPool()
	defer p.Close()
	ctx := context.Background()
	f := &oversizedRootClient{}
	i, err := p.Provision(ctx, "legacy", 1, f, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	f.shards = map[string]string{"ab": i.Root + "/existing"}
	var saved storage.Locator
	got, err := p.Write(ctx, i, strings.Repeat("ab", 16), 4, strings.NewReader("data"), func(loc storage.Locator) error { saved = loc; return nil })
	if err != nil || got != saved || got.ID != i.Root+"/object" || string(f.data) != "data" {
		t.Fatal(got, saved, err)
	}
	found, err := p.Find(ctx, i, strings.Repeat("ab", 16), saved)
	if err != nil || found != saved {
		t.Fatal(found, err)
	}
	_, err = p.Write(ctx, i, "ab"+strings.Repeat("1", 30), 4, strings.NewReader("next"), func(storage.Locator) error { return nil })
	if err != nil || f.rootLists != 1 {
		t.Fatalf("repeated oversized root listings: %d %v", f.rootLists, err)
	}

}
