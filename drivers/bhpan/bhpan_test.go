package bhpan

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	storage "github.com/StuHelper/stuhelper-storage"
	protocol "github.com/StuHelper/stuhelper-storage-bhpan"
)

type fake struct {
	root, current, revision            string
	data                               []byte
	deleted, closed, forbid, invisible bool
	writes, purges                     int
	multipartBegins, multipartParts    int
	multipartCompletes                 int
	multipartGrantBatches              int
	multipartMinSize                   int64
	beforeWrite                        func()
	partStaging                        bytes.Buffer
}

func (f *fake) Identity(context.Context) (protocol.Identity, error) {
	return protocol.Identity{ID: "stable-user"}, nil
}
func (f *fake) Libraries(context.Context) ([]protocol.Library, error) {
	return []protocol.Library{{ID: "gns://library", Type: "user_doc_lib"}}, nil
}
func (f *fake) Quota(context.Context) (protocol.Quota, error) {
	return protocol.Quota{Allocated: 1024}, nil
}
func (f *fake) CreateDirectory(_ context.Context, parent, name string) (string, error) {
	f.root = parent + "/owned"
	return f.root, nil
}
func (f *fake) List(_ context.Context, id string) (protocol.Directory, error) {
	d := protocol.Directory{Directories: []protocol.Entry{}, Files: []protocol.Entry{}}
	if id == "gns://library" {
		d.Directories = append(d.Directories, protocol.Entry{ID: f.root})
	} else if f.current == f.root+"/object" {
		d.Files = append(d.Files, protocol.Entry{ID: f.current, Name: strings.Repeat("a", 32), Revision: f.revision})
	}
	return d, nil
}
func (f *fake) FileInfo(_ context.Context, id string) (protocol.FileMetadata, error) {
	if f.forbid {
		return protocol.FileMetadata{}, protocol.ErrPermission
	}
	if f.current == "" {
		return protocol.FileMetadata{}, protocol.ErrNotFound
	}
	return protocol.FileMetadata{ObjectID: id, DocumentID: f.current, Name: strings.Repeat("a", 32), Revision: f.revision, Size: int64(len(f.data)), LibraryID: "library"}, nil
}
func (f *fake) BeginUpload(context.Context, string, string, int64) (protocol.Upload, error) {
	f.current = f.root + "/object"
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
func (f *fake) FinishUpload(context.Context, string, string) error { return nil }
func (f *fake) MultipartOptions(context.Context) (protocol.MultipartOptions, error) {
	minSize := f.multipartMinSize
	if minSize == 0 {
		minSize = 4 << 20
	}
	return protocol.MultipartOptions{MinimumSize: minSize, MaximumSize: 64 << 20, MaximumParts: 10000}, nil
}
func (f *fake) BeginMultipart(context.Context, string, string, int64) (protocol.MultipartUpload, error) {
	f.multipartBegins++
	f.partStaging.Reset()
	f.current = f.root + "/object"
	f.revision = "v1"
	return protocol.MultipartUpload{DocumentID: f.current, Revision: f.revision, UploadID: "upload-1"}, nil
}
func (f *fake) PartGrants(_ context.Context, _ protocol.MultipartUpload, first, last int) ([]protocol.PartGrant, error) {
	f.multipartGrantBatches++
	out := make([]protocol.PartGrant, last-first+1)
	return out, nil
}
func (f *fake) WritePart(ctx context.Context, _ protocol.PartGrant, src io.Reader, length int64) (protocol.Part, error) {
	if f.beforeWrite != nil {
		f.beforeWrite()
	}
	if ctx.Err() != nil {
		return protocol.Part{}, ctx.Err()
	}
	b, err := io.ReadAll(src)
	if err != nil {
		return protocol.Part{}, err
	}
	f.multipartParts++
	_, _ = f.partStaging.Write(b)
	return protocol.Part{Number: f.multipartParts, ETag: "part-etag", Size: int64(len(b))}, nil
}
func (f *fake) CompleteMultipart(_ context.Context, _ protocol.MultipartUpload, parts []protocol.Part) error {
	if len(parts) == 0 {
		return protocol.ErrInput
	}
	f.multipartCompletes++
	f.data = bytes.Clone(f.partStaging.Bytes())
	return nil
}
func (f *fake) Download(_ context.Context, _ string, dst io.Writer) (int64, error) {
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

func TestMultipartUploadCheckpointRevocationAndFallback(t *testing.T) {
	p, f, i := fixture(t)
	ctx := context.Background()
	large := bytes.Repeat([]byte("0123456789abcdef"), (17<<20)/16)
	checkpointCalls := 0
	f.beforeWrite = func() {
		if checkpointCalls == 0 {
			t.Error("multipart part written before durable locator checkpoint")
		}
	}
	remote, err := p.Write(ctx, i, strings.Repeat("b", 32), int64(len(large)), bytes.NewReader(large), func(r storage.Locator) error {
		if r.ID == "" {
			return storage.ErrInput
		}
		checkpointCalls++
		return nil
	})
	if err != nil {
		t.Fatalf("multipart write failed: %v", err)
	}
	if f.writes != 0 || f.multipartBegins != 1 || f.multipartParts != 2 || f.multipartCompletes != 1 || checkpointCalls != 2 {
		t.Fatalf("unexpected multipart counters: single=%d begins=%d parts=%d completes=%d checkpoints=%d", f.writes, f.multipartBegins, f.multipartParts, f.multipartCompletes, checkpointCalls)
	}
	var got bytes.Buffer
	if _, err = p.Read(ctx, i, remote, &got); err != nil || !bytes.Equal(got.Bytes(), large) {
		t.Fatalf("multipart readback mismatch: err=%v len=%d", err, got.Len())
	}

	// Verify >100 parts batching with custom threshold and small min part size.
	f2 := &fake{multipartMinSize: 64}
	p2 := NewPool()
	p2.SetMultipartThreshold(64)
	t.Cleanup(p2.Close)
	i2, err := p2.Provision(ctx, "batched", 1, f2, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	batchedData := bytes.Repeat([]byte("z"), 64*105+13)
	if _, err = p2.Write(ctx, i2, strings.Repeat("c", 32), int64(len(batchedData)), bytes.NewReader(batchedData), func(storage.Locator) error { return nil }); err != nil {
		t.Fatalf("multi-batch multipart failed: %v", err)
	}
	if f2.multipartGrantBatches != 2 || f2.multipartParts != 106 || f2.multipartCompletes != 1 {
		t.Fatalf("expected 2 grant batches and 106 parts, got batches=%d parts=%d", f2.multipartGrantBatches, f2.multipartParts)
	}

	// Fallback to single PUT when provider MinimumSize >= object size.
	f3 := &fake{multipartMinSize: 32 << 20}
	p3 := NewPool()
	t.Cleanup(p3.Close)
	i3, err := p3.Provision(ctx, "fallback", 1, f3, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	medium := bytes.Repeat([]byte("m"), 17<<20)
	if _, err = p3.Write(ctx, i3, strings.Repeat("d", 32), int64(len(medium)), bytes.NewReader(medium), func(storage.Locator) error { return nil }); err != nil {
		t.Fatalf("fallback write failed: %v", err)
	}
	if f3.writes != 1 || f3.multipartBegins != 0 {
		t.Fatalf("expected single-PUT fallback, got writes=%d multipartBegins=%d", f3.writes, f3.multipartBegins)
	}

	// Revocation during multipart checkpoint prevents part uploads and completion.
	f4 := &fake{}
	p4 := NewPool()
	t.Cleanup(p4.Close)
	i4, err := p4.Provision(ctx, "revoke-multi", 1, f4, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	_, err = p4.Write(ctx, i4, strings.Repeat("e", 32), int64(len(large)), bytes.NewReader(large), func(storage.Locator) error {
		p4.Revoke(i4.CredentialRef, i4.CredentialRevision)
		return nil
	})
	if !errors.Is(err, storage.ErrDenied) || f4.multipartParts != 0 || f4.multipartCompletes != 0 {
		t.Fatalf("revoked multipart continued: err=%v parts=%d completes=%d", err, f4.multipartParts, f4.multipartCompletes)
	}
}
