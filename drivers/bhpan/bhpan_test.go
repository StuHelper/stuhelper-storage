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
	beforeWrite                        func()
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
