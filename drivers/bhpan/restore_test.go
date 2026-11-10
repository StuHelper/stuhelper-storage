package bhpan

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	storage "github.com/StuHelper/stuhelper-storage"
	protocol "github.com/StuHelper/stuhelper-storage-bhpan"
)

type restoringClient struct {
	*fake
	account    string
	name       string
	beforeList func()
}

func (f *restoringClient) Identity(context.Context) (protocol.Identity, error) {
	return protocol.Identity{ID: f.account}, nil
}
func (f *restoringClient) List(ctx context.Context, id string) (protocol.Directory, error) {
	if f.beforeList != nil {
		f.beforeList()
	}
	d, err := f.fake.List(ctx, id)
	for n := range d.Directories {
		d.Directories[n].Name = f.name
	}
	return d, err
}
func restoredClient(i storage.Instance) *restoringClient {
	return &restoringClient{fake: &fake{root: i.Root}, account: "stable-user", name: "stuhelper-storage-" + strings.Repeat("a", 32)}
}
func TestRestoreExistingBindingAndReplaceSession(t *testing.T) {
	p, _, i := fixture(t)
	p.Close()
	next := NewPool()
	t.Cleanup(next.Close)
	first := restoredClient(i)
	if err := next.Restore(context.Background(), i, first); err != nil {
		t.Fatal(err)
	}
	if _, err := next.Verify(context.Background(), i); err != nil {
		t.Fatal(err)
	}
	bad := restoredClient(i)
	bad.account = "another-account"
	if err := next.Restore(context.Background(), i, bad); !errors.Is(err, storage.ErrDenied) {
		t.Fatal(err)
	}
	if first.closed {
		t.Fatal("failed validation destroyed active session")
	}
	next.mu.Lock()
	old := next.sessions[i.CredentialRef]
	next.mu.Unlock()
	second := restoredClient(i)
	if err := next.Restore(context.Background(), i, second); err != nil {
		t.Fatal(err)
	}
	next.expire(old)
	if !first.closed || second.closed {
		t.Fatal("replacement or old timer affected wrong session")
	}
	if _, err := next.Verify(context.Background(), i); err != nil {
		t.Fatal(err)
	}
}
func TestRestoreRejectsForeignRootAndRevokedLateResult(t *testing.T) {
	p, _, i := fixture(t)
	bad := restoredClient(i)
	bad.name = "personal"
	if err := p.Restore(context.Background(), i, bad); !errors.Is(err, storage.ErrDenied) {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	f := restoredClient(i)
	f.beforeList = func() { close(entered); <-release }
	result := make(chan error, 1)
	go func() { result <- p.Restore(context.Background(), i, f) }()
	<-entered
	p.Revoke(i.CredentialRef, i.CredentialRevision)
	close(release)
	if err := <-result; !errors.Is(err, storage.ErrStale) {
		t.Fatal(err)
	}
	if err := p.Restore(context.Background(), i, restoredClient(i)); !errors.Is(err, storage.ErrDenied) {
		t.Fatal(err)
	}
	i.CredentialRevision++
	if err := p.Restore(context.Background(), i, restoredClient(i)); err != nil {
		t.Fatal(err)
	}
	p.Close()
	i.ExpiresAt = time.Now().Add(time.Hour)
	if err := p.Restore(context.Background(), i, restoredClient(i)); !errors.Is(err, storage.ErrDenied) {
		t.Fatal(err)
	}
}
