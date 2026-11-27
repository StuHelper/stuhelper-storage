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
	return &restoringClient{fake: &fake{root: i.Root}, account: "stable-user", name: rootPrefix + "1234abcd"}
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
	bad.fake.root = "gns://library/another-id"
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

func TestOlderRevocationPreservesNewerCredentialWork(t *testing.T) {
	ctx := context.Background()
	p := NewPool()
	defer p.Close()
	f := &fake{beforeIdentity: func(ctx context.Context) error { p.Revoke("ordered", 4); return ctx.Err() }}
	i, err := p.Provision(ctx, "ordered", 5, f, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal("newer provisioning", err)
	}
	i.CredentialRevision = 6
	replacement := restoredClient(i)
	replacement.beforeList = func() { p.Revoke("ordered", 5) }
	if err = p.Restore(ctx, i, replacement); err != nil {
		t.Fatal("newer restore", err)
	}
	replacement.beforeList = nil
	if _, err = p.Verify(ctx, i); err != nil {
		t.Fatal(err)
	}
}

func TestManagedRootNameAndRestoreByBoundID(t *testing.T) {
	name, err := NewRootName()
	if err != nil || !IsManagedRootName(name) || len(strings.TrimPrefix(name, "【严禁自行删除！StuHelper贡献空间 严禁自行删除！】")) != 8 {
		t.Fatal("wrong new root format", err)
	}
	p, _, i := fixture(t)
	defer p.Close()
	for _, name := range []string{"stuhelper-storage-" + strings.Repeat("a", 32), "用户改过的名称"} {
		c := restoredClient(i)
		c.name = name
		if err := p.Restore(context.Background(), i, c); err != nil {
			t.Fatal("could not restore the bound ID", err)
		}
		if _, err := p.Verify(context.Background(), i); err != nil {
			t.Fatal("could not use restored session", err)
		}
	}
	c := restoredClient(i)
	c.name = name
	c.fake.root = "gns://library/foreign"
	if err := p.Restore(context.Background(), i, c); !errors.Is(err, storage.ErrDenied) {
		t.Fatal("restored a different ID with the expected name", err)
	}
}

func TestProvisionRejectsExistingManagedDirectory(t *testing.T) {
	p := NewPool()
	defer p.Close()
	existing := &restoringClient{fake: &fake{root: "gns://library/old"}, account: "confirmed-account", name: rootPrefix + "12345678"}
	_, err := p.Provision(t.Context(), "new-ref", 1, existing, time.Now().Add(time.Hour))
	if !errors.Is(err, storage.ErrConflict) || existing.root != "gns://library/old" {
		t.Fatalf("existing root overwritten: root=%q err=%v", existing.root, err)
	}
}
