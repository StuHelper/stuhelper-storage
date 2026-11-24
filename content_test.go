package storage_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	storage "github.com/StuHelper/stuhelper-storage"
	"github.com/StuHelper/stuhelper-storage/postgres"
	"github.com/StuHelper/stuhelper-storage/storagetest"
	"sync"
	"testing"
	"time"
)

func sharedRequest(data []byte) storage.CreateRequest {
	sum := sha256.Sum256(data)
	return storage.CreateRequest{Deduplicate: true, Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:]), Protection: storage.Protection{Class: "public", Scope: "school-a", Public: true}}
}
func sharedCreate(t *testing.T, h *harness, key string, r storage.CreateRequest) storage.Status {
	t.Helper()
	st, e := h.s.Create(h.ctx, h.actor, key, r)
	if e != nil {
		t.Fatal(e)
	}
	return st
}
func drainContent(t *testing.T, h *harness) {
	t.Helper()
	for i := 0; i < 100; i++ {
		ok, e := h.s.RunOne(h.ctx, "content-worker")
		if e != nil {
			t.Fatal(e)
		}
		if !ok {
			return
		}
	}
	t.Fatal("content jobs did not finish")
}
func physicalCount(t *testing.T, h *harness) int {
	t.Helper()
	var n int
	if e := h.db.QueryRow(`SELECT count(*) FROM storage.objects WHERE data->>'state' NOT IN ('deleted','deleting')`).Scan(&n); e != nil {
		t.Fatal(e)
	}
	return n
}
func TestSharedContentConcurrentProofAndSinglePhysicalObject(t *testing.T) {
	h := harnessFor(t)
	for i := 0; i < 3; i++ {
		h.instance(t, fmt.Sprint(i), fmt.Sprint(i), 1024)
	}
	data := []byte("shared immutable content")
	req := sharedRequest(data)
	const n = 12
	out := make([]storage.Status, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func(i int) { defer wg.Done(); out[i], errs[i] = h.s.Create(h.ctx, h.actor, fmt.Sprint(i), req) }(i)
	}
	wg.Wait()
	for i, e := range errs {
		if e != nil {
			t.Fatal(e)
		}
		for j := 0; j < i; j++ {
			if out[j].ID == out[i].ID {
				t.Fatal("independent logical uploads collapsed")
			}
		}
	}
	if _, e := h.s.Ingest(h.ctx, h.actor, out[1].ID, "bad", bytes.NewReader(bytes.Repeat([]byte{'x'}, len(data)))); !errors.Is(e, storage.ErrIntegrity) {
		t.Fatalf("hash-only spoof: %v", e)
	}
	h.ingest(t, out[0].ID, data)
	hidden, e := h.s.Status(h.ctx, h.actor, out[1].ID)
	if e != nil || hidden.Healthy != 0 {
		t.Fatalf("unproven digest disclosed shared health: %+v %v", hidden, e)
	}
	if e = h.s.ReviewDownload(h.ctx, h.actor, out[1].ID, &bytes.Buffer{}); !errors.Is(e, storage.ErrDenied) {
		t.Fatal(e)
	}
	for i := 1; i < n; i++ {
		h.ingest(t, out[i].ID, data)
	}
	if physicalCount(t, h) != 1 || h.provider.writes != 1 {
		t.Fatalf("duplicate physical upload: %d writes", h.provider.writes)
	}
	h.reconcile(t)
	drainContent(t, h)
	if h.provider.writes != 3 {
		t.Fatalf("one replica set expected, got %d", h.provider.writes)
	}
	for _, o := range out {
		var b bytes.Buffer
		if e = h.s.Download(h.ctx, h.actor, o.ID, &b); e != nil || !bytes.Equal(data, b.Bytes()) {
			t.Fatalf("shared read %v", e)
		}
	}
}
func TestSharedContentIndependentReferencesAndLastRelease(t *testing.T) {
	h := harnessFor(t)
	for i := 0; i < 3; i++ {
		h.instance(t, fmt.Sprint(i), fmt.Sprint(i), 1024)
	}
	data := []byte("keep the other reference")
	a := sharedCreate(t, h, "a", sharedRequest(data))
	h.ingest(t, a.ID, data)
	req := sharedRequest(data)
	req.ReuseFrom = a.ID
	b := sharedCreate(t, h, "b", req)
	if h.provider.writes != 1 {
		t.Fatal("reuse uploaded bytes")
	}
	h.reconcile(t)
	drainContent(t, h)
	ref := storage.Reference{Module: "media", ID: "file"}
	if _, e := h.s.Reference(h.ctx, h.actor, b.ID, "attach", ref, true); e != nil {
		t.Fatal(e)
	}
	if _, e := h.s.Delete(h.ctx, h.actor, a.ID, "delete-a", a.Revision); e != nil {
		t.Fatal(e)
	}
	h.reconcile(t)
	drainContent(t, h)
	var buf bytes.Buffer
	if e := h.s.Download(h.ctx, h.actor, b.ID, &buf); e != nil || !bytes.Equal(buf.Bytes(), data) {
		t.Fatal("released another file", e)
	}
	if _, e := h.s.Delete(h.ctx, h.actor, b.ID, "still-held", b.Revision); !errors.Is(e, storage.ErrConflict) {
		t.Fatal(e)
	}
	if _, e := h.s.Reference(h.ctx, h.actor, b.ID, "release", ref, false); e != nil {
		t.Fatal(e)
	}
	deleting, e := h.s.Delete(h.ctx, h.actor, b.ID, "delete-b", b.Revision)
	if e != nil || deleting.State != "deleting" {
		t.Fatalf("last release reported cleanup before provider deletion: %+v %v", deleting, e)
	}
	drainContent(t, h)
	h.reconcile(t)
	state, e := h.s.Status(h.ctx, h.actor, b.ID)
	if e != nil || state.State != "deleted" {
		t.Fatalf("cleanup %+v %v", state, e)
	}
	for _, files := range h.provider.files {
		if len(files) != 0 {
			t.Fatal("last release retained provider bytes")
		}
	}
	c := sharedCreate(t, h, "new", sharedRequest(data))
	h.ingest(t, c.ID, data)
	if h.provider.writes != 4 {
		t.Fatal("deleted group was resurrected")
	}
}
func TestSharedContentProtectionMigrationAndReuseRemainIndependent(t *testing.T) {
	h := harnessFor(t)
	for i := 0; i < 3; i++ {
		v := h.instance(t, fmt.Sprint(i), storage.ContributionOwnerDomain(h.actor), 4096)
		if _, e := storagetest.Trust(h.ctx, h.s, h.actor, v, "school-a", []string{"quarantine"}); e != nil {
			t.Fatal(e)
		}
	}
	data := []byte("same bytes with different protection")
	a := sharedCreate(t, h, "a", sharedRequest(data))
	h.ingest(t, a.ID, data)
	req := sharedRequest(data)
	req.ReuseFrom = a.ID
	b := sharedCreate(t, h, "b", req)
	restricted := storage.Protection{Class: "quarantine", Scope: "school-a"}
	moved, e := h.s.ChangeProtection(h.ctx, h.actor, a.ID, "move-a", a.Revision, restricted)
	if e != nil || moved.Protection != restricted {
		t.Fatalf("move %v %+v", e, moved)
	}
	original, e := h.s.Status(h.ctx, h.actor, b.ID)
	if e != nil || original.Protection != req.Protection {
		t.Fatal("changed another handle's protection", e)
	}
	if physicalCount(t, h) != 2 {
		t.Fatal("different protection groups were merged")
	}
	before := h.provider.writes
	moved, e = h.s.ChangeProtection(h.ctx, h.actor, b.ID, "move-b", b.Revision, restricted)
	if e != nil {
		t.Fatal(e)
	}
	if h.provider.writes != before {
		t.Fatal("existing destination was uploaded again")
	}
	drainContent(t, h)
	h.reconcile(t)
	drainContent(t, h)
	if physicalCount(t, h) != 1 {
		t.Fatal("source group was not released")
	}
	var buf bytes.Buffer
	if e = h.s.ReviewDownload(h.ctx, h.actor, moved.ID, &buf); e != nil || !bytes.Equal(buf.Bytes(), data) {
		t.Fatal(e)
	}
}
func TestSharedContentReplayScopePolicyAndMigration(t *testing.T) {
	h := harnessFor(t)
	h.instance(t, "one", "one", 4096)
	data := []byte("stable content key")
	req := sharedRequest(data)
	req.ClientKey = "same-session"
	a := sharedCreate(t, h, "key", req)
	h.ingest(t, a.ID, data)
	again := sharedCreate(t, h, "retry", req)
	if a.ID != again.ID {
		t.Fatal("stable key changed")
	}
	changed := req
	changed.Size++
	if _, e := h.s.Create(h.ctx, h.actor, "other", changed); !errors.Is(e, storage.ErrConflict) {
		t.Fatal(e)
	}
	for _, change := range []func(*storage.CreateRequest){func(r *storage.CreateRequest) { r.Protection.Scope = "other-school" }, func(r *storage.CreateRequest) { r.Policy = storage.Policy{Publish: 2, Target: 4} }} {
		r := sharedRequest(data)
		change(&r)
		sharedCreate(t, h, fmt.Sprint(r), r)
	}
	var count int
	if e := h.db.QueryRow(`SELECT count(*) FROM storage.content_groups WHERE active`).Scan(&count); e != nil || count != 3 {
		t.Fatalf("scope/policy groups %d %v", count, e)
	}
	if _, e := h.admin.Exec(postgres.Schema); e != nil {
		t.Fatal(e)
	}
	if e := h.repo.CheckRuntime(h.ctx); e != nil {
		t.Fatal(e)
	}
	st, e := h.s.Status(h.ctx, h.actor, a.ID)
	if e != nil || st.Healthy != 1 {
		t.Fatal("migration did not preserve data", e)
	}
	h.auth.denied.Store(true)
	if _, e = h.s.Create(h.ctx, h.actor, "key", req); !errors.Is(e, storage.ErrDenied) {
		t.Fatal("replay bypassed permission", e)
	}
}

func TestSharedContentLostReplyExpiryAndCanonicalProtection(t *testing.T) {
	h := harnessFor(t)
	instance := h.instance(t, "one", "one", 4096)
	instance.ExpiresAt = h.clock.Now().Add(72 * time.Hour)
	for i := range instance.Admissions {
		instance.Admissions[i].ExpiresAt = instance.ExpiresAt
	}
	if _, e := h.s.UpdateInstance(h.ctx, h.actor, "long-auth", instance); e != nil {
		t.Fatal(e)
	}
	data := []byte("durable shared upload")
	a := sharedCreate(t, h, "a", sharedRequest(data))
	b := sharedCreate(t, h, "b", sharedRequest(data))
	h.provider.lostReply = true
	if _, e := h.s.Ingest(h.ctx, h.actor, a.ID, "lost", bytes.NewReader(data)); !errors.Is(e, storage.ErrUnknown) {
		t.Fatal(e)
	}
	h.provider.lostReply = false
	h.clock.Add(6 * time.Second)
	drainContent(t, h)
	h.ingest(t, b.ID, data)
	if h.provider.writes != 1 {
		t.Fatal("lost response duplicated content")
	}
	var object string
	if e := h.db.QueryRow(`SELECT data->>'object_id' FROM storage.content_groups WHERE active`).Scan(&object); e != nil {
		t.Fatal(e)
	}
	st, e := h.s.Status(h.ctx, h.actor, object)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = h.s.Delete(h.ctx, h.actor, object, "bypass", st.Revision); !errors.Is(e, storage.ErrDenied) {
		t.Fatal("canonical deletion bypass", e)
	}
	if _, e = h.s.ChangeProtection(h.ctx, h.actor, object, "bypass-protection", st.Revision, storage.Protection{Class: "quarantine", Scope: "school-a"}); !errors.Is(e, storage.ErrDenied) {
		t.Fatal("canonical protection bypass", e)
	}
	h.clock.Add(24 * time.Hour)
	h.reconcile(t)
	drainContent(t, h)
	h.reconcile(t)
	for _, id := range []string{a.ID, b.ID} {
		st, e = h.s.Status(h.ctx, h.actor, id)
		if e != nil || st.State != "deleted" {
			t.Fatalf("expired shared handle %+v %v", st, e)
		}
	}
}

func TestConcurrentSharedIngestKeepsOneProviderIntent(t *testing.T) {
	h := harnessFor(t)
	h.instance(t, "one", "one", 4096)
	data := []byte("overlapping provider uploads")
	a := sharedCreate(t, h, "first", sharedRequest(data))
	b := sharedCreate(t, h, "second", sharedRequest(data))
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	h.provider.afterWrite = func() { once.Do(func() { close(entered); <-release }) }
	first := make(chan error, 1)
	go func() { _, e := h.s.Ingest(h.ctx, h.actor, a.ID, "first-body", bytes.NewReader(data)); first <- e }()
	<-entered
	second := make(chan error, 1)
	go func() { _, e := h.s.Ingest(h.ctx, h.actor, b.ID, "second-body", bytes.NewReader(data)); second <- e }()
	select {
	case e := <-second:
		if !errors.Is(e, storage.ErrConflict) {
			close(release)
			<-first
			t.Fatalf("overlapping write result %v", e)
		}
	case <-time.After(2 * time.Second):
		close(release)
		<-first
		<-second
		t.Fatal("concurrent upload did not reject the occupied intent")
	}
	close(release)
	if e := <-first; e != nil {
		t.Fatal(e)
	}
	h.provider.afterWrite = nil
	h.ingest(t, b.ID, data)
	if h.provider.writes != 1 || physicalCount(t, h) != 1 {
		t.Fatal("concurrent requests duplicated provider content")
	}
}

func TestDeleteDuringSharedProtectionCopyCleansDestinationAndKeepsOtherHandle(t *testing.T) {
	h := harnessFor(t)
	i := h.instance(t, "one", storage.ContributionOwnerDomain(h.actor), 4096)
	if _, e := storagetest.Trust(h.ctx, h.s, h.actor, i, "school-a", []string{"quarantine"}); e != nil {
		t.Fatal(e)
	}
	data := []byte("cancel protection copy")
	a := sharedCreate(t, h, "a", sharedRequest(data))
	h.ingest(t, a.ID, data)
	req := sharedRequest(data)
	req.ReuseFrom = a.ID
	b := sharedCreate(t, h, "b", req)
	var deleted storage.Status
	var deleteErr error
	h.provider.afterWrite = func() { deleted, deleteErr = h.s.Delete(h.ctx, h.actor, a.ID, "cancel-copy", a.Revision) }
	_, err := h.s.ChangeProtection(h.ctx, h.actor, a.ID, "protect", a.Revision, storage.Protection{Class: "quarantine", Scope: "school-a"})
	h.provider.afterWrite = nil
	if err == nil || deleteErr != nil || deleted.State != "deleting" {
		t.Fatalf("copy/delete result %v %v %+v", err, deleteErr, deleted)
	}
	drainContent(t, h)
	state, e := h.s.Status(h.ctx, h.actor, a.ID)
	if e != nil || state.State != "deleted" {
		t.Fatal(state, e)
	}
	var out bytes.Buffer
	if e = h.s.ReviewDownload(h.ctx, h.actor, b.ID, &out); e != nil || !bytes.Equal(data, out.Bytes()) {
		t.Fatal("cancel removed another handle", e)
	}
	remaining := 0
	for _, files := range h.provider.files {
		remaining += len(files)
	}
	if remaining != 1 {
		t.Fatal("cancelled destination retained bytes", remaining)
	}
}

type scopedActionAuth struct {
	mu      sync.Mutex
	allowed map[string]map[string]bool
}

func (a *scopedActionAuth) Authorize(_ context.Context, p storage.Principal, action, _ string, _ storage.Protection) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.allowed[p.Subject]["*"] || a.allowed[p.Subject][action] {
		return nil
	}
	return storage.ErrDenied
}

func TestSharedContentProtectionChangeLeastPrivilegeAndRollback(t *testing.T) {
	base := harnessFor(t)
	auth := &scopedActionAuth{
		allowed: map[string]map[string]bool{
			"service": {"*": true},
		},
	}
	svc, err := storage.New(base.repo, auth, base.provider, base.provider, storage.Config{
		Clock:              base.clock.Now,
		MaxObjectSize:      1 << 20,
		TemporaryDirectory: t.TempDir(),
		ParallelTransfers:  4,
		Lease:              time.Minute,
		VerificationAge:    time.Hour,
		MaxAttempts:        3,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close(base.ctx) })

	actor := storage.Principal{Issuer: "test-issuer", Subject: "service"}
	until := base.clock.Now().Add(24 * time.Hour)
	inst, err := storagetest.RegisterContribution(base.ctx, svc, actor, "reg-pub", storage.Instance{
		ID:                 "pub-only",
		Adapter:            "test",
		OwnerDomain:        storage.ContributionOwnerDomain(base.actor),
		Ownership:          "contributor",
		CredentialRef:      "pub-only",
		CredentialRevision: 1,
		Root:               "isolated",
		State:              "active",
		Authorized:         true,
		Limit:              4096,
		ExpiresAt:          until,
		Admissions:         []storage.Admission{{Class: "public", Scope: "school-a", Plaintext: true, ExpiresAt: until}},
	})
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("protection rollback and least privilege")
	req := sharedRequest(data)
	created, err := svc.Create(base.ctx, actor, "create-h", req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Ingest(base.ctx, actor, created.ID, "ingest-h", bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}

	// Restrict actor to ONLY protection.change + protection.assign + objects.review.
	auth.mu.Lock()
	auth.allowed["service"] = map[string]bool{
		"storage.protection.change": true,
		"storage.protection.assign": true,
		"storage.objects.review":    true,
	}
	auth.mu.Unlock()

	// 1. No quarantine capacity yet -> ChangeProtection fails with ErrCapacity, leaving PendingGroup.
	quarantine := storage.Protection{Class: "quarantine", Scope: "school-a"}
	if _, err = svc.ChangeProtection(base.ctx, actor, created.ID, "to-quarantine-no-cap", created.Revision, quarantine); !errors.Is(err, storage.ErrCapacity) {
		t.Fatalf("expected ErrCapacity when destination has no instance, got %v", err)
	}
	// ReviewDownload must still read verified source while pending migration is stuck!
	var reviewed bytes.Buffer
	if err = svc.ReviewDownload(base.ctx, actor, created.ID, &reviewed); err != nil || !bytes.Equal(reviewed.Bytes(), data) {
		t.Fatalf("ReviewDownload blocked by failed PendingGroup: err=%v", err)
	}
	// Revert back to original protection must cancel PendingGroup and restore handle!
	reverted, err := svc.ChangeProtection(base.ctx, actor, created.ID, "cancel-quarantine", created.Revision, req.Protection)
	if err != nil || reverted.Protection != req.Protection || reverted.Revision != created.Revision+1 {
		t.Fatalf("reverting stuck protection change failed: %+v err=%v", reverted, err)
	}

	// Start a distinct migration while the destination still has no capacity.
	if _, err = svc.ChangeProtection(base.ctx, actor, created.ID, "to-quarantine-ok", reverted.Revision, quarantine); !errors.Is(err, storage.ErrCapacity) {
		t.Fatal(err)
	}
	replay, err := svc.ChangeProtection(base.ctx, actor, created.ID, "cancel-quarantine", created.Revision, req.Protection)
	if err != nil || replay.Revision != reverted.Revision {
		t.Fatalf("old cancellation resumed the subsequent migration: %+v %v", replay, err)
	}
	var pending string
	if err = base.db.QueryRow("SELECT pending_group_id FROM storage.content_handles WHERE id=$1", created.ID).Scan(&pending); err != nil || pending == "" {
		t.Fatalf("pending migration changed on replay: %v", err)
	}

	// 2. Admit quarantine on instance, then ChangeProtection with ONLY protection.change + protection.assign!
	if _, err := storagetest.Trust(base.ctx, base.s, base.actor, inst, "school-a", []string{"quarantine"}); err != nil {
		t.Fatal(err)
	}
	auth.mu.Lock()
	auth.allowed["service"] = map[string]bool{
		"storage.protection.change": true,
		"storage.protection.assign": true,
	}
	auth.mu.Unlock()

	migrated, err := svc.ChangeProtection(base.ctx, actor, created.ID, "to-quarantine-ok", reverted.Revision, quarantine)
	if err != nil || migrated.Protection != quarantine {
		t.Fatalf("ChangeProtection demanded extra object permissions: %+v err=%v", migrated, err)
	}
	again, err := svc.ChangeProtection(base.ctx, actor, created.ID, "to-quarantine-ok", reverted.Revision, quarantine)
	if err != nil || again != migrated {
		t.Fatalf("completed migration replay returned %+v instead of %+v: %v", again, migrated, err)
	}

}

func TestSharedContentCleanupUsesActualActorWithoutOwnerPermissions(t *testing.T) {
	base := harnessFor(t)
	auth := &scopedActionAuth{
		allowed: map[string]map[string]bool{
			"creator":    {"*": true},
			"maintainer": {"storage.maintenance": true},
		},
	}
	svc, err := storage.New(base.repo, auth, base.provider, base.provider, storage.Config{
		Clock:              base.clock.Now,
		MaxObjectSize:      1 << 20,
		TemporaryDirectory: t.TempDir(),
		ParallelTransfers:  4,
		Lease:              time.Minute,
		VerificationAge:    time.Hour,
		MaxAttempts:        3,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close(base.ctx) })

	creator := storage.Principal{Issuer: "test-issuer", Subject: "creator"}
	maintainer := storage.Principal{Issuer: "test-issuer", Subject: "maintainer"}
	until := base.clock.Now().Add(48 * time.Hour)
	if _, err = storagetest.RegisterContribution(base.ctx, svc, creator, "reg-1", storage.Instance{
		ID:                 "inst-1",
		Adapter:            "test",
		OwnerDomain:        "platform",
		Ownership:          "contributor",
		CredentialRef:      "inst-1",
		CredentialRevision: 1,
		Root:               "isolated",
		State:              "active",
		Authorized:         true,
		Limit:              4096,
		ExpiresAt:          until,
		Admissions:         []storage.Admission{{Class: "public", Scope: "school-a", Plaintext: true, ExpiresAt: until}},
	}); err != nil {
		t.Fatal(err)
	}

	data := []byte("expire after creator permissions revoked")
	h1, err := svc.Create(base.ctx, creator, "c1", sharedRequest(data))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Ingest(base.ctx, creator, h1.ID, "u1", bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}

	// Revoke all permissions of creator except status read; maintainer runs 24h expiry cleanup.
	auth.mu.Lock()
	auth.allowed["creator"] = map[string]bool{"storage.objects.read": true}
	auth.mu.Unlock()

	base.clock.Add(25 * time.Hour)
	if _, err = svc.Reconcile(base.ctx, maintainer, 100, ""); err != nil {
		t.Fatalf("maintenance cleanup failed when creator lost permissions: %v", err)
	}
	for range 10 {
		ok, err := svc.RunOne(base.ctx, "maint-worker")
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			break
		}
	}
	if _, err = svc.Reconcile(base.ctx, maintainer, 100, ""); err != nil {
		t.Fatal(err)
	}
	st, err := svc.Status(base.ctx, creator, h1.ID)
	if err != nil || st.State != "deleted" {
		t.Fatalf("shared handle not cleaned up: %+v err=%v", st, err)
	}
	var actorSubject string
	if err = base.db.QueryRow(`SELECT data->'actor'->>'subject' FROM storage.audit WHERE data->'event'->>'type'='storage.object.deleting.v1'`).Scan(&actorSubject); err != nil || actorSubject != "maintainer" {
		t.Fatalf("cleanup audit impersonated creator instead of maintainer: actor=%q err=%v", actorSubject, err)
	}
}
