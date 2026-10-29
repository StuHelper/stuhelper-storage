package storage_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	storage "github.com/StuHelper/stuhelper-storage"
	"github.com/StuHelper/stuhelper-storage/postgres"
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
		h.instance(t, fmt.Sprint(i), fmt.Sprint(i), "platform", 1024)
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
		h.instance(t, fmt.Sprint(i), fmt.Sprint(i), "platform", 1024)
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
	if _, e := h.s.Delete(h.ctx, h.actor, b.ID, "delete-b", b.Revision); e != nil {
		t.Fatal(e)
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
		v := h.instance(t, fmt.Sprint(i), fmt.Sprint(i), "platform", 4096)
		v.Admissions = append(v.Admissions, storage.Admission{Class: "quarantine", Scope: "school-a", Plaintext: true, ExpiresAt: v.ExpiresAt})
		if _, e := h.s.UpdateInstance(h.ctx, h.actor, "admit-"+v.ID, v); e != nil {
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
	h.instance(t, "one", "one", "platform", 4096)
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
	instance := h.instance(t, "one", "one", "platform", 4096)
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
