package storage_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	storage "github.com/StuHelper/stuhelper-storage"
	"testing"
	"time"
)

func TestStableClientKeySurvivesReplayExpiryAndDeletion(t *testing.T) {
	h := harnessFor(t)
	sum := sha256.Sum256([]byte("stable"))
	req := storage.CreateRequest{ClientKey: "media:version", Size: 6, SHA256: hex.EncodeToString(sum[:]), Protection: storage.Protection{Class: "public", Scope: "school-a", Public: true}}
	a, err := h.s.Create(h.ctx, h.actor, "first", req)
	if err != nil {
		t.Fatal(err)
	}
	h.clock.Add(25 * time.Hour)
	b, err := h.s.Create(h.ctx, h.actor, "retry", req)
	if err != nil || a.ID != b.ID {
		t.Fatal("created a second object after request replay expiry", err)
	}
	req.Size++
	if _, err = h.s.Create(h.ctx, h.actor, "changed", req); !errors.Is(err, storage.ErrConflict) {
		t.Fatal(err)
	}
	req.Size--
	if _, err = h.s.Delete(h.ctx, h.actor, a.ID, "delete", a.Revision); err != nil {
		t.Fatal(err)
	}
	h.clock.Add(25 * time.Hour)
	b, err = h.s.Create(h.ctx, h.actor, "after-delete", req)
	if err != nil || b.ID != a.ID || b.State != "deleted" {
		t.Fatal("stable identity resurrected deleted content", err, b.State)
	}
}

func TestProtectionChangePreservesLastVerifiedSource(t *testing.T) {
	h := harnessFor(t)
	i := h.instance(t, "controlled", "platform", "platform", 1024)
	i.Admissions = []storage.Admission{{Class: "internal", Scope: "school-a", Plaintext: true, ExpiresAt: i.ExpiresAt}}
	var err error
	i, err = h.s.UpdateInstance(h.ctx, h.actor, "quarantine", i)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("preserve source")
	o := h.object(t, "create", data)
	o, err = h.s.ChangeProtection(h.ctx, h.actor, o.ID, "initial", o.Revision, storage.Protection{Class: "internal", Scope: "school-a"})
	if err != nil {
		t.Fatal(err)
	}
	h.ingest(t, o.ID, data)
	target := storage.Protection{Class: "public", Scope: "school-a", Public: true}
	if _, err := h.s.ChangeProtection(h.ctx, h.actor, o.ID, "unsafe", o.Revision, target); !errors.Is(err, storage.ErrUnavailable) {
		t.Fatal("last source was discarded", err)
	}
	st, err := h.s.Status(h.ctx, h.actor, o.ID)
	if err != nil || st.Revision != o.Revision || st.Healthy != 1 {
		t.Fatal("rejected migration changed object", err)
	}
	i.Admissions = append(i.Admissions, storage.Admission{Class: "public", Scope: "school-a", Plaintext: true, ExpiresAt: i.ExpiresAt})
	if _, err = h.s.UpdateInstance(h.ctx, h.actor, "admit", i); err != nil {
		t.Fatal(err)
	}
	st, err = h.s.ChangeProtection(h.ctx, h.actor, o.ID, "safe", o.Revision, target)
	if err != nil || st.Healthy != 1 || st.Protection != target {
		t.Fatal("eligible source not preserved", err, st)
	}
}
