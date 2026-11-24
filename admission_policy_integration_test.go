package storage_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	storage "github.com/StuHelper/stuhelper-storage"
	"github.com/StuHelper/stuhelper-storage/storagetest"
)

func registerContributor(t *testing.T, h *harness, id string, owner storage.Principal, limit int64) storage.Instance {
	t.Helper()
	until := h.clock.Now().Add(24 * time.Hour)
	i, err := h.s.Register(h.ctx, h.actor, "register-"+id, storage.Instance{ID: id, Adapter: "test", OwnerDomain: storage.ContributionOwnerDomain(owner),
		Ownership: "contributor", CredentialRef: id, CredentialRevision: 1, Root: "isolated", State: "paused", Authorized: true,
		ExpiresAt: until, Admissions: []storage.Admission{{Class: "public", Scope: "school-a", Plaintext: true, ExpiresAt: until}}})
	if err != nil {
		t.Fatal(err)
	}
	sn, err := h.s.ApplyContribution(h.ctx, h.actor, i.ID, storage.ContributionControl{ID: "contribution-" + id, OwnerDomain: i.OwnerDomain,
		ExpectedRevision: i.Revision, Revision: 1, State: "active", Until: until, LimitBytes: limit})
	if err != nil {
		t.Fatal(err)
	}
	i.Revision, i.State, i.Limit, i.ContributionControl = sn.Revision, sn.State, limit, sn.Control
	return i
}

func TestContributionTrustRequiresOwnerConsentAndAdministration(t *testing.T) {
	h := harnessFor(t)
	i := registerContributor(t, h, "contributed", h.actor, 1024)
	if _, err := h.s.CommandInstance(h.ctx, h.actor, i.ID, "premature", storage.InstanceCommand{Revision: i.Revision, Action: "trust"}); !errors.Is(err, storage.ErrDenied) {
		t.Fatal(err)
	}
	input := storage.TrustConsentRequest{Revision: i.Revision, Scope: "school-a", Classes: []string{"quarantine", "restricted"}, Until: i.ExpiresAt}
	other := storage.Principal{Issuer: "different-issuer", Subject: h.actor.Subject}
	if _, err := h.s.SetOwnTrustConsent(h.ctx, other, i.ID, "wrong-owner", input); !errors.Is(err, storage.ErrDenied) {
		t.Fatal(err)
	}
	c, err := h.s.SetOwnTrustConsent(h.ctx, h.actor, i.ID, "consent", input)
	if err != nil || c.Trusted || c.Consent == nil {
		t.Fatal(c, err)
	}
	state, err := h.s.CommandInstance(h.ctx, h.actor, i.ID, "trust", storage.InstanceCommand{Revision: c.Revision, Action: "trust"})
	if err != nil || !state.Trusted {
		t.Fatal(state, err)
	}
	existing, err := h.s.Instances(h.ctx, h.actor, 100, "")
	if err != nil || len(existing) != 1 {
		t.Fatal(err)
	}
	inst := existing[0]
	if !inst.CanWrite(storage.Protection{Class: "quarantine", Scope: "school-a"}, 1, h.clock.Now()) ||
		inst.CanWrite(storage.Protection{Class: "restricted", Scope: "school-b"}, 1, h.clock.Now()) ||
		inst.CanWrite(storage.Protection{Class: "unknown", Scope: "school-a"}, 1, h.clock.Now()) {
		t.Fatal("invalid trust scope")
	}
	input.Classes = []string{}
	input.Revision = state.Revision
	got, err := h.s.SetOwnTrustConsent(h.ctx, h.actor, i.ID, "withdraw", input)
	if err != nil || got.Trusted || got.Consent != nil {
		t.Fatal(got, err)
	}
	var decisions int
	if err := h.db.QueryRow(`SELECT count(*) FROM storage.audit WHERE data ? 'trust_decision'`).Scan(&decisions); err != nil || decisions != 2 {
		t.Fatal(decisions, err)
	}
}

func TestAdmissionReservesThresholdAndPrefersContributions(t *testing.T) {
	for _, n := range []int{0, 1, 2, 3} {
		t.Run(string(rune('0'+n)), func(t *testing.T) {
			h := harnessFor(t)
			p := storage.Protection{Class: "public", Scope: "school-a", Public: true}
			body := []byte("scoped upload")
			digest := sha256.Sum256(body)
			q := storage.CreateRequest{ClientKey: "one", Deduplicate: true, Size: int64(len(body)), SHA256: hex.EncodeToString(digest[:]), Protection: p, ReserveFor: &p}
			if _, err := h.s.Create(h.ctx, h.actor, "empty", q); !errors.Is(err, storage.ErrCapacity) {
				t.Fatal(err)
			}
			var objects int
			if err := h.db.QueryRow("SELECT count(*) FROM storage.objects").Scan(&objects); err != nil || objects != 0 {
				t.Fatal(objects, err)
			}
			for j := 0; j < n; j++ {
				registerContributor(t, h, string(rune('a'+j)), h.actor, int64(len(body)))
			}
			cfg := storage.FallbackConfig{ID: "fallback", AccountDomain: "cos:fixture", Root: "replicas", Scopes: []string{"school-a"}, AlertPercent: 80, Limit: int64(len(body))}
			if err := h.s.ConfigureFallback(h.ctx, h.actor, cfg); err != nil {
				t.Fatal(err)
			}
			state, err := h.s.Create(h.ctx, h.actor, "create", q)
			if err != nil {
				t.Fatal(err)
			}
			inst, err := h.s.Instances(h.ctx, h.actor, 100, "")
			if err != nil {
				t.Fatal(err)
			}
			var held int64
			for _, i := range inst {
				held += i.Reserved
				if i.IsFallback() && (i.Reserved > 0) != (n < 2) {
					t.Fatal("unexpected fallback reservation", n, i.Reserved)
				}
			}
			if held != int64(len(body))*int64(min(n+1, 2)) {
				t.Fatal("incorrect reservation", held)
			}
			if _, err := h.s.Ingest(h.ctx, h.actor, state.ID, "ingest", bytes.NewReader(body)); err != nil {
				t.Fatal(err)
			}
			if n > 0 {
				h.run(t)
			}
			got, err := h.s.Status(h.ctx, h.actor, state.ID)
			if err != nil || !got.CanReference() || got.VerifiedCOSOnly != (n == 0) || got.Healthy != min(n+1, 2) {
				t.Fatal(got, err)
			}
			if _, err = h.s.Reference(h.ctx, h.actor, state.ID, "attach", storage.Reference{Module: "media", ID: "ok"}, true); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestContributionAdmissionNarrowingRepairsVerifiedReplicas(t *testing.T) {
	h := harnessFor(t)
	owner := storage.ContributionOwnerDomain(h.actor)
	for _, id := range []string{"a", "b", "c"} {
		i := registerContributor(t, h, id, h.actor, 1<<20)
		if _, err := storagetest.Trust(h.ctx, h.s, h.actor, i, "school-a", []string{"quarantine"}); err != nil {
			t.Fatal(err)
		}
	}
	data := []byte("quarantined example")
	sum := sha256.Sum256(data)
	object, err := h.s.Create(h.ctx, h.actor, "quarantine", storage.CreateRequest{
		Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:]), Protection: storage.Protection{Class: "quarantine", Scope: "school-a"},
		Policy: storage.Policy{Target: 2, Publish: 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	h.ingest(t, object.ID, data)
	h.reconcile(t)
	h.run(t)
	before, err := h.s.Status(h.ctx, h.actor, object.ID)
	if err != nil || before.Healthy != 2 || len(h.provider.files["a"]) != 1 || len(h.provider.files["b"]) != 1 {
		t.Fatalf("expected two verified contribution replicas: %+v %v", before, err)
	}
	policy := storage.ContributionAdmissionPolicy{
		Rules:       []storage.ContributionAdmissionRule{{SubjectKind: "contributor", SubjectID: owner, InstanceID: "a", Levels: []string{"public"}}},
		Memberships: []storage.ContributionAdmissionMembership{},
	}
	for attempt := 0; attempt < 2; attempt++ {
		applied, err := h.s.ReplaceContributionAdmissionPolicy(h.ctx, h.actor, "narrow", policy)
		if err != nil || applied.Revision != 1 {
			t.Fatal(applied, err)
		}
	}
	after, err := h.s.Status(h.ctx, h.actor, object.ID)
	if err != nil || after.Healthy != 1 || after.CanReference() {
		t.Fatalf("withdrawn contribution still counted: %+v %v", after, err)
	}
	h.reconcile(t)
	h.run(t)
	h.reconcile(t)
	h.run(t)
	repaired, err := h.s.Status(h.ctx, h.actor, object.ID)
	if err != nil || repaired.Healthy != 2 || len(h.provider.files["a"]) != 0 || len(h.provider.files["b"]) != 1 || len(h.provider.files["c"]) != 1 {
		t.Fatalf("replacement or cleanup failed: %+v %v", repaired, err)
	}
	var audits int
	if err := h.db.QueryRow(`SELECT count(*) FROM storage.audit WHERE audit_action='storage.contribution_admission.updated.v1'`).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("expected one policy audit after retry, got %d: %v", audits, err)
	}
}
