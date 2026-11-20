package storage_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	storage "github.com/StuHelper/stuhelper-storage"
)

func TestContributionAdmissionAdoptionPlacementAndNarrowing(t *testing.T) {
	h := harnessFor(t)
	owner := storage.Principal{Issuer: "synthetic-issuer", Subject: "contributor"}
	domain := storage.ContributionOwnerDomain(owner)
	until := h.clock.Now().Add(24 * time.Hour)
	admissions := []storage.Admission{
		{Class: "public", Scope: "school-a", Plaintext: true, ExpiresAt: until},
		{Class: "quarantine", Scope: "school-a", Plaintext: true, ExpiresAt: until},
		{Class: "restricted", Scope: "school-a", Plaintext: true, ExpiresAt: until},
		{Class: storage.PaidRestrictedClass, Scope: "school-a", Plaintext: true, ExpiresAt: until},
	}
	instances := map[string]storage.Instance{}
	for _, id := range []string{"a", "b", "c"} {
		var err error
		instances[id], err = h.s.Register(h.ctx, h.actor, "register-"+id, storage.Instance{
			ID: id, Adapter: "test", OwnerDomain: id, Ownership: "platform", CredentialRef: id, CredentialRevision: 1,
			Root: "isolated", State: "active", Authorized: true, Limit: 1 << 20, ExpiresAt: until, Admissions: admissions,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	pending := storage.Protection{Class: "quarantine", Scope: "school-a"}
	data := []byte("synthetic quarantine content")
	sum := sha256.Sum256(data)
	object, err := h.s.Create(h.ctx, h.actor, "new-pending", storage.CreateRequest{
		Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:]),
		Protection: pending, Policy: storage.Policy{Target: 2, Publish: 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	h.ingest(t, object.ID, data)
	h.reconcile(t)
	h.run(t)
	before := h.provider.writes
	levels := []string{"public", "quarantine", "restricted", storage.PaidRestrictedClass}
	policy := storage.ContributionAdmissionPolicy{
		Rules: []storage.ContributionAdmissionRule{
			{SubjectKind: "contributor", SubjectID: domain, InstanceID: "a", Levels: levels},
			{SubjectKind: "contributor", SubjectID: domain, InstanceID: "b", Levels: levels},
		},
		Memberships: []storage.ContributionAdmissionMembership{},
	}
	if _, err = h.s.ReplaceContributionAdmissionPolicy(h.ctx, owner, "unauthorized", policy); !errors.Is(err, storage.ErrDenied) {
		t.Fatalf("non-administrator updated policy: %v", err)
	}
	first, err := h.s.ReplaceContributionAdmissionPolicy(h.ctx, h.actor, "approve", policy)
	if err != nil || first.Revision != 1 {
		t.Fatal(first, err)
	}
	if _, err = h.s.ReplaceContributionAdmissionPolicy(h.ctx, h.actor, "stale", policy); !errors.Is(err, storage.ErrConflict) {
		t.Fatalf("stale revisions accepted: %v", err)
	}
	if retry, err := h.s.ReplaceContributionAdmissionPolicy(h.ctx, h.actor, "approve", policy); err != nil || retry.Revision != 1 {
		t.Fatal(retry, err)
	}
	for _, id := range []string{"a", "b"} {
		i := instances[id]
		in := storage.ContributionAdoption{Owner: owner, InstanceID: id, ApprovalReference: "approved-receipt", Control: storage.ContributionControl{
			ID: "approved-" + id, OwnerDomain: domain, Revision: 1, ExpectedRevision: i.Revision,
			State: "active", LimitBytes: i.Limit, Until: until,
		}}
		result, err := h.s.AdoptContribution(h.ctx, h.actor, "adopt-"+id, in)
		if err != nil || result.Control == nil || result.Control.OwnerDomain != domain || result.RemainingReplicas != 1 {
			t.Fatalf("adoption %s: %+v %v", id, result, err)
		}
	}
	status, err := h.s.Status(h.ctx, h.actor, object.ID)
	if err != nil || status.Healthy != 2 || before != h.provider.writes {
		t.Fatalf("same-owner accounts must preserve two verified copies: %+v %v", status, err)
	}
	summary, err := h.s.SummarizeContributions(h.ctx, h.actor)
	if err != nil || summary.ActiveInstances != 2 || summary.DeclaredBytes != 2<<20 {
		t.Fatalf("adopted contributions missing from aggregate: %+v %v", summary, err)
	}
	paid, err := h.s.Create(h.ctx, h.actor, "new-paid", storage.CreateRequest{
		Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:]), Protection: storage.Protection{Class: storage.PaidRestrictedClass, Scope: "school-a"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.s.Ingest(h.ctx, h.actor, paid.ID, "paid", bytes.NewReader(data)); !errors.Is(err, storage.ErrCapacity) {
		t.Fatalf("paid restricted data placed without protection: %v", err)
	}
	policy = first
	policy.Rules[0].Levels = []string{"public"}
	if _, err = h.s.ReplaceContributionAdmissionPolicy(h.ctx, h.actor, "narrow", policy); err != nil {
		t.Fatal(err)
	}
	status, err = h.s.Status(h.ctx, h.actor, object.ID)
	if err != nil || status.Healthy != 1 {
		t.Fatalf("withdrawn account remained eligible: %+v %v", status, err)
	}
	h.reconcile(t)
	h.run(t)
	h.reconcile(t)
	h.run(t)
	status, err = h.s.Status(h.ctx, h.actor, object.ID)
	if err != nil || status.Healthy != 2 || len(h.provider.files["a"]) != 0 || len(h.provider.files["c"]) != 1 {
		t.Fatalf("repair did not verify replacement before cleanup: %+v %v", status, err)
	}
	var audited int
	err = h.db.QueryRow(`SELECT count(*) FROM storage.audit WHERE audit_action='storage.contribution_admission.updated.v1'`).Scan(&audited)
	if err != nil || audited != 2 {
		t.Fatalf("expected two audit records, got %d: %v", audited, err)
	}
}
