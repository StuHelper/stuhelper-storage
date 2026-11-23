package storage_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	storage "github.com/StuHelper/stuhelper-storage"
	"github.com/StuHelper/stuhelper-storage/httpapi"
	"github.com/StuHelper/stuhelper-storage/sdk"
)

func TestProviderQuotaRefreshFailureExpiryAndRecovery(t *testing.T) {
	h := harnessFor(t)
	owner := storage.Principal{Issuer: "test", Subject: "owner"}
	h.provider.verificationClock = h.clock.Now
	h.provider.quota = &storage.ProviderQuotaSample{TotalBytes: 200, UsedBytes: 30}
	until := h.clock.Now().Add(time.Hour)
	i, err := h.s.Register(h.ctx, h.actor, "quota-register", storage.Instance{
		ID: "disk", Adapter: "test", OwnerDomain: storage.ContributionOwnerDomain(owner),
		Ownership: "contributor", CredentialRef: "disk", CredentialRevision: 1, Root: "isolated",
		State: "paused", Authorized: true, SafetyMargin: 5, ExpiresAt: until,
		Admissions: []storage.Admission{{Class: "public", Scope: "school-a", Plaintext: true, ExpiresAt: until}},
	})
	if err != nil {
		t.Fatal(err)
	}
	capacity := func(p storage.Principal) storage.OwnerCapacity {
		t.Helper()
		out, err := h.s.InspectOwnerCapacities(h.ctx, h.actor, p, []string{"disk", "missing"})
		if err != nil {
			t.Fatal(err)
		}
		return out["disk"]
	}
	readAt := h.clock.Now()
	first := capacity(owner)
	q := first.ProviderCapacity
	if q.Status != storage.CapacityAvailable || q.TotalBytes == nil || *q.TotalBytes != 200 ||
		q.UsedBytes == nil || *q.UsedBytes != 30 || q.RemainingBytes == nil || *q.RemainingBytes != 170 ||
		q.ObservedAt == nil || !q.ObservedAt.Equal(readAt) || first.SafetyMarginBytes != 5 ||
		first.MaxContributableBytes == nil || *first.MaxContributableBytes != 165 {
		t.Fatal("provider reading or zero-reserve limit was not projected")
	}
	if capacity(storage.Principal{Issuer: "other", Subject: owner.Subject}).ProviderCapacity.Status != "" {
		t.Fatal("a different identity issuer received the owner's quota")
	}
	control := storage.ContributionControl{
		ID: "grant", OwnerDomain: i.OwnerDomain, Revision: 1, ExpectedRevision: i.Revision,
		State: "active", LimitBytes: 156, PersonalReserve: 10, Until: until,
	}
	if _, err := h.s.ApplyContribution(h.ctx, h.actor, i.ID, control); !errors.Is(err, storage.ErrContributionLimitExceeded) {
		t.Fatal("locked limit check did not reject one byte over the limit", err)
	}
	control.LimitBytes = 155
	bound, err := h.s.ApplyContribution(h.ctx, h.actor, i.ID, control)
	if err != nil || bound.AvailableBytes != 155 {
		t.Fatal("an exact-limit request was rejected", err)
	}

	h.clock.Add(time.Minute)
	h.provider.verifyErr = storage.ErrUnavailable
	if err := h.s.RefreshInstance(h.ctx, h.actor, i.ID); !errors.Is(err, storage.ErrUnavailable) {
		t.Fatal("quota refresh did not report the provider failure", err)
	}
	failed := capacity(owner)
	q = failed.ProviderCapacity
	if q.Recovery != storage.RecoveryWaitingScan {
		t.Fatal("failed sample without a scheduled retry", q.Recovery)
	}
	h.s.SetQuotaRetry(i.ID, i.CredentialRevision, true)
	if capacity(owner).ProviderCapacity.Recovery != storage.RecoveryWaitingRetry {
		t.Fatal("scheduled retry missing")
	}
	h.provider.credentialsRequired.Store(true)
	if capacity(owner).ProviderCapacity.Recovery != storage.RecoveryCredentialsRequired {
		t.Fatal("exhausted budget offered retry")
	}
	h.provider.credentialsRequired.Store(false)
	h.s.SetQuotaRetry(i.ID, i.CredentialRevision, false)
	if q.Status != storage.CapacityReadFailed || q.TotalBytes != nil || q.UsedBytes != nil ||
		q.RemainingBytes != nil || q.ObservedAt == nil || !q.ObservedAt.Equal(readAt) || failed.MaxContributableBytes != nil {
		t.Fatal("failed read did not preserve the last-success time and hide unknown capacity")
	}
	snapshot, err := h.s.InspectContribution(h.ctx, h.actor, i.ID, i.OwnerDomain)
	if err != nil || snapshot.CapacityStatus != storage.CapacityReadFailed || snapshot.AvailableBytes != 155 ||
		snapshot.ObservedAt == nil || !snapshot.ObservedAt.Equal(readAt) || !snapshot.SnapshotAt.Equal(h.clock.Now()) ||
		!snapshot.QuotaExpiresAt.Equal(i.QuotaExpiresAt) {
		t.Fatal("failed read extended freshness or changed valid placement capacity", err)
	}
	summary, err := h.s.SummarizeContributions(h.ctx, h.actor)
	if err != nil || summary.ActiveInstances != 1 || summary.AvailableBytes != 155 {
		t.Fatal("community summary dropped valid placement capacity after a failed attempt", err)
	}
	control.ExpectedRevision = bound.Revision
	control.Revision++
	control.LimitBytes++
	if _, err := h.s.ApplyContribution(h.ctx, h.actor, i.ID, control); !errors.Is(err, storage.ErrContributionCapacityUnavailable) {
		t.Fatal("changed declaration accepted when current provider capacity is unavailable", err)
	}
	control.LimitBytes = 154
	if _, err := h.s.ApplyContribution(h.ctx, h.actor, i.ID, control); err != nil {
		t.Fatal("safe reduction of an existing contribution was rejected", err)
	}

	h.clock.Add(4 * time.Minute)
	snapshot, err = h.s.InspectContribution(h.ctx, h.actor, i.ID, i.OwnerDomain)
	if err != nil || snapshot.AvailableBytes != 0 || snapshot.CapacityStatus != storage.CapacityReadFailed {
		t.Fatal("expired failed reading supplied capacity", err)
	}
	data := []byte("fixture")
	o := h.object(t, "quota-object", data)
	if _, err := h.s.Ingest(h.ctx, h.actor, o.ID, "upload-expired", bytes.NewReader(data)); !errors.Is(err, storage.ErrCapacity) {
		t.Fatal("writes did not stop at the original expiry", err)
	}
	h.provider.verifyErr = nil
	h.provider.quota = &storage.ProviderQuotaSample{TotalBytes: 220, UsedBytes: 60}
	if err := h.s.RefreshInstance(h.ctx, h.actor, i.ID); err != nil {
		t.Fatal(err)
	}
	snapshot, err = h.s.InspectContribution(h.ctx, h.actor, i.ID, i.OwnerDomain)
	if err != nil || snapshot.CapacityStatus != storage.CapacityAvailable || snapshot.AvailableBytes != 145 ||
		snapshot.ObservedAt == nil || !snapshot.ObservedAt.Equal(h.clock.Now()) {
		t.Fatal("capacity was not recalculated after recovery", err)
	}
	h.ingest(t, o.ID, data)
	q = capacity(owner).ProviderCapacity
	if q.RemainingBytes == nil || *q.RemainingBytes != 160 {
		t.Fatal("placement ledger modified the raw provider observation")
	}
	h.clock.Add(5 * time.Minute)
	q = capacity(owner).ProviderCapacity
	if q.Status != storage.CapacityExpired || q.TotalBytes != nil || q.ObservedAt == nil || q.ObservedAt.Equal(h.clock.Now()) {
		t.Fatal("last reading expiry or success timestamp was lost")
	}
}

func TestLegacyQuotaProjectionAndPrivateStorageHTTP(t *testing.T) {
	h := harnessFor(t)
	owner := storage.Principal{Issuer: "test", Subject: "owner"}
	h.provider.verificationClock = h.clock.Now
	handler, err := httpapi.New(h.s, testAuthentication{}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	call := func(method, path, key string, body []byte) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer synthetic-test-token")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", key)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w
	}
	const path = "/api/v1/storage/instances"
	i := sdk.InstanceInput{Id: "disk", Adapter: "test", OwnerDomain: storage.ContributionOwnerDomain(owner),
		Ownership: "contributor", CredentialRef: "disk", CredentialRevision: 1, Root: "isolated",
		State: "paused", Authorized: true, ExpiresAt: h.clock.Now().Add(time.Hour)}
	body, err := json.Marshal(i)
	if err != nil {
		t.Fatal(err)
	}
	assertPrivate := func(result *httptest.ResponseRecorder) {
		t.Helper()
		if result.Code != http.StatusOK {
			t.Fatalf("unexpected storage status %d", result.Code)
		}
		for _, key := range []string{"quota_observation", "provider_free", "total_bytes", "remaining_bytes", "provider_capacity"} {
			if strings.Contains(result.Body.String(), key) {
				t.Fatalf("private field leaked through storage HTTP: %s", key)
			}
		}
	}
	assertPrivate(call(http.MethodPost, path, "register", body))
	assertPrivate(call(http.MethodPost, path, "register", body))
	i.Revision = 1
	i.AccountDomain = "account:disk"
	body, err = json.Marshal(i)
	if err != nil {
		t.Fatal(err)
	}
	assertPrivate(call(http.MethodPut, path+"/disk", "update", body))
	assertPrivate(call(http.MethodGet, path, "", nil))
	h.instance(t, "platform", "platform", "platform", 1024)
	var results struct {
		Items []map[string]json.RawMessage `json:"items"`
	}
	r := call(http.MethodGet, path, "", nil)
	if r.Code != http.StatusOK || json.Unmarshal(r.Body.Bytes(), &results) != nil || len(results.Items) != 2 ||
		results.Items[0]["provider_free"] != nil || results.Items[1]["provider_free"] == nil {
		t.Fatal("instance listing did not preserve the platform-only placement field")
	}

	if _, err := h.db.Exec(`UPDATE storage.instances SET data=data-'quota_observation' WHERE id='disk'`); err != nil {
		t.Fatal(err)
	}
	snapshot, err := h.s.InspectContribution(h.ctx, h.actor, i.Id, i.OwnerDomain)
	if err != nil || snapshot.CapacityStatus != storage.CapacityNotRead || snapshot.ObservedAt != nil {
		t.Fatal("legacy ledger row fabricated a reading", err)
	}
	capacities, err := h.s.InspectOwnerCapacities(h.ctx, h.actor, owner, []string{"disk", "platform"})
	if err != nil || len(capacities) != 1 || capacities["disk"].ProviderCapacity.Status != storage.CapacityNotRead {
		t.Fatal("legacy or non-contributor capacity was projected as available", err)
	}
	if err := h.s.RefreshInstance(h.ctx, h.actor, i.Id); err != nil {
		t.Fatal(err)
	}
	snapshot, err = h.s.InspectContribution(h.ctx, h.actor, i.Id, i.OwnerDomain)
	if err != nil || snapshot.ObservedAt == nil || snapshot.CapacityStatus != storage.CapacityAvailable {
		t.Fatal("legacy ledger row did not recover on refresh", err)
	}
}
