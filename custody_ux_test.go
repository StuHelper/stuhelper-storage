package storage_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	storage "github.com/StuHelper/stuhelper-storage"
	protocol "github.com/StuHelper/stuhelper-storage-bhpan"
	"github.com/StuHelper/stuhelper-storage/custody"
	"github.com/StuHelper/stuhelper-storage/drivers/bhpan"
	"github.com/StuHelper/stuhelper-storage/httpapi"
	"github.com/StuHelper/stuhelper-storage/postgres"
)

type challengeCustodyProvider struct {
	*custodyProvider
	challenge bool
}

func (p *challengeCustodyProvider) Prepare(ctx context.Context, id string, until time.Time, raw json.RawMessage, current *storage.Instance, claim func(string) error) (storage.Instance, error) {
	if p.challenge {
		return storage.Instance{}, protocol.ErrChallenge
	}
	return p.custodyProvider.Prepare(ctx, id, until, raw, current, claim)
}

type challengeBHClient struct {
	bhpan.Client
}

func (challengeBHClient) Identity(context.Context) (protocol.Identity, error) {
	return protocol.Identity{}, protocol.ErrChallenge
}

func TestCustodyChallengeCooldownCleanupAndCandidateReasons(t *testing.T) {
	h := harnessFor(t)
	h.clock.now = h.clock.now.Truncate(time.Second).Add(999_999_900 * time.Nanosecond)
	h.provider.verificationClock = h.clock.Now
	baseProvider := &custodyProvider{h: h}
	prov := &challengeCustodyProvider{custodyProvider: baseProvider, challenge: true}
	auth := &custodyAuth{}
	svc, err := custody.New(&postgres.CustodyRepository{Repository: h.repo}, auth, h.s, prov, custody.Config{
		Actor:        h.actor,
		Policy:       custody.Policy{Version: "custody-v1", Digest: strings.Repeat("a", 64), URL: "https://example.invalid/custody", MaxTermSeconds: 86400 * 30},
		PublicScopes: []string{"school-a"},
		Clock:        h.clock.Now,
		Timeout:      time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	user := storage.Principal{Issuer: "test-issuer", Subject: "user"}
	foreign := storage.Principal{Issuer: "test-issuer", Subject: "foreign"}
	reqBody := custody.Request{
		Adapter:    "bhpan",
		Credential: json.RawMessage(`{"mode":"sso","username":"student","password":"test-only-value"}`),
		Until:      h.clock.Now().Add(24 * time.Hour),
		Consent:    custody.Consent{Accepted: true, Version: "custody-v1", Digest: strings.Repeat("a", 64)},
	}

	// 1. Verify BHpan Pool maps protocol.ErrChallenge to storage.ErrChallenge.
	pool := bhpan.NewPool()
	t.Cleanup(pool.Close)
	if _, err := pool.Provision(h.ctx, "challenge-ref", 1, challengeBHClient{}, time.Now().Add(time.Minute)); !errors.Is(err, storage.ErrChallenge) {
		t.Fatalf("expected storage.ErrChallenge from Pool.Provision, got %v", err)
	}

	// 2. Verify interactive verification challenge maps to dedicated last_error and credentials_required.
	key1 := "50000000-0000-4000-8000-000000000001"
	view, err := svc.Submit(h.ctx, user, "", key1, reqBody)
	if err != nil {
		t.Fatal(err)
	}
	if view.State != "credentials_required" || view.LastError != "interactive_verification_required" {
		t.Fatalf("expected interactive_verification_required, got %+v", view)
	}

	// 3. Foreign user cannot delete; owner can clean up failed unprovisioned binding idempotently.
	delKey := "50000000-0000-4000-8000-000000000011"
	if _, err := svc.Delete(h.ctx, foreign, view.ID, delKey); !errors.Is(err, storage.ErrDenied) {
		t.Fatalf("foreign delete should fail with ErrDenied, got %v", err)
	}
	handler, err := httpapi.NewCustody(svc, custodyAuthentication{user})
	if err != nil {
		t.Fatal(err)
	}
	doCustody := func(method, path, idemKey string, payload any) *httptest.ResponseRecorder {
		t.Helper()
		var body []byte
		if payload != nil {
			body, _ = json.Marshal(payload)
		}
		r := httptest.NewRequest(method, path, bytes.NewReader(body))
		if payload != nil {
			r.Header.Set("Content-Type", "application/json")
		}
		if idemKey != "" {
			r.Header.Set("Idempotency-Key", idemKey)
		}
		r.Header.Set("Authorization", "Bearer fixture")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}

	delResp := doCustody("DELETE", "/api/v1/storage/custody/"+view.ID, delKey, nil)
	if delResp.Code != http.StatusOK {
		t.Fatalf("owner delete failed: status=%d body=%s", delResp.Code, delResp.Body.String())
	}
	replayResp := doCustody("DELETE", "/api/v1/storage/custody/"+view.ID, delKey, nil)
	if replayResp.Code != http.StatusOK || replayResp.Body.String() != delResp.Body.String() {
		t.Fatalf("idempotent delete replay mismatch: status=%d", replayResp.Code)
	}
	conflictResp := doCustody("DELETE", "/api/v1/storage/custody/50000000-0000-4000-8000-000000000099", delKey, nil)
	if conflictResp.Code != http.StatusConflict {
		t.Fatalf("reusing delete key for another binding should return 409, got %d", conflictResp.Code)
	}
	listPage, err := svc.List(h.ctx, user, 20, "", false)
	if err != nil || len(listPage.Items) != 0 {
		t.Fatalf("deleted binding remained in list: %+v %v", listPage, err)
	}

	// 4. Verify 5-minute login budget is NOT bypassed by deleting failed bindings, and returns Retry-After + retry_after_seconds.
	h.clock.Add(2 * time.Minute)
	for n := 2; n <= 5; n++ {
		k := fmt.Sprintf("50000000-0000-4000-8000-%012d", n)
		v, err := svc.Submit(h.ctx, user, "", k, reqBody)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = svc.Delete(h.ctx, user, v.ID, fmt.Sprintf("50000000-0000-4000-8000-1%011d", n)); err != nil {
			t.Fatal(err)
		}
	}
	// 6th attempt within 5 minutes (earliest attempt was 2 minutes ago -> ~180s cooldown remaining).
	limitedKey := "50000000-0000-4000-8000-000000000006"
	limitedResp := doCustody("POST", "/api/v1/storage/custody", limitedKey, reqBody)
	if limitedResp.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 on login budget exhaustion, got %d: %s", limitedResp.Code, limitedResp.Body.String())
	}
	retryHeader, err := strconv.Atoi(limitedResp.Header().Get("Retry-After"))
	if err != nil || retryHeader != 180 {
		t.Fatalf("expected Retry-After=180, got %q", limitedResp.Header().Get("Retry-After"))
	}
	var problem struct {
		Code              string `json:"code"`
		RetryAfterSeconds int    `json:"retry_after_seconds"`
	}
	if err := json.Unmarshal(limitedResp.Body.Bytes(), &problem); err != nil || problem.Code != "storage_capacity_unavailable" || problem.RetryAfterSeconds != 180 {
		t.Fatalf("unexpected rate-limit problem payload: %+v err=%v", problem, err)
	}

	// 5. Provisioned custody binding cannot be deleted while active/paused or holding replicas, but can be deleted once revoked and empty.
	h.clock.Add(4 * time.Minute)
	prov.challenge = false
	baseProvider.account = "account:reusable-student"
	readyKey := "50000000-0000-4000-8000-000000000020"
	readyView, err := svc.Submit(h.ctx, user, "", readyKey, reqBody)
	if err != nil || readyView.State != "ready" {
		t.Fatalf("expected ready binding, got %+v %v", readyView, err)
	}
	if _, err := svc.Delete(h.ctx, user, readyView.ID, "50000000-0000-4000-8000-000000000021"); !errors.Is(err, storage.ErrConflict) {
		t.Fatalf("paused live instance must not be deleted before revocation, got %v", err)
	}

	// The candidate's capacity reason follows its current quota observation.
	ownerDomain := custody.OwnerDomain(user)
	cands, err := h.s.ListContributionCandidates(h.ctx, h.actor, ownerDomain, 10, "")
	if err != nil || len(cands.Items) != 1 || cands.Items[0].Reason != "" || cands.Items[0].AvailableBytes <= 0 || cands.Items[0].QuotaExpiresAt.IsZero() {
		t.Fatalf("unexpected fresh candidate: %+v err=%v", cands, err)
	}
	h.clock.Add(6 * time.Minute)
	expiredCands, err := h.s.ListContributionCandidates(h.ctx, h.actor, ownerDomain, 10, "")
	if err != nil || len(expiredCands.Items) != 1 || expiredCands.Items[0].Reason != "capacity_expired" || expiredCands.Items[0].AvailableBytes != 0 {
		t.Fatalf("expected capacity_expired for expired quota sample, got %+v err=%v", expiredCands, err)
	}
	instances, _ := h.s.Instances(h.ctx, h.actor, 100, "")
	inst := instances[0]
	inst.SafetyMargin = 1 << 30
	inst, err = h.s.UpdateInstance(h.ctx, h.actor, "margin-exhaust", inst)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.s.RefreshInstance(h.ctx, h.actor, inst.ID); err != nil {
		t.Fatal(err)
	}
	exhaustedCands, err := h.s.ListContributionCandidates(h.ctx, h.actor, ownerDomain, 10, "")
	if err != nil || len(exhaustedCands.Items) != 1 || exhaustedCands.Items[0].Reason != "capacity_exhausted" || exhaustedCands.Items[0].AvailableBytes != 0 {
		t.Fatalf("expected capacity_exhausted candidate, got %+v err=%v", exhaustedCands, err)
	}

	// Revoke instance, delete custody binding, and verify the same account can re-enroll.
	instances, _ = h.s.Instances(h.ctx, h.actor, 100, "")
	if _, err := h.s.CommandInstance(h.ctx, h.actor, readyView.ID, "op-revoke", storage.InstanceCommand{Revision: instances[0].Revision, Action: "revoke"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Delete(h.ctx, user, readyView.ID, "50000000-0000-4000-8000-000000000022"); err != nil {
		t.Fatalf("revoked empty custody binding delete failed: %v", err)
	}
	reenrollView, err := svc.Submit(h.ctx, user, "", "50000000-0000-4000-8000-000000000023", reqBody)
	if err != nil || reenrollView.State != "ready" {
		t.Fatalf("re-enrolling cleaned-up account failed: %+v %v", reenrollView, err)
	}
}

type custodyStoreAfterList struct {
	custody.Store
	after func()
}

func (s *custodyStoreAfterList) Instances(ctx context.Context, p storage.Principal, limit int, after string) ([]storage.Instance, error) {
	rows, err := s.Store.Instances(ctx, p, limit, after)
	if err == nil && s.after != nil {
		run := s.after
		s.after = nil
		run()
	}
	return rows, err
}
func TestCustodyDeleteRechecksProvisioningAndExpiresOrphanAttempts(t *testing.T) {
	h, provision, provider, auth, user, request := custodyFixture(t)
	provider.failPrepare.Store(true)
	k := "70000000-0000-4000-8000-000000000001"
	failed, err := provision.Submit(h.ctx, user, "", k, request)
	if err != nil || failed.State != "credentials_required" {
		t.Fatal(failed, err)
	}
	store := &custodyStoreAfterList{Store: h.s}
	remove, err := custody.New(&postgres.CustodyRepository{Repository: h.repo}, auth, store, provider, custody.Config{Actor: h.actor, Policy: provision.Policy(), Clock: h.clock.Now, PublicScopes: []string{"school-a"}, Timeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	store.after = func() {
		provider.failPrepare.Store(false)
		ready, e := provision.Resume(h.ctx, user, k, custody.ResumeRequest{RequestID: k, Revision: failed.Revision}, false)
		if e != nil || ready.State != "ready" {
			t.Fatal(ready, e)
		}
	}
	if _, err = remove.Delete(h.ctx, user, k, "70000000-0000-4000-8000-000000000002"); !errors.Is(err, storage.ErrConflict) {
		t.Errorf("concurrent provisioning: %v", err)
	}
	var count int
	if err = h.db.QueryRow("SELECT count(*) FROM storage.custody_bindings WHERE id=$1 AND data->>'state'='ready'", k).Scan(&count); err != nil || count != 1 {
		t.Errorf("ready binding count=%d err=%v", count, err)
	}
	orphan := "70000000-0000-4000-8000-000000000003"
	provider.failPrepare.Store(true)
	if _, err = provision.Submit(h.ctx, user, "", orphan, request); err != nil {
		t.Fatal(err)
	}
	if _, err = remove.Delete(h.ctx, user, orphan, "70000000-0000-4000-8000-000000000004"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []int{1, 0} {
		if _, err = h.s.PurgeExpired(h.ctx, h.actor, 1); err != nil {
			t.Fatal(err)
		}
		if err = h.db.QueryRow("SELECT count(*) FROM storage.custody_operations WHERE id=$1", orphan).Scan(&count); err != nil || count != want {
			t.Fatalf("orphan retention count=%d want=%d err=%v", count, want, err)
		}
		h.clock.Add(5*time.Minute + time.Second)
	}
}
