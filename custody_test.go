package storage_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	storage "github.com/StuHelper/stuhelper-storage"
	"github.com/StuHelper/stuhelper-storage/custody"
	"github.com/StuHelper/stuhelper-storage/httpapi"
	"github.com/StuHelper/stuhelper-storage/postgres"
)

type custodyAuthentication struct{ principal storage.Principal }

func (a custodyAuthentication) Authenticate(r *http.Request) (storage.Principal, error) {
	if r.Header.Get("Authorization") != "Bearer fixture" {
		return storage.Principal{}, storage.ErrDenied
	}
	return a.principal, nil
}
func TestCustodyHTTPBoundaryAndSecretFreeResponses(t *testing.T) {
	h, s, _, a, user, q := custodyFixture(t)
	handler, e := httpapi.NewCustody(s, custodyAuthentication{user})
	if e != nil {
		t.Fatal(e)
	}
	key := "30000000-0000-4000-8000-000000000001"
	body, _ := json.Marshal(q)
	send := func(method, path, content, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(content))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", key)
		if token != "" {
			r.Header.Set("Authorization", token)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	base := "/api/v1/storage/custody"
	if w := send("GET", base+"/policy", "", ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := send("POST", base, string(body), ""); w.Code != 401 {
		t.Fatal(w.Code)
	}
	w := send("POST", base, string(body), "Bearer fixture")
	if w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, secret := range []string{"test-only-value", "username", "credential_ref", "root", "AccountDomain"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("HTTP exposed private custody data")
		}
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("response could be cached")
	}
	if w = send("GET", base+"/operations", "", "Bearer fixture"); w.Code != 403 {
		t.Fatal("owner gained operations access", w.Code)
	}
	a.denied.Store(true)
	if w = send("GET", base+"/requests/"+key, "", "Bearer fixture"); w.Code != 403 {
		t.Fatal(w.Code)
	}
	var count int
	if e = h.db.QueryRow(`SELECT count(*) FROM storage.instances`).Scan(&count); e != nil || count != 1 {
		t.Fatal(count, e)
	}
}

type custodyAuth struct{ denied atomic.Bool }

func (a *custodyAuth) Authorize(_ context.Context, p storage.Principal, action, _ string, _ storage.Protection) error {
	if a.denied.Load() || p.Subject == "foreign" && action != "storage.custody.read" || strings.Contains(action, "operations") && p.Subject != "admin" || !strings.Contains(action, "operations") && p.Subject == "admin" {
		return storage.ErrDenied
	}
	return nil
}

type custodyProvider struct {
	h                 *harness
	creates           atomic.Int32
	failCommit        atomic.Bool
	failPrepare       atomic.Bool
	failAfterClaim    atomic.Bool
	unknownAfterClaim atomic.Bool
	prepareInputs     atomic.Int32
	account           string
}

func (p *custodyProvider) Fingerprint(b []byte) (string, error) {
	m := hmac.New(sha256.New, []byte("fixture-private-mac"))
	m.Write(b)
	return hex.EncodeToString(m.Sum(nil)), nil
}
func (p *custodyProvider) ValidateInput(string, json.RawMessage) error { return nil }
func (p *custodyProvider) Prepare(ctx context.Context, id string, until time.Time, input json.RawMessage, current *storage.Instance, claim func(string) error) (storage.Instance, error) {
	if len(input) > 0 {
		p.prepareInputs.Add(1)
	}
	if p.failPrepare.Load() {
		return storage.Instance{}, storage.ErrDenied
	}
	if current != nil {
		i := *current
		i.CredentialRevision++
		i.ExpiresAt = until
		return i, nil
	}
	ref := "custody-" + id
	account := p.account
	if account == "" {
		account = "account:" + ref
	}
	if e := claim(account); e != nil {
		return storage.Instance{}, e
	}
	if p.unknownAfterClaim.Load() {
		return storage.Instance{}, storage.ErrUnknown
	}
	if p.failAfterClaim.Load() {
		return storage.Instance{}, storage.ErrUnavailable
	}
	p.h.provider.mu.Lock()
	p.h.provider.accounts[ref] = account
	p.h.provider.mu.Unlock()
	p.creates.Add(1)
	return storage.Instance{Adapter: "bhpan", CredentialRef: ref, CredentialRevision: 1, AccountDomain: account, Root: "dedicated-root", ExpiresAt: until}, nil
}
func (p *custodyProvider) Resume(ctx context.Context, id string, until time.Time, current *storage.Instance, claim func(string) error) (storage.Instance, error) {
	return p.Prepare(ctx, id, until, nil, current, claim)
}
func (p *custodyProvider) Commit(context.Context, storage.Instance) error {
	if p.failCommit.Load() {
		return storage.ErrUnavailable
	}
	return nil
}
func custodyFixture(t *testing.T) (*harness, *custody.Service, *custodyProvider, *custodyAuth, storage.Principal, custody.Request) {
	h := harnessFor(t)
	provider := &custodyProvider{h: h}
	auth := &custodyAuth{}
	s, e := custody.New(&postgres.CustodyRepository{Repository: h.repo}, auth, h.s, provider, custody.Config{Actor: h.actor, Policy: custody.Policy{Version: "custody-v1", Digest: strings.Repeat("a", 64), URL: "https://example.invalid/custody", MaxTermSeconds: 86400 * 30}, PublicScopes: []string{"school-a"}, Clock: h.clock.Now, Timeout: time.Minute})
	if e != nil {
		t.Fatal(e)
	}
	q := custody.Request{Adapter: "bhpan", Credential: json.RawMessage(`{"mode":"local","username":"fixture","password":"test-only-value"}`), Until: h.clock.Now().Add(24 * time.Hour), Consent: custody.Consent{Accepted: true, Version: "custody-v1", Digest: strings.Repeat("a", 64)}}
	return h, s, provider, auth, storage.Principal{Issuer: "test-issuer", Subject: "user"}, q
}
func TestCustodyConsentOwnershipIdempotencyAndIsolation(t *testing.T) {
	h, s, p, a, user, q := custodyFixture(t)
	key := "00000000-0000-4000-8000-000000000001"
	bad := q
	bad.Consent.Accepted = false
	if _, e := s.Submit(h.ctx, user, "", key, bad); !errors.Is(e, storage.ErrInput) {
		t.Fatal(e)
	}
	v, e := s.Submit(h.ctx, user, "", key, q)
	if e != nil || v.State != "ready" {
		t.Fatal(v, e)
	}
	rows, e := h.s.Instances(h.ctx, h.actor, 100, "")
	if e != nil || len(rows) != 1 || rows[0].State != "paused" || rows[0].Limit != 0 || rows[0].OwnerDomain != custody.OwnerDomain(user) {
		t.Fatal("enrollment started contribution", e)
	}
	var wg sync.WaitGroup
	for n := 0; n < 8; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			again, e := s.Submit(h.ctx, user, "", key, q)
			if e != nil || again != v {
				t.Error(again, e)
			}
		}()
	}
	wg.Wait()
	if p.creates.Load() != 1 {
		t.Fatal("duplicate remote roots")
	}
	bad = q
	bad.Credential = json.RawMessage(`{"password":"changed"}`)
	if _, e = s.Submit(h.ctx, user, "", key, bad); !errors.Is(e, storage.ErrConflict) {
		t.Fatal(e)
	}
	foreign := storage.Principal{Issuer: user.Issuer, Subject: "foreign"}
	if _, e = s.GetRequest(h.ctx, foreign, key); !errors.Is(e, storage.ErrDenied) {
		t.Fatal(e)
	}
	page, e := s.List(h.ctx, foreign, 20, "", false)
	if e != nil || len(page.Items) != 0 {
		t.Fatal(e, page)
	}
	if _, e = s.List(h.ctx, user, 20, "", true); !errors.Is(e, storage.ErrDenied) {
		t.Fatal(e)
	}
	page, e = s.List(h.ctx, storage.Principal{Issuer: user.Issuer, Subject: "admin"}, 20, "", true)
	if e != nil || len(page.Items) != 1 {
		t.Fatal(e)
	}
	serialized, _ := json.Marshal(page)
	for _, secret := range []string{"password", "username", "credential_ref", "dedicated-root", "account_domain"} {
		if strings.Contains(string(serialized), secret) {
			t.Fatal("private metadata leaked")
		}
	}
	var persisted string
	if e = h.db.QueryRow(`SELECT data::text FROM storage.custody_operations WHERE id=$1`, key).Scan(&persisted); e != nil || strings.Contains(persisted, "test-only-value") {
		t.Fatal("secret entered ledger", e)
	}
	if _, e = h.db.Exec(`SELECT * FROM other_module.private_data`); e == nil {
		t.Fatal("runtime crossed module boundary")
	}
	a.denied.Store(true)
	if _, e = s.GetRequest(h.ctx, user, key); !errors.Is(e, storage.ErrDenied) {
		t.Fatal(e)
	}
}
func TestCustodyRecoveryAndRenewalPreserveExistingInstance(t *testing.T) {
	h, s, p, _, user, q := custodyFixture(t)
	key := "00000000-0000-4000-8000-000000000002"
	p.failCommit.Store(true)
	v, e := s.Submit(h.ctx, user, "", key, q)
	if e != nil || v.State != "blocked" {
		t.Fatal(v, e)
	}
	p.failCommit.Store(false)
	v, e = s.Resume(h.ctx, user, v.ID, custody.ResumeRequest{RequestID: key, Revision: v.Revision}, false)
	if e != nil || v.State != "ready" || p.creates.Load() != 1 {
		t.Fatal("recovery repeated provision", v, e)
	}
	rows, _ := h.s.Instances(h.ctx, h.actor, 100, "")
	old := rows[0]
	c := storage.ContributionControl{ID: "contribution", OwnerDomain: old.OwnerDomain, Revision: 1, ExpectedRevision: old.Revision, State: "active", LimitBytes: 1024, PersonalReserve: 100, Until: q.Until}
	if _, e = h.s.ApplyContribution(h.ctx, h.actor, old.ID, c); e != nil {
		t.Fatal(e)
	}
	rows, _ = h.s.Instances(h.ctx, h.actor, 100, "")
	old = rows[0]
	q.Revision = v.Revision
	q.Until = q.Until.Add(time.Hour)
	p.failPrepare.Store(true)
	v, e = s.Submit(h.ctx, user, v.ID, "00000000-0000-4000-8000-000000000003", q)
	if e != nil || v.State != "credentials_required" {
		t.Fatal(v, e)
	}
	rows, _ = h.s.Instances(h.ctx, h.actor, 100, "")
	if !reflect.DeepEqual(old, rows[0]) {
		t.Fatal("failed renewal changed live instance")
	}
	p.failPrepare.Store(false)
	q.Revision = v.Revision
	v, e = s.Submit(h.ctx, user, v.ID, "00000000-0000-4000-8000-000000000004", q)
	if e != nil || v.State != "ready" {
		t.Fatal(v, e)
	}
	rows, _ = h.s.Instances(h.ctx, h.actor, 100, "")
	next := rows[0]
	if next.CredentialRevision != old.CredentialRevision+1 || !next.ExpiresAt.Equal(q.Until) {
		t.Fatal("credential not advanced")
	}
	next.CredentialRevision = old.CredentialRevision
	next.ExpiresAt = old.ExpiresAt
	next.Revision = old.Revision
	if next.QuotaRevision != old.QuotaRevision+1 || next.QuotaExpiresAt.Before(old.QuotaExpiresAt) {
		t.Fatalf("renewal did not record the new sample: quota revision %d -> %d", old.QuotaRevision, next.QuotaRevision)
	}
	next.QuotaRevision = old.QuotaRevision
	next.QuotaExpiresAt = old.QuotaExpiresAt
	if !reflect.DeepEqual(old, next) {
		t.Fatal("renewal modified contribution, admissions, root or quota")
	}
}
func TestCustodyDuplicateAccountsClaimsAndPagination(t *testing.T) {
	h, s, p, _, user, q := custodyFixture(t)
	p.account = "account:stable"
	for n := 1; n <= 2; n++ {
		key := fmt.Sprintf("10000000-0000-4000-8000-%012d", n)
		v, e := s.Submit(h.ctx, user, "", key, q)
		if e != nil || n == 1 && v.State != "ready" || n == 2 && v.LastError != "conflict" {
			t.Fatal(v, e)
		}
	}
	if p.creates.Load() != 1 {
		t.Fatal("duplicate account created root")
	}
	page, e := s.List(h.ctx, user, 1, "", false)
	if e != nil || len(page.Items) != 1 || page.NextCursor == "" {
		t.Fatal(page, e)
	}
	page, e = s.List(h.ctx, user, 1, page.NextCursor, false)
	if e != nil || len(page.Items) != 1 || page.NextCursor != "" {
		t.Fatal(page, e)
	}
}

func TestCustodyLoginBudgetSurvivesNewRequestKeysAndRestart(t *testing.T) {
	h, s, p, auth, user, q := custodyFixture(t)
	p.failPrepare.Store(true)
	var v custody.View
	for n := 1; n <= 5; n++ {
		target := ""
		if n > 1 {
			target = v.ID
			q.Revision = v.Revision
		}
		var e error
		v, e = s.Submit(h.ctx, user, target, fmt.Sprintf("40000000-0000-4000-8000-%012d", n), q)
		if e != nil || v.State != "credentials_required" {
			t.Fatal(v, e)
		}
	}
	// Reconstructing the service does not reset the persisted per-owner budget.
	next, e := custody.New(&postgres.CustodyRepository{Repository: h.repo}, auth, h.s, p, custody.Config{Actor: h.actor, Policy: s.Policy(), PublicScopes: []string{"school-a"}, Clock: h.clock.Now, Timeout: time.Minute})
	if e != nil {
		t.Fatal(e)
	}
	q.Revision = v.Revision
	v, e = next.Submit(h.ctx, user, v.ID, "40000000-0000-4000-8000-000000000006", q)
	if !errors.Is(e, storage.ErrCapacity) {
		t.Fatal("new key reset login budget", e)
	}
	h.clock.Add(6 * time.Minute)
	v, e = next.Resume(h.ctx, user, v.ID, custody.ResumeRequest{RequestID: v.RequestID, Revision: v.Revision}, false)
	if e != nil || v.State != "credentials_required" {
		t.Fatal("budget did not recover after cooldown", v, e)
	}
}

func TestCustodyBlockedRecoveryReauthorizeReplayQuotaAndSlidingBudget(t *testing.T) {
	h, s, p, _, user, q := custodyFixture(t)
	h.provider.verificationClock = h.clock.Now

	// 1. Six failed initial enrollments (target="") across cooldown must not permanently exhaust 5-binding quota.
	p.failPrepare.Store(true)
	for n := 1; n <= 6; n++ {
		if n == 6 {
			h.clock.Add(6 * time.Minute)
		}
		key := fmt.Sprintf("50000000-0000-4000-8000-%012d", n)
		v, err := s.Submit(h.ctx, user, "", key, q)
		if err != nil || v.State != "credentials_required" {
			t.Fatalf("failed unprovisioned attempt %d consumed binding quota: v=%+v err=%v", n, v, err)
		}
	}
	p.failPrepare.Store(false)
	h.clock.Add(6 * time.Minute)

	// 2. Claim succeeds then Prepare fails -> blocked (Result == nil).
	// Also test sliding window: 4 attempts on Day 1, then 1 attempt on Day 2 must count as 1 recent attempt, not 5.
	p.account = "account:recoverable-drive"
	p.failAfterClaim.Store(true)
	q.Until = h.clock.Now().Add(48 * time.Hour)
	blockedKey := "50000000-0000-4000-8000-000000000010"
	v, err := s.Submit(h.ctx, user, "", blockedKey, q)
	if err != nil || v.State != "blocked" {
		t.Fatalf("expected blocked binding, got %+v err=%v", v, err)
	}
	for attempt := 2; attempt <= 4; attempt++ {
		h.clock.Add(3 * time.Minute)
		v, err = s.Resume(h.ctx, user, v.ID, custody.ResumeRequest{RequestID: blockedKey, Revision: v.Revision}, false)
		if err != nil || v.State != "blocked" {
			t.Fatalf("attempt %d: %+v %v", attempt, v, err)
		}
	}
	// Advance 24h: previous 4 attempts are outside the 5-minute window.
	h.clock.Add(24 * time.Hour)
	v, err = s.Resume(h.ctx, user, v.ID, custody.ResumeRequest{RequestID: blockedKey, Revision: v.Revision}, false)
	if err != nil || v.State != "blocked" {
		t.Fatalf("5th attempt failed: %+v %v", v, err)
	}
	// Only 1 attempt occurred in the last 5 minutes, AND blocked binding with Result==nil/Attempts==5 must accept new Submit!
	p.failAfterClaim.Store(false)
	q.Revision = v.Revision
	q.Until = h.clock.Now().Add(48 * time.Hour)
	v, err = s.Submit(h.ctx, user, v.ID, "50000000-0000-4000-8000-000000000011", q)
	if err != nil || v.State != "ready" {
		t.Fatalf("blocked binding deadlock or sliding budget miscount: v=%+v err=%v", v, err)
	}

	// 3. Reauthorize succeeds in store, Commit fails -> blocked; >24h later (idempotency expired), Resume must converge to ready!
	p.failCommit.Store(true)
	q.Revision = v.Revision
	q.Until = h.clock.Now().Add(72 * time.Hour)
	reauthKey := "50000000-0000-4000-8000-000000000012"
	v, err = s.Submit(h.ctx, user, v.ID, reauthKey, q)
	if err != nil || v.State != "blocked" {
		t.Fatalf("expected blocked reauth on commit failure: v=%+v err=%v", v, err)
	}
	p.failCommit.Store(false)
	h.clock.Add(25 * time.Hour)
	v, err = s.Resume(h.ctx, user, v.ID, custody.ResumeRequest{RequestID: reauthKey, Revision: v.Revision}, false)
	if err != nil || v.State != "ready" {
		t.Fatalf("reauthorize recovery after 24h failed: v=%+v err=%v", v, err)
	}
}

func TestInstanceIdempotencySkipsSupplierProbeAndRefreshesExpiredQuota(t *testing.T) {
	h := harnessFor(t)
	h.provider.verificationClock = h.clock.Now
	i := h.instance(t, "idem-inst", "owner", "platform", 2048)
	callsAfterRegister := h.provider.verifyCalls

	// Replay Register with same key must not call Verify again.
	replayInput := storage.Instance{
		ID:                 "idem-inst",
		Adapter:            "test",
		AccountDomain:      "untrusted-alias",
		OwnerDomain:        "owner",
		Ownership:          "platform",
		CredentialRef:      "idem-inst",
		CredentialRevision: 1,
		Root:               "isolated",
		State:              "active",
		Authorized:         true,
		Limit:              2048,
		ExpiresAt:          i.ExpiresAt,
		Admissions:         i.Admissions,
	}
	again, err := h.s.Register(h.ctx, h.actor, "register-idem-inst", replayInput)
	if err != nil || again.ID != i.ID || h.provider.verifyCalls != callsAfterRegister {
		t.Fatalf("Register replay probed supplier or failed: calls=%d->%d err=%v", callsAfterRegister, h.provider.verifyCalls, err)
	}

	// Expire quota sample, then UpdateInstance: must refresh QuotaExpiresAt when Reserved == 0, and replay must skip Verify.
	h.clock.Add(10 * time.Minute)
	i.Limit = 4096
	updated, err := h.s.UpdateInstance(h.ctx, h.actor, "update-idem", i)
	if err != nil || !updated.QuotaExpiresAt.After(h.clock.Now()) {
		t.Fatalf("UpdateInstance discarded fresh quota evidence: %+v err=%v", updated, err)
	}
	callsAfterUpdate := h.provider.verifyCalls
	if _, err = h.s.UpdateInstance(h.ctx, h.actor, "update-idem", i); err != nil || h.provider.verifyCalls != callsAfterUpdate {
		t.Fatalf("UpdateInstance replay probed supplier: calls=%d->%d err=%v", callsAfterUpdate, h.provider.verifyCalls, err)
	}

	// Expire quota sample again, then ReauthorizeInstance: must refresh expired QuotaExpiresAt when Reserved == 0.
	h.clock.Add(10 * time.Minute)
	renewed, err := h.s.ReauthorizeInstance(h.ctx, h.actor, "reauth-idem", storage.CredentialRenewal{
		ID:                 updated.ID,
		ExpectedRevision:   updated.Revision,
		CredentialRef:      updated.CredentialRef,
		CredentialRevision: updated.CredentialRevision + 1,
		Until:              h.clock.Now().Add(24 * time.Hour),
	})
	if err != nil || !renewed.QuotaExpiresAt.After(h.clock.Now()) {
		t.Fatalf("ReauthorizeInstance left expired quota sample stale: %+v err=%v", renewed, err)
	}
}

func TestFailedCustodyRequestsReleaseOperationBudget(t *testing.T) {
	h, s, provider, _, user, q := custodyFixture(t)
	provider.failPrepare.Store(true)
	v, err := s.Submit(h.ctx, user, "", "90000000-0000-4000-8000-000000000001", q)
	if err != nil || v.State != "credentials_required" {
		t.Fatal(v, err)
	}
	repo := &postgres.CustodyRepository{Repository: h.repo}
	err = repo.Transaction(h.ctx, func(tx custody.Tx) error {
		count, err := tx.OperationCount()
		if err == nil && count != 0 {
			t.Errorf("terminal requests charged to operation budget: %d", count)
		}
		if err != nil {
			return err
		}
		op, err := tx.Operation(v.RequestID)
		if err == nil && op.Attempts != 1 {
			t.Errorf("lost login budget evidence: %d", op.Attempts)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCustodyRecoveryReacquiresReleasedSlot(t *testing.T) {
	h, s, provider, _, user, q := custodyFixture(t)
	h.provider.verificationClock = h.clock.Now
	provider.failPrepare.Store(true)
	v, err := s.Submit(h.ctx, user, "", "91000000-0000-4000-8000-000000000000", q)
	if err != nil || v.State != "credentials_required" {
		t.Fatal(v, err)
	}
	provider.failPrepare.Store(false)
	h.clock.Add(6 * time.Minute)
	for n := 1; n <= 5; n++ {
		result, err := s.Submit(h.ctx, user, "", fmt.Sprintf("91000000-0000-4000-8000-%012d", n), q)
		if err != nil || result.State != "ready" {
			t.Fatal(result, err)
		}
	}
	h.clock.Add(6 * time.Minute)
	if _, err = s.Resume(h.ctx, user, v.ID, custody.ResumeRequest{RequestID: v.RequestID, Revision: v.Revision}, false); !errors.Is(err, storage.ErrCapacity) {
		t.Errorf("resume with all slots occupied: %v", err)
	}
	q.Revision = v.Revision
	if _, err = s.Submit(h.ctx, user, v.ID, "91000000-0000-4000-8000-000000000006", q); !errors.Is(err, storage.ErrCapacity) {
		t.Errorf("replacement with all slots occupied: %v", err)
	}
	var count int
	if err = h.db.QueryRow("SELECT count(*) FROM storage.instances").Scan(&count); err != nil || count != 5 || provider.creates.Load() != 5 {
		t.Fatalf("registered %d, created roots %d, err %v", count, provider.creates.Load(), err)
	}
}

func TestCustodyInterruptedLastAttemptAllowsNewRevision(t *testing.T) {
	h, s, provider, _, user, q := custodyFixture(t)
	provider.failPrepare.Store(true)
	v, err := s.Submit(h.ctx, user, "", "92000000-0000-4000-8000-000000000001", q)
	if err != nil {
		t.Fatal(err)
	}
	repo := &postgres.CustodyRepository{Repository: h.repo}
	err = repo.Transaction(h.ctx, func(tx custody.Tx) error {
		b, err := tx.Binding(v.ID)
		if err != nil {
			return err
		}
		op, err := tx.Operation(v.RequestID)
		if err != nil {
			return err
		}
		b.State = "pending"
		op.Attempts = 5
		op.LeaseUntil = h.clock.Now().Add(time.Minute)
		if err := tx.SaveOperation(op); err != nil {
			return err
		}
		return tx.SaveBinding(b)
	})
	if err != nil {
		t.Fatal(err)
	}
	q.Revision = v.Revision
	key := "92000000-0000-4000-8000-000000000002"
	if _, err = s.Submit(h.ctx, user, v.ID, key, q); !errors.Is(err, storage.ErrConflict) {
		t.Fatal(err)
	}
	h.clock.Add(6 * time.Minute)
	provider.failPrepare.Store(false)
	h.provider.verificationClock = h.clock.Now
	next, err := s.Submit(h.ctx, user, v.ID, key, q)
	if err != nil || next.State != "ready" || next.Revision != v.Revision+1 || provider.creates.Load() != 1 {
		t.Fatal(next, err)
	}
}

type updatingVerifier struct {
	storage.Verifier
	after func()
}

func (v updatingVerifier) Verify(ctx context.Context, i storage.Instance) (storage.InstanceEvidence, error) {
	sample, err := v.Verifier.Verify(ctx, i)
	if err == nil {
		v.after()
	}
	return sample, err
}

func TestInstanceUpdatePreservesNewerQuotaSample(t *testing.T) {
	h := harnessFor(t)
	i := h.instance(t, "sampling", "platform", "platform", 4096)
	verifier := updatingVerifier{h.provider, func() {
		err := h.repo.Transaction(h.ctx, func(tx storage.Transaction) error {
			current, err := tx.Instance(i.ID)
			if err != nil {
				return err
			}
			current.QuotaRevision++
			current.ProviderFree = 42
			return tx.SaveInstance(current)
		})
		if err != nil {
			t.Fatal(err)
		}
	}}
	cfg := h.cfg
	cfg.TemporaryDirectory = t.TempDir()
	s, err := storage.New(h.repo, h.auth, h.provider, verifier, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close(h.ctx) })
	i.Limit = 2048
	updated, err := s.UpdateInstance(h.ctx, h.actor, "sampling-update", i)
	if err != nil || updated.ProviderFree != 42 || updated.QuotaRevision != i.QuotaRevision+1 || updated.Limit != 2048 {
		t.Fatalf("quota=%d revision=%d error=%v", updated.ProviderFree, updated.QuotaRevision, err)
	}
}

func TestCustodyUnknownPreparationKeepsAccountClaim(t *testing.T) {
	h, s, p, _, user, q := custodyFixture(t)
	p.account = "account:shared"
	h.provider.verificationClock = h.clock.Now
	p.unknownAfterClaim.Store(true)
	key := "00000000-0000-4000-8000-000000000001"
	v, err := s.Submit(h.ctx, user, "", key, q)
	if err != nil || v.State != "blocked" || v.LastError != "result_unknown" {
		t.Fatal(v, err)
	}
	h.clock.Add(3 * time.Minute)
	replacement := q
	replacement.Revision = v.Revision
	if _, err = s.Submit(h.ctx, user, v.ID, "00000000-0000-4000-8000-000000000002", replacement); !errors.Is(err, storage.ErrConflict) {
		t.Fatalf("replaced unknown request: %v", err)
	}
	var claimed string
	if err = h.db.QueryRow("SELECT account_domain FROM storage.custody_bindings WHERE id=$1", v.ID).Scan(&claimed); err != nil || claimed != p.account {
		t.Fatal(claimed, err)
	}
	p.unknownAfterClaim.Store(false)
	v, err = s.Submit(h.ctx, user, "", key, q)
	if err != nil || v.State != "ready" || p.prepareInputs.Load() != 1 || p.creates.Load() != 1 {
		t.Fatalf("recovery state=%s err=%v preparations=%d roots=%d", v.State, err, p.prepareInputs.Load(), p.creates.Load())
	}
}
