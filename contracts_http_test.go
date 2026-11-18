package storage_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	storage "github.com/StuHelper/stuhelper-storage"
	"github.com/StuHelper/stuhelper-storage/httpapi"
	"github.com/StuHelper/stuhelper-storage/sdk"
)

type unavailableAuth struct{}

func (unavailableAuth) Authenticate(*http.Request) (storage.Principal, error) {
	return storage.Principal{}, storage.ErrUnavailable
}

type minPrivAuth struct {
	mu      sync.Mutex
	allowed map[string]map[string]bool
}

func (a *minPrivAuth) Authorize(_ context.Context, p storage.Principal, action, _ string, _ storage.Protection) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.allowed[p.Subject]["*"] || a.allowed[p.Subject][action] {
		return nil
	}
	return storage.ErrDenied
}

func TestHTTPChunkedMaxBytesAuthUnavailableAndDuplicateIdempotencyHeader(t *testing.T) {
	h := harnessFor(t)
	h.instance(t, "upload-inst", "platform", "platform", 4096)

	const maxUpload = 64
	handler, err := httpapi.New(h.s, testAuthentication{}, maxUpload)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	// 1. Non-deduplicated object with Size == maxUpload, uploaded via chunked stream (ContentLength == -1) with maxUpload + 1 bytes -> must return 413, not 503!
	data := bytes.Repeat([]byte("a"), maxUpload)
	sum := sha256.Sum256(data)
	obj, err := h.s.Create(h.ctx, h.actor, "create-max", storage.CreateRequest{
		Size:       maxUpload,
		SHA256:     hex.EncodeToString(sum[:]),
		Protection: storage.Protection{Class: "public", Scope: "school-a", Public: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	oversizedBody := io.NopCloser(bytes.NewReader(bytes.Repeat([]byte("a"), maxUpload+1)))
	req, err := http.NewRequestWithContext(h.ctx, http.MethodPut, server.URL+"/api/v1/storage/objects/"+obj.ID+"/content", oversizedBody)
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = -1
	req.Header.Set("Authorization", "Bearer synthetic-test-token")
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Idempotency-Key", "chunked-over-limit")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	rawBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge || !strings.Contains(string(rawBody), "storage_upload_too_large") {
		t.Fatalf("chunked upload exceeding maxUpload returned %d %s, want 413 storage_upload_too_large", resp.StatusCode, string(rawBody))
	}

	// 2. Duplicate Idempotency-Key headers on httpapi.New must return 400!
	dupReq, _ := http.NewRequestWithContext(h.ctx, http.MethodPost, server.URL+"/api/v1/storage/objects", strings.NewReader(`{"size":4,"sha256":"`+strings.Repeat("b", 64)+`","protection":{"class":"public","scope":"school-a","public":true,"encrypted":false}}`))
	dupReq.Header.Set("Authorization", "Bearer synthetic-test-token")
	dupReq.Header.Set("Content-Type", "application/json")
	dupReq.Header.Add("Idempotency-Key", "key-1")
	dupReq.Header.Add("Idempotency-Key", "key-2")
	dupResp, err := http.DefaultClient.Do(dupReq)
	if err != nil {
		t.Fatal(err)
	}
	dupResp.Body.Close()
	if dupResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("duplicate Idempotency-Key accepted with status %d, want 400", dupResp.StatusCode)
	}

	// 3. Custody handler when authenticator returns ErrUnavailable must return 503 identity_unavailable!
	_, cs, _, _, _, _ := custodyFixture(t)
	custodyHandler, err := httpapi.NewCustody(cs, unavailableAuth{})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	custodyHandler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/storage/custody", nil))
	var prob sdk.Problem
	_ = json.Unmarshal(rec.Body.Bytes(), &prob)
	if rec.Code != http.StatusServiceUnavailable || prob.Code != "identity_unavailable" {
		t.Fatalf("custody unavailable auth returned %d %q, want 503 identity_unavailable", rec.Code, prob.Code)
	}
}

func TestCustodyBrowserSDKClassifies404AsNotFound(t *testing.T) {
	script := `
import ts from 'typescript';
import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';

const src = fs.readFileSync('sdk/custody-browser.ts', 'utf8');
const out = ts.transpileModule(src, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } });
const exportsObj = {};
const mod = { exports: exportsObj };
vm.runInNewContext(out.outputText, { exports: exportsObj, module: mod, URL, Response, AbortController, fetch: async () => new Response('{"code":"storage_not_found"}', { status: 404 }) });
const api = mod.exports.custodyAPI(async () => new Response('{"code":"storage_not_found"}', { status: 404 }));
const ac = new AbortController();
let statusErr;
try { await api.requestStatus('00000000-0000-4000-8000-000000000099', ac.signal); } catch (e) { statusErr = e; }
assert.equal(statusErr?.code, 'not_found');
assert.equal(statusErr?.uncertain, false);
let resumeErr;
try { await api.resume({ id: '00000000-0000-4000-8000-000000000099', adapter: 'bhpan', revision: 1, state: 'blocked', authorization_expires_at: '2027-01-01T00:00:00Z', request_id: '00000000-0000-4000-8000-000000000099', last_error: 'conflict' }, ac.signal); } catch (e) { resumeErr = e; }
assert.equal(resumeErr?.code, 'not_found');
assert.equal(resumeErr?.uncertain, false);
`
	cmd := exec.Command("node", "--input-type=module", "-e", script)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("custody-browser.ts 404 handling failed: %v\n%s", err, string(output))
	}
}

func TestLeastPrivilegeCreateDownloadAndExpiredConsentRetryRejection(t *testing.T) {
	base := harnessFor(t, func(c *storage.Config) { c.MaxAttempts = 1 })
	auth := &minPrivAuth{
		allowed: map[string]map[string]bool{
			"admin": {"*": true},
			"uploader": {
				"storage.objects.create": true,
				"storage.objects.upload": true,
			},
			"downloader": {
				"storage.objects.download": true,
			},
		},
	}
	svc, err := storage.New(base.repo, auth, base.provider, base.provider, storage.Config{
		Clock:              base.clock.Now,
		MaxObjectSize:      1 << 20,
		TemporaryDirectory: t.TempDir(),
		ParallelTransfers:  4,
		Lease:              time.Minute,
		VerificationAge:    time.Hour,
		MaxAttempts:        1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close(base.ctx) })

	admin := storage.Principal{Issuer: "test-issuer", Subject: "admin"}
	uploader := storage.Principal{Issuer: "test-issuer", Subject: "uploader"}
	downloader := storage.Principal{Issuer: "test-issuer", Subject: "downloader"}
	until := base.clock.Now().Add(48 * time.Hour)
	for _, id := range []string{"p1", "p2"} {
		if _, err = svc.Register(base.ctx, admin, "reg-"+id, storage.Instance{
			ID:                 id,
			Adapter:            "test",
			OwnerDomain:        id,
			Ownership:          "platform",
			CredentialRef:      id,
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
	}

	// 1. Deduplicated Create + Ingest with ONLY create + upload (no read)!
	payload := []byte("least-privilege-content")
	req := sharedRequest(payload)
	created, err := svc.Create(base.ctx, uploader, "dedup-create", req)
	if err != nil {
		t.Fatalf("Create(Deduplicate: true) required read permission: %v", err)
	}
	if _, err = svc.Ingest(base.ctx, uploader, created.ID, "dedup-upload", bytes.NewReader(payload)); err != nil {
		t.Fatalf("Ingest(Deduplicate: true) required read permission: %v", err)
	}

	// 2. HTTP download with ONLY storage.objects.download (no storage.objects.read)!
	regObj, err := svc.Create(base.ctx, admin, "dl-obj", storage.CreateRequest{
		Size:       int64(len(payload)),
		SHA256:     req.SHA256,
		Protection: req.Protection,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Ingest(base.ctx, admin, regObj.ID, "dl-ingest", bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Reconcile(base.ctx, admin, 100, ""); err != nil {
		t.Fatal(err)
	}
	for range 10 {
		claimed, err := svc.RunOne(base.ctx, "dl-worker")
		if err != nil {
			t.Fatal(err)
		}
		if !claimed {
			break
		}
	}

	httpHandler, err := httpapi.New(svc, fixedAuth{downloader}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	dlRec := httptest.NewRecorder()
	httpHandler.ServeHTTP(dlRec, httptest.NewRequest(http.MethodGet, "/api/v1/storage/objects/"+regObj.ID+"/content", nil))
	if dlRec.Code != http.StatusOK || !bytes.Equal(dlRec.Body.Bytes(), payload) {
		t.Fatalf("HTTP download demanded read permission: code=%d body=%q", dlRec.Code, dlRec.Body.String())
	}

	// The stable physical object outlives the 24-hour creation replay cache.
	base.clock.Add(25 * time.Hour)
	replay, err := svc.Ingest(base.ctx, uploader, created.ID, "dedup-upload-again", bytes.NewReader(payload))
	if err != nil || replay.ID != created.ID {
		t.Fatalf("stable content upload replay: %+v %v", replay, err)
	}
	var physical int
	if err = base.db.QueryRow("SELECT count(*) FROM storage.objects WHERE data ? 'content_group'").Scan(&physical); err != nil || physical != 1 {
		t.Fatalf("physical objects after replay: %d %v", physical, err)
	}

	// 3. RetryJob must reject blocked ingest/replicate job when ContributionControl.Until has expired!
	h2 := harnessFor(t, func(c *storage.Config) { c.MaxAttempts = 1 })
	cInst := h2.instance(t, "contrib-retry", "c-owner", "contributor", 0)
	cInst.State = "paused"
	cInst, err = h2.s.UpdateInstance(h2.ctx, h2.actor, "pause-c", cInst)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := h2.s.ApplyContribution(h2.ctx, h2.actor, cInst.ID, storage.ContributionControl{
		ID:               "c-consent",
		OwnerDomain:      "c-owner",
		Revision:         1,
		ExpectedRevision: cInst.Revision,
		State:            "active",
		LimitBytes:       2048,
		Until:            h2.clock.Now().Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = snap
	oBlocked := h2.object(t, "blocked-contrib", payload)
	h2.provider.lostBegin = true
	if _, err = h2.s.Ingest(h2.ctx, h2.actor, oBlocked.ID, "ingest-blocked", bytes.NewReader(payload)); !errors.Is(err, storage.ErrUnknown) {
		t.Fatal(err)
	}
	h2.provider.lostBegin = false
	ops, err := h2.s.Operations(h2.ctx, h2.actor, 100, "", "")
	if err != nil || len(ops.Failures) != 1 {
		t.Fatal(ops, err)
	}
	h2.clock.Add(11 * time.Minute) // ContributionControl.Until expired, while instance.ExpiresAt is 24h!
	if _, err = h2.s.RetryJob(h2.ctx, h2.actor, oBlocked.ID, ops.Failures[0].ID, "retry-expired-consent", ops.Failures[0].Generation); !errors.Is(err, storage.ErrDenied) {
		t.Fatalf("RetryJob allowed retry on expired contribution consent: %v", err)
	}
}

type fixedAuth struct{ p storage.Principal }

func (f fixedAuth) Authenticate(*http.Request) (storage.Principal, error) { return f.p, nil }
