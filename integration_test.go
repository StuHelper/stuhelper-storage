package storage_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	storage "github.com/StuHelper/stuhelper-storage"
	"github.com/StuHelper/stuhelper-storage/httpapi"
	"github.com/StuHelper/stuhelper-storage/postgres"
	"github.com/StuHelper/stuhelper-storage/sdk"
)

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *clock) Add(d time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.now = c.now.Add(d) }

type authorization struct{ denied atomic.Bool }

func (a *authorization) Authorize(_ context.Context, p storage.Principal, action, id string, protection storage.Protection) error {
	if a.denied.Load() || p.Subject != "operator" {
		return storage.ErrDenied
	}
	return nil
}

type provider struct {
	mu              sync.Mutex
	files           map[string]map[string][]byte
	accounts        map[string]string
	writes          int
	verifyCalls     int
	lostReply       bool
	lostBegin       bool
	corruptWrite    bool
	readUnavailable bool
	readStarted     chan struct{}
	readWait        chan struct{}
	afterWrite      func()
}

func (p *provider) Verify(_ context.Context, i storage.Instance) (storage.InstanceEvidence, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.verifyCalls++
	domain := p.accounts[i.CredentialRef]
	if domain == "" {
		domain = "account:" + i.CredentialRef
	}
	return storage.InstanceEvidence{AccountDomain: domain, ProviderFree: 1 << 30, VerifiedAt: time.Now()}, nil
}
func (p *provider) Resolve(context.Context, storage.Instance) (storage.Driver, error) { return p, nil }
func (p *provider) Find(_ context.Context, i storage.Instance, intent string, expected storage.Locator) (storage.Locator, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.files[i.ID][intent]; !ok {
		return storage.Locator{}, storage.ErrNotFound
	}
	return storage.Locator{ID: intent, Revision: "1"}, nil
}
func (p *provider) Write(ctx context.Context, i storage.Instance, intent string, size int64, src io.Reader, checkpoint func(storage.Locator) error) (storage.Locator, error) {
	if p.lostBegin {
		p.writes++
		return storage.Locator{}, storage.ErrUnknown
	}
	remote := storage.Locator{ID: intent, Revision: "1"}
	if err := checkpoint(remote); err != nil {
		return remote, err
	}
	data, err := io.ReadAll(io.LimitReader(src, size+1))
	if err != nil {
		return remote, err
	}
	if int64(len(data)) != size {
		return remote, storage.ErrIntegrity
	}
	p.mu.Lock()
	if p.files[i.ID] == nil {
		p.files[i.ID] = map[string][]byte{}
	}
	if p.corruptWrite {
		data[0] ^= 1
	}
	p.files[i.ID][intent] = data
	p.writes++
	lost := p.lostReply
	hook := p.afterWrite
	p.mu.Unlock()
	if hook != nil {
		hook()
	}
	if lost {
		return remote, storage.ErrUnknown
	}
	return remote, nil
}

func TestUnknownBeginNeverRetriesOrReleasesReservation(t *testing.T) {
	h := harnessFor(t)
	h.instance(t, "one", "owner", "platform", 1024)
	data := []byte("ambiguous begin")
	o := h.object(t, "create", data)
	h.provider.lostBegin = true
	if _, err := h.s.Ingest(h.ctx, h.actor, o.ID, "ingest", bytes.NewReader(data)); !errors.Is(err, storage.ErrUnknown) {
		t.Fatal(err)
	}
	h.provider.lostBegin = false
	h.clock.Add(6 * time.Second)
	if _, err := h.s.RunOne(h.ctx, "worker"); !errors.Is(err, storage.ErrUnknown) {
		t.Fatal(err)
	}
	if h.provider.writes != 1 {
		t.Fatal("blindly retried unknown begin")
	}
	if _, err := h.s.Delete(h.ctx, h.actor, o.ID, "delete", o.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := h.s.RunOne(h.ctx, "worker"); !errors.Is(err, storage.ErrUnknown) {
		t.Fatal(err)
	}
	instances, _ := h.s.Instances(h.ctx, h.actor, 100, "")
	if instances[0].Reserved != int64(len(data)) {
		t.Fatal("released unknown remote capacity")
	}
}

func TestRestrictedPlacementAndCredentialRotation(t *testing.T) {
	h := harnessFor(t)
	i := h.instance(t, "one", "owner", "contributor", 1024)
	data := []byte("public")
	o := h.object(t, "create", data)
	h.ingest(t, o.ID, data)
	protection := storage.Protection{Class: "internal", Scope: "school-a"}
	if _, err := h.s.ChangeProtection(h.ctx, h.actor, o.ID, "protect", o.Revision, protection); err != nil {
		t.Fatal(err)
	}
	st, err := h.s.Status(h.ctx, h.actor, o.ID)
	if err != nil || st.Healthy != 0 {
		t.Fatalf("restricted placement: %+v %v", st, err)
	}
	h.run(t)
	if _, err = h.s.Ingest(h.ctx, h.actor, o.ID, "restricted-upload", bytes.NewReader(data)); !errors.Is(err, storage.ErrCapacity) {
		t.Fatal(err)
	}
	i.CredentialRef = "new-account"
	i.CredentialRevision = 2
	if _, err = h.s.UpdateInstance(h.ctx, h.actor, "wrong-account", i); !errors.Is(err, storage.ErrDenied) {
		t.Fatal(err)
	}
	h.provider.accounts["new-account"] = i.AccountDomain
	if _, err = h.s.UpdateInstance(h.ctx, h.actor, "same-account", i); err != nil {
		t.Fatal(err)
	}
}

func TestExpiredEmptyObjectIsTombstoned(t *testing.T) {
	h := harnessFor(t)
	o := h.object(t, "unused", []byte("x"))
	h.clock.Add(25 * time.Hour)
	h.reconcile(t)
	st, err := h.s.Status(h.ctx, h.actor, o.ID)
	if err != nil || st.State != "deleted" {
		t.Fatalf("expired: %+v %v", st, err)
	}
}
func (p *provider) Read(ctx context.Context, i storage.Instance, r storage.Locator, dst io.Writer) (int64, error) {
	if p.readWait != nil {
		p.readStarted <- struct{}{}
		select {
		case <-p.readWait:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	if p.readUnavailable {
		return 0, storage.ErrUnavailable
	}
	p.mu.Lock()
	data, ok := p.files[i.ID][r.ID]
	data = bytes.Clone(data)
	p.mu.Unlock()
	if !ok {
		return 0, storage.ErrNotFound
	}
	n, err := dst.Write(data)
	return int64(n), err
}
func (p *provider) Remove(_ context.Context, i storage.Instance, r storage.Locator) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.files[i.ID], r.ID)
	return nil
}

type harness struct {
	s         *storage.Service
	repo      *postgres.Repository
	db, admin *sql.DB
	provider  *provider
	auth      *authorization
	clock     *clock
	actor     storage.Principal
	ctx       context.Context
	cfg       storage.Config
}

func harnessFor(t *testing.T, configure ...func(*storage.Config)) *harness {
	t.Helper()
	dsn := os.Getenv("STUHELPER_STORAGE_TEST_DSN")
	if dsn == "" {
		t.Skip("PostgreSQL integration requires STUHELPER_STORAGE_TEST_DSN")
	}
	ctx := context.Background()
	control, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	var nonce [8]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	name := "storage_test_" + hex.EncodeToString(nonce[:])
	if _, err = control.Exec(`CREATE DATABASE ` + name); err != nil {
		t.Fatal(err)
	}
	admin, err := sql.Open("pgx", dsn+" dbname="+name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		admin.Close()
		_, err := control.Exec(`DROP DATABASE ` + name + ` WITH (FORCE)`)
		if err != nil {
			t.Error(err)
		}
		control.Close()
	})
	if _, err = admin.Exec(postgres.Schema); err != nil {
		t.Fatal(err)
	}
	if _, err = admin.Exec(`DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='storage_test_runtime') THEN CREATE ROLE storage_test_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE; END IF; END $$;
GRANT USAGE ON SCHEMA storage TO storage_test_runtime;
GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA storage TO storage_test_runtime;
REVOKE UPDATE,DELETE ON storage.audit FROM storage_test_runtime;
CREATE SCHEMA other_module;
CREATE TABLE other_module.private_data(id integer);
REVOKE ALL ON SCHEMA other_module FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM PUBLIC;`); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("pgx", dsn+" dbname="+name+" user=storage_test_runtime")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(12)
	t.Cleanup(func() { db.Close() })
	repo := &postgres.Repository{DB: db}
	auth := &authorization{}
	p := &provider{files: map[string]map[string][]byte{}, accounts: map[string]string{}}
	c := &clock{now: time.Now().UTC()}
	cfg := storage.Config{Clock: c.Now, MaxObjectSize: 1 << 20, TemporaryDirectory: t.TempDir(), ParallelTransfers: 4, Lease: time.Minute, VerificationAge: time.Hour, MaxAttempts: 3}
	for _, apply := range configure {
		apply(&cfg)
	}
	s, err := storage.New(repo, auth, p, p, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	return &harness{s, repo, db, admin, p, auth, c, storage.Principal{Issuer: "test-issuer", Subject: "operator"}, ctx, cfg}
}
func (h *harness) instance(t *testing.T, id, owner, kind string, limit int64) storage.Instance {
	t.Helper()
	v, err := h.s.Register(h.ctx, h.actor, "register-"+id, storage.Instance{ID: id, Adapter: "test", AccountDomain: "untrusted-alias", OwnerDomain: owner, Ownership: kind, CredentialRef: id, CredentialRevision: 1, Root: "isolated", State: "active", Authorized: true, Limit: limit, ExpiresAt: h.clock.Now().Add(24 * time.Hour), Admissions: []storage.Admission{{Class: "public", Scope: "school-a", Plaintext: true, ExpiresAt: h.clock.Now().Add(24 * time.Hour)}}})
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func (h *harness) object(t *testing.T, key string, data []byte) storage.Status {
	t.Helper()
	sum := sha256.Sum256(data)
	v, err := h.s.Create(h.ctx, h.actor, key, storage.CreateRequest{Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:]), Protection: storage.Protection{Class: "public", Scope: "school-a", Public: true}})
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func (h *harness) ingest(t *testing.T, id string, data []byte) storage.Status {
	t.Helper()
	v, err := h.s.Ingest(h.ctx, h.actor, id, "upload", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func (h *harness) reconcile(t *testing.T) {
	t.Helper()
	if _, err := h.s.Reconcile(h.ctx, h.actor, 100, ""); err != nil {
		t.Fatal(err)
	}
}
func (h *harness) run(t *testing.T) {
	t.Helper()
	claimed, err := h.s.RunOne(h.ctx, "worker-a")
	if err != nil {
		t.Fatal(err)
	}
	if !claimed {
		t.Fatal("expected queued job")
	}
}

func TestPublicationThresholdAndThreeIndependentReplicas(t *testing.T) {
	h := harnessFor(t)
	for n := 1; n <= 3; n++ {
		h.instance(t, fmt.Sprintf("i%d", n), fmt.Sprintf("owner%d", n), "contributor", 1024)
	}
	data := []byte("immutable storage data")
	o := h.object(t, "create", data)
	h.ingest(t, o.ID, data)
	if _, err := h.s.Reference(h.ctx, h.actor, o.ID, "attach-before-ready", storage.Reference{Module: "resources", ID: "r1"}, true); !errors.Is(err, storage.ErrUnavailable) {
		t.Fatalf("premature reference: %v", err)
	}
	h.reconcile(t)
	h.run(t)
	st, err := h.s.Status(h.ctx, h.actor, o.ID)
	if err != nil || st.Healthy != 2 || st.State != "degraded" {
		t.Fatalf("two replicas: %+v %v", st, err)
	}
	if _, err = h.s.Reference(h.ctx, h.actor, o.ID, "attach", storage.Reference{Module: "resources", ID: "r1"}, true); err != nil {
		t.Fatal(err)
	}
	h.run(t)
	st, err = h.s.Status(h.ctx, h.actor, o.ID)
	if err != nil || st.Healthy != 3 || st.State != "ready" || !st.Published {
		t.Fatalf("three replicas: %+v %v", st, err)
	}
	var output bytes.Buffer
	if err = h.s.Download(h.ctx, h.actor, o.ID, &output); err != nil || !bytes.Equal(output.Bytes(), data) {
		t.Fatalf("download: %v", err)
	}
	for _, id := range []string{"i1", "i2"} {
		items, _ := h.s.Instances(h.ctx, h.actor, 100, "")
		for _, v := range items {
			if v.ID == id {
				v.State = "revoked"
				v.Authorized = false
				if _, err = h.s.UpdateInstance(h.ctx, h.actor, "revoke-"+id, v); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	output.Reset()
	if err = h.s.Download(h.ctx, h.actor, o.ID, &output); err != nil || !bytes.Equal(output.Bytes(), data) {
		t.Fatalf("single surviving copy: %v", err)
	}
	items, _ := h.s.Instances(h.ctx, h.actor, 100, "")
	for _, v := range items {
		if v.ID == "i3" {
			v.Authorized = false
			_, err = h.s.UpdateInstance(h.ctx, h.actor, "revoke-final", v)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	output.Reset()
	if err = h.s.Download(h.ctx, h.actor, o.ID, &output); !errors.Is(err, storage.ErrUnavailable) || output.Len() != 0 {
		t.Fatalf("all revoked: %v bytes=%d", err, output.Len())
	}
}

func TestConcurrentCapacityReservationsAndIdempotency(t *testing.T) {
	h := harnessFor(t)
	data := []byte("capacity")
	h.instance(t, "only", "owner", "platform", int64(len(data)))
	var objects [2]storage.Status
	for i := range objects {
		objects[i] = h.object(t, fmt.Sprint(i), data)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, o := range objects {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			_, err := h.s.Ingest(h.ctx, h.actor, id, "same-upload-key", bytes.NewReader(data))
			errs <- err
		}(o.ID)
	}
	wg.Wait()
	close(errs)
	success, capacity := 0, 0
	for err := range errs {
		if err == nil {
			success++
		} else if errors.Is(err, storage.ErrCapacity) {
			capacity++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || capacity != 1 {
		t.Fatalf("success=%d capacity=%d", success, capacity)
	}
	instances, _ := h.s.Instances(h.ctx, h.actor, 100, "")
	if instances[0].Used != int64(len(data)) || instances[0].Reserved != 0 {
		t.Fatalf("budget: %+v", instances[0])
	}
	replay := h.object(t, "0", data)
	if replay.ID != objects[0].ID {
		t.Fatal("idempotency created another object")
	}
	_, err := h.s.Create(h.ctx, h.actor, "0", storage.CreateRequest{Size: 1, SHA256: strings.Repeat("a", 64), Protection: storage.Protection{Class: "public", Scope: "school-a", Public: true}})
	if !errors.Is(err, storage.ErrConflict) {
		t.Fatal(err)
	}
	h.auth.denied.Store(true)
	_, err = h.s.Create(h.ctx, h.actor, "0", storage.CreateRequest{Size: int64(len(data)), SHA256: objects[0].SHA256, Protection: objects[0].Protection})
	if !errors.Is(err, storage.ErrDenied) {
		t.Fatalf("replay authorization: %v", err)
	}
}

func TestAccountDeduplicationAndContributorIsolation(t *testing.T) {
	h := harnessFor(t)
	h.provider.accounts["alias"] = "account:first"
	h.instance(t, "first", "same-owner", "contributor", 1024)
	_, err := h.s.Register(h.ctx, h.actor, "duplicate", storage.Instance{ID: "alias", Adapter: "test", OwnerDomain: "other-owner", Ownership: "contributor", CredentialRef: "alias", CredentialRevision: 1, Root: "second-root", State: "active", Authorized: true, Limit: 1024, ExpiresAt: time.Now().Add(time.Hour)})
	if !errors.Is(err, storage.ErrConflict) {
		t.Fatalf("duplicate account: %v", err)
	}
	h.instance(t, "second", "same-owner", "contributor", 1024)
	data := []byte("a")
	o := h.object(t, "create", data)
	h.ingest(t, o.ID, data)
	h.reconcile(t)
	claimed, err := h.s.RunOne(h.ctx, "worker")
	if err != nil || claimed {
		t.Fatalf("same contributor counted twice: %v %v", claimed, err)
	}
	st, _ := h.s.Status(h.ctx, h.actor, o.ID)
	if st.Healthy != 1 {
		t.Fatalf("replicas=%d", st.Healthy)
	}
}

func TestUnknownWriteReconcilesWithoutDuplicatingOrReleasingCapacity(t *testing.T) {
	h := harnessFor(t)
	h.instance(t, "i1", "owner", "platform", 1024)
	data := []byte("lost completion response")
	o := h.object(t, "create", data)
	h.provider.lostReply = true
	_, err := h.s.Ingest(h.ctx, h.actor, o.ID, "upload", bytes.NewReader(data))
	if !errors.Is(err, storage.ErrUnknown) {
		t.Fatal(err)
	}
	instances, _ := h.s.Instances(h.ctx, h.actor, 100, "")
	if instances[0].Reserved != int64(len(data)) || instances[0].Used != 0 {
		t.Fatal("ambiguous result released budget")
	}
	h.provider.lostReply = false
	h.clock.Add(6 * time.Second)
	h.run(t)
	st, _ := h.s.Status(h.ctx, h.actor, o.ID)
	if st.Healthy != 1 || h.provider.writes != 1 {
		t.Fatalf("status=%+v writes=%d", st, h.provider.writes)
	}
}

func TestChecksumMismatchNeverPublishesOrLeaksPartialDownload(t *testing.T) {
	h := harnessFor(t)
	for n := 1; n <= 3; n++ {
		h.instance(t, fmt.Sprint("i", n), fmt.Sprint("owner", n), "platform", 1024)
	}
	data := []byte("verified data")
	o := h.object(t, "create", data)
	h.ingest(t, o.ID, data)
	h.reconcile(t)
	h.run(t)
	h.run(t)
	h.provider.mu.Lock()
	for _, files := range h.provider.files {
		for _, data := range files {
			data[0] ^= 1
		}
	}
	h.provider.mu.Unlock()
	var dst bytes.Buffer
	err := h.s.Download(h.ctx, h.actor, o.ID, &dst)
	if !errors.Is(err, storage.ErrUnavailable) || dst.Len() != 0 {
		t.Fatalf("corrupt output: %v %q", err, dst.Bytes())
	}
	st, _ := h.s.Status(h.ctx, h.actor, o.ID)
	if st.Healthy != 0 {
		t.Fatal("damaged replicas still healthy")
	}
}

func TestRevocationDuringWriteAndDeleteCannotResurrectObject(t *testing.T) {
	h := harnessFor(t)
	h.instance(t, "i1", "owner", "platform", 1024)
	data := []byte("tombstone")
	o := h.object(t, "create", data)
	h.provider.afterWrite = func() {
		_, err := h.s.Delete(h.ctx, h.actor, o.ID, "delete", o.Revision)
		if err != nil {
			t.Error(err)
		}
	}
	_, err := h.s.Ingest(h.ctx, h.actor, o.ID, "upload", bytes.NewReader(data))
	if !errors.Is(err, storage.ErrStale) {
		t.Fatalf("late write: %v", err)
	}
	h.provider.afterWrite = nil
	h.run(t)
	st, _ := h.s.Status(h.ctx, h.actor, o.ID)
	if st.State != "deleted" || st.Healthy != 0 {
		t.Fatalf("resurrected %+v", st)
	}
	instances, _ := h.s.Instances(h.ctx, h.actor, 100, "")
	if instances[0].Reserved != 0 || instances[0].Used != 0 {
		t.Fatal("deleted bytes remain accounted")
	}
}

func TestRuntimeDatabaseIdentityAndAtomicAuditOutbox(t *testing.T) {
	h := harnessFor(t)
	if err := h.repo.CheckRuntime(h.ctx); err != nil {
		t.Fatal(err)
	}
	if err := (&postgres.Repository{DB: h.admin}).CheckRuntime(h.ctx); !errors.Is(err, storage.ErrDenied) {
		t.Fatal("accepted administrative database identity", err)
	}
	for _, query := range []string{`SELECT * FROM other_module.private_data`, `CREATE TABLE storage.forbidden(id integer)`, `DELETE FROM storage.audit`} {
		if _, err := h.db.Exec(query); err == nil {
			t.Fatalf("runtime permitted %s", query)
		}
	}
	h.object(t, "create", []byte("a"))
	events, err := h.repo.PendingEvents(h.ctx, 100)
	if err != nil || len(events) != 1 {
		t.Fatalf("events=%d %v", len(events), err)
	}
	var audits int
	if err = h.admin.QueryRow(`SELECT count(*) FROM storage.audit`).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("audit missing", err)
	}
	if err = h.repo.AcknowledgeEvent(h.ctx, events[0].ID); err != nil {
		t.Fatal(err)
	}
	events, err = h.repo.PendingEvents(h.ctx, 100)
	if err != nil || len(events) != 0 {
		t.Fatal("event acknowledgement failed", err)
	}
}

type testAuthentication struct{}

func (testAuthentication) Authenticate(r *http.Request) (storage.Principal, error) {
	if r.Header.Get("Authorization") != "Bearer synthetic-test-token" {
		return storage.Principal{}, storage.ErrDenied
	}
	return storage.Principal{Issuer: "test-issuer", Subject: "operator"}, nil
}

func TestHTTPContractSDKAndAuthenticationBoundary(t *testing.T) {
	h := harnessFor(t)
	handler, err := httpapi.New(h.s, testAuthentication{}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	client, err := sdk.NewClientWithResponses(server.URL, sdk.WithRequestEditorFn(func(_ context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer synthetic-test-token")
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.CreateObjectWithResponse(h.ctx, &sdk.CreateObjectParams{IdempotencyKey: "sdk-create"}, sdk.CreateObjectJSONRequestBody{Size: 3, Sha256: strings.Repeat("a", 64), Protection: sdk.Protection{Class: "public", Scope: "school-a", Public: true, Encrypted: false}})
	if err != nil || result.JSON200 == nil || result.JSON200.Policy.Target != 3 || result.JSON200.Policy.Publish != 2 {
		t.Fatalf("SDK result: %+v %v", result, err)
	}
	response, err := http.Get(server.URL + "/api/v1/storage/objects/" + result.JSON200.Id)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatalf("anonymous status %d", response.StatusCode)
	}
	request, _ := http.NewRequest("POST", server.URL+"/api/v1/storage/objects", strings.NewReader(`{"size":3,"sha256":"`+strings.Repeat("a", 64)+`","protection":{"class":"public","scope":"school-a","public":true,"encrypted":false},"unexpected":true}`))
	request.Header.Set("Authorization", "Bearer synthetic-test-token")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "strict")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 400 {
		t.Fatalf("unknown fields status %d", response.StatusCode)
	}
	closed, _ := httpapi.New(h.s, nil, 1<<20)
	recorder := httptest.NewRecorder()
	closed.ServeHTTP(recorder, httptest.NewRequest("GET", "/api/v1/storage/instances", nil))
	if recorder.Code != 503 {
		t.Fatal("missing identity did not close access")
	}
}

func TestDrainWaitsForVerifiedReplacement(t *testing.T) {
	h := harnessFor(t)
	for n := 1; n <= 4; n++ {
		h.instance(t, fmt.Sprint("i", n), fmt.Sprint("owner", n), "platform", 1024)
	}
	data := []byte("drain only after replacement")
	o := h.object(t, "create", data)
	h.ingest(t, o.ID, data)
	h.reconcile(t)
	h.run(t)
	h.run(t)
	instances, _ := h.s.Instances(h.ctx, h.actor, 100, "")
	draining := instances[0]
	draining.State = "draining"
	if _, err := h.s.UpdateInstance(h.ctx, h.actor, "drain", draining); err != nil {
		t.Fatal(err)
	}
	h.reconcile(t)
	var pendingDeletes int
	if err := h.admin.QueryRow(`SELECT count(*) FROM storage.jobs WHERE data->>'kind'='delete' AND state='pending'`).Scan(&pendingDeletes); err != nil {
		t.Fatal(err)
	}
	if pendingDeletes != 0 {
		t.Fatal("deleted before replacement verification")
	}
	for n := 0; n < 2; n++ {
		h.run(t)
	}
	h.reconcile(t)
	h.run(t)
	st, err := h.s.Status(h.ctx, h.actor, o.ID)
	if err != nil || st.Healthy != 3 {
		t.Fatalf("after drain: %+v %v", st, err)
	}
	h.provider.mu.Lock()
	remaining := len(h.provider.files[draining.ID])
	h.provider.mu.Unlock()
	if remaining != 0 {
		t.Fatal("drained copy was not removed")
	}
}

func TestOldLeaseCannotCommitAfterAnotherWorkerClaims(t *testing.T) {
	h := harnessFor(t)
	h.instance(t, "i1", "owner", "platform", 1024)
	data := []byte("lease fencing")
	o := h.object(t, "create", data)
	h.provider.afterWrite = func() {
		h.clock.Add(61 * time.Second)
		if _, err := h.repo.Claim(h.ctx, "replacement-worker", h.clock.Now(), time.Minute); err != nil {
			t.Error(err)
		}
	}
	_, err := h.s.Ingest(h.ctx, h.actor, o.ID, "upload", bytes.NewReader(data))
	if !errors.Is(err, storage.ErrStale) {
		t.Fatalf("old completion: %v", err)
	}
	st, _ := h.s.Status(h.ctx, h.actor, o.ID)
	if st.Healthy != 0 {
		t.Fatal("old worker published replica")
	}
	h.provider.afterWrite = nil
	h.clock.Add(61 * time.Second)
	h.run(t)
	st, _ = h.s.Status(h.ctx, h.actor, o.ID)
	if st.Healthy != 1 || h.provider.writes != 1 {
		t.Fatal("recovery did not reconcile existing content")
	}
}
