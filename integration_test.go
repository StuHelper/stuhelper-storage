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
	"github.com/StuHelper/stuhelper-storage/auditquery"
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
	mu                sync.Mutex
	files             map[string]map[string][]byte
	accounts          map[string]string
	writes            int
	verifyCalls       int
	verificationClock func() time.Time
	lostReply         bool
	lostBegin         bool
	corruptWrite      bool
	readUnavailable   bool
	readStarted       chan struct{}
	readWait          chan struct{}
	afterWrite        func()
}

func (p *provider) Verify(_ context.Context, i storage.Instance) (storage.InstanceEvidence, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.verifyCalls++
	domain := p.accounts[i.CredentialRef]
	if domain == "" {
		domain = "account:" + i.CredentialRef
	}
	now := time.Now()
	if p.verificationClock != nil {
		now = p.verificationClock()
	}
	return storage.InstanceEvidence{AccountDomain: domain, ProviderFree: 1 << 30, VerifiedAt: now}, nil
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
REVOKE UPDATE,DELETE,TRUNCATE ON storage.audit FROM storage_test_runtime;
REVOKE INSERT,UPDATE,DELETE,TRUNCATE ON storage.audit_retention FROM storage_test_runtime;
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

func TestUnpublishedReviewReadKeepsPublicationThresholdAndRechecksPermission(t *testing.T) {
	h := harnessFor(t)
	h.instance(t, "review-store", "review-owner", "platform", 1024)
	data := []byte("unpublished review data")
	o := h.object(t, "review", data)
	h.ingest(t, o.ID, data)
	var out bytes.Buffer
	if e := h.s.Download(h.ctx, h.actor, o.ID, &out); !errors.Is(e, storage.ErrUnavailable) || out.Len() != 0 {
		t.Fatal("ordinary read before threshold", e)
	}
	if e := h.s.ReviewDownload(h.ctx, h.actor, o.ID, &out); e != nil || !bytes.Equal(out.Bytes(), data) {
		t.Fatal("review read", e)
	}
	status, e := h.s.Status(h.ctx, h.actor, o.ID)
	if e != nil || status.Published || status.Healthy != 1 {
		t.Fatal("review altered publication", status, e)
	}
	h.auth.denied.Store(true)
	out.Reset()
	if e = h.s.ReviewDownload(h.ctx, h.actor, o.ID, &out); !errors.Is(e, storage.ErrDenied) || out.Len() != 0 {
		t.Fatal("revoked review read", e)
	}
}

func TestAuditRetentionBoundarySchoolProjectionAndReviewAudit(t *testing.T) {
	h := harnessFor(t)

	// 1. CheckRuntime must reject a runtime role that can mutate storage.audit_retention.
	if _, err := h.admin.Exec(`GRANT UPDATE ON storage.audit_retention TO storage_test_runtime`); err != nil {
		t.Fatal(err)
	}
	if err := h.repo.CheckRuntime(h.ctx); !errors.Is(err, storage.ErrDenied) {
		t.Fatalf("CheckRuntime permitted audit_retention write privilege: %v", err)
	}
	if _, err := h.admin.Exec(`REVOKE INSERT,UPDATE,DELETE,TRUNCATE ON storage.audit_retention FROM storage_test_runtime`); err != nil {
		t.Fatal(err)
	}
	if err := h.repo.CheckRuntime(h.ctx); err != nil {
		t.Fatalf("CheckRuntime rejected valid read-only audit_retention grant: %v", err)
	}

	// 2. Object operations and ReviewDownload (both regular object and shared content) must project school scope, result='success', and review audit.
	h.instance(t, "audit-inst", "platform", "platform", 4096)
	data := []byte("reviewable school-a content")
	o := h.object(t, "school-obj", data)
	h.ingest(t, o.ID, data)
	var reviewed bytes.Buffer
	if err := h.s.ReviewDownload(h.ctx, h.actor, o.ID, &reviewed); err != nil || !bytes.Equal(reviewed.Bytes(), data) {
		t.Fatalf("object ReviewDownload failed: %v", err)
	}

	shared := sharedCreate(t, h, "school-shared", sharedRequest(data))
	h.ingest(t, shared.ID, data)
	reviewed.Reset()
	if err := h.s.ReviewDownload(h.ctx, h.actor, shared.ID, &reviewed); err != nil || !bytes.Equal(reviewed.Bytes(), data) {
		t.Fatalf("shared ReviewDownload failed: %v", err)
	}

	until := time.Now().UTC().Add(time.Hour)
	batchA, err := h.repo.ReadAudit(h.ctx, auditquery.Request{
		Scopes: []auditquery.Scope{{School: "school-a", Group: "*", Module: "storage"}},
		Until:  until,
		Limit:  100,
	})
	if err != nil {
		t.Fatal(err)
	}
	seenObjectReview := false
	seenContentReview := false
	for _, rec := range batchA.Records {
		if rec.Scope.School != "school-a" || rec.Result != "success" {
			t.Fatalf("unexpected audit projection: %+v", rec)
		}
		if rec.Action == "storage.object.reviewed.v1" && rec.Target == o.ID {
			seenObjectReview = true
		}
		if rec.Action == "storage.content.reviewed.v1" && rec.Target == shared.ID {
			seenContentReview = true
		}
	}
	if !seenObjectReview || !seenContentReview {
		t.Fatalf("missing review audit records in school-a scope: obj=%v content=%v total=%d", seenObjectReview, seenContentReview, len(batchA.Records))
	}

	batchB, err := h.repo.ReadAudit(h.ctx, auditquery.Request{
		Scopes: []auditquery.Scope{{School: "school-b", Group: "*", Module: "storage"}},
		Until:  until,
		Limit:  100,
	})
	if err != nil || len(batchB.Records) != 0 {
		t.Fatalf("foreign school leaked audit records: len=%d err=%v", len(batchB.Records), err)
	}

	// Failed custody password must record result='denied'.
	ch, cs, cp, _, user, q := custodyFixture(t)
	cp.failPrepare.Store(true)
	cv, err := cs.Submit(ch.ctx, user, "", "60000000-0000-4000-8000-000000000001", q)
	if err != nil {
		t.Fatal(err)
	}
	custodyBatch, err := ch.repo.ReadAudit(ch.ctx, auditquery.Request{
		Scopes: []auditquery.Scope{{School: "*", Group: "*", Module: "storage"}},
		Target: cv.ID,
		Action: "storage.custody.credentials_required.v1",
		Until:  time.Now().UTC().Add(time.Hour),
		Limit:  10,
	})
	if err != nil || len(custodyBatch.Records) != 1 || custodyBatch.Records[0].Result != "denied" {
		t.Fatalf("custody denied audit not projected: %+v err=%v", custodyBatch.Records, err)
	}
}

func TestOutboxSequencePreservesSubjectOrderAndAvoidsHeadOfLineStarvation(t *testing.T) {
	h := harnessFor(t)
	h.instance(t, "outbox-inst", "platform", "platform", 8192)

	// Perform multiple sequential mutations on the same object so revision 1, 2, 3 are emitted;
	// random hex IDs have >80% chance of inverting order across 10 objects without monotonic seq!
	for idx := 0; idx < 10; idx++ {
		payload := []byte(fmt.Sprintf("outbox-order-%d", idx))
		o := h.object(t, fmt.Sprintf("ord-%d", idx), payload)
		h.ingest(t, o.ID, payload)
		if _, err := h.s.Delete(h.ctx, h.actor, o.ID, fmt.Sprintf("del-%d", idx), o.Revision); err != nil {
			t.Fatal(err)
		}
		h.run(t)
	}

	events, err := h.repo.PendingEvents(h.ctx, 100)
	if err != nil || len(events) != 41 {
		t.Fatalf("expected 41 pending events, got %d err=%v", len(events), err)
	}
	lastRev := map[string]int64{}
	for idx, ev := range events {
		if idx > 0 && ev.Sequence <= events[idx-1].Sequence {
			t.Fatalf("outbox sequence not strictly ascending: %d <= %d", ev.Sequence, events[idx-1].Sequence)
		}
		if ev.Data.Revision <= lastRev[ev.Subject] {
			t.Fatalf("outbox broke per-subject revision order for %s: got rev %d after %d", ev.Subject, ev.Data.Revision, lastRev[ev.Subject])
		}
		lastRev[ev.Subject] = ev.Data.Revision
	}

	// Verify cursor + blocked subject exclusion prevents head-of-line starvation.
	blockedSubject := events[1].Subject
	filtered, err := h.repo.PendingEventsAfter(h.ctx, 10, events[0].Sequence, []string{blockedSubject})
	if err != nil || len(filtered) != 10 {
		t.Fatalf("PendingEventsAfter cursor/exclusion failed: len=%d err=%v", len(filtered), err)
	}
	for _, ev := range filtered {
		if ev.Subject == blockedSubject || ev.Sequence <= events[0].Sequence {
			t.Fatalf("PendingEventsAfter returned excluded/stale event: %+v", ev)
		}
	}
}

func TestOutboxUpgradePreservesPendingRevisions(t *testing.T) {
	h := harnessFor(t)
	// The old layout permits heap order to differ from stream order (e.g. after a restore).
	_, err := h.admin.Exec(`ALTER TABLE storage.outbox DROP COLUMN seq;
        INSERT INTO storage.outbox(id,data,delivered) VALUES
        ('c','{"subject":"object/test","id":"c","data":{"revision":3}}',false),
        ('b','{"subject":"object/test","id":"b","data":{"revision":2}}',false),
        ('a','{"subject":"object/test","id":"a","data":{"revision":1}}',true)`)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := h.admin.Exec(postgres.Schema); err != nil {
			t.Fatal(err)
		}
		events, err := h.repo.PendingEvents(h.ctx, 10)
		if err != nil || len(events) != 2 {
			t.Fatal(events, err)
		}
		if events[0].Data.Revision != 2 || events[1].Data.Revision != 3 || events[1].Sequence <= events[0].Sequence {
			t.Fatalf("upgraded revisions %d,%d; seq %d,%d", events[0].Data.Revision, events[1].Data.Revision, events[0].Sequence, events[1].Sequence)
		}
	}
	before, err := h.repo.PendingEvents(h.ctx, 10)
	if err != nil || len(before) != 2 {
		t.Fatal(before, err)
	}
	h.instance(t, "after-upgrade", "platform", "platform", 4096)
	tail, err := h.repo.PendingEventsAfter(h.ctx, 10, before[1].Sequence, nil)
	if err != nil || len(tail) != 1 || tail[0].Subject != "instance/after-upgrade" {
		t.Fatalf("new event missing after backfill cursor: %+v %v", tail, err)
	}

}

func TestObjectWithOnlyDeletedHistoryReplicasCompletesDeletion(t *testing.T) {
	h := harnessFor(t)
	h.instance(t, "contrib-only", "owner-1", "contributor", 1024)
	data := []byte("public-then-restricted")

	// Case 1: explicit Delete on object whose sole historical replica is already "deleted".
	o1 := h.object(t, "obj-del-history", data)
	h.ingest(t, o1.ID, data)
	moved, err := h.s.ChangeProtection(h.ctx, h.actor, o1.ID, "restrict-1", o1.Revision, storage.Protection{Class: "internal", Scope: "school-a"})
	if err != nil {
		t.Fatal(err)
	}
	h.run(t) // cleans up old incompatible replica -> r.State == "deleted"
	deleted, err := h.s.Delete(h.ctx, h.actor, o1.ID, "delete-1", moved.Revision)
	if err != nil || deleted.State != "deleted" {
		t.Fatalf("object with only deleted replicas stuck in %q (err=%v)", deleted.State, err)
	}

	// Case 2: 24-hour unreferenced expiry in Reconcile on object whose sole historical replica is "deleted".
	o2 := h.object(t, "obj-exp-history", data)
	h.ingest(t, o2.ID, data)
	if _, err = h.s.ChangeProtection(h.ctx, h.actor, o2.ID, "restrict-2", o2.Revision, storage.Protection{Class: "internal", Scope: "school-a"}); err != nil {
		t.Fatal(err)
	}
	h.run(t)
	h.clock.Add(25 * time.Hour)
	h.reconcile(t)
	expired, err := h.s.Status(h.ctx, h.actor, o2.ID)
	if err != nil || expired.State != "deleted" {
		t.Fatalf("expired object with only deleted replicas stuck in %q (err=%v)", expired.State, err)
	}
}

func TestProtectionAuditUsesCommittedSchool(t *testing.T) {
	h := harnessFor(t)
	i := h.instance(t, "audit-race", "platform", "platform", 4096)
	data := []byte("audit race content")
	shared := sharedCreate(t, h, "shared-school", sharedRequest(data))
	h.ingest(t, shared.ID, data)
	next := storage.Protection{Class: "public", Scope: "school-b", Public: true}
	if _, err := h.s.ChangeProtection(h.ctx, h.actor, shared.ID, "request-b", shared.Revision, next); !errors.Is(err, storage.ErrCapacity) {
		t.Fatalf("copy without destination: %v", err)
	}
	school := func(target, action string) string {
		t.Helper()
		var s string
		if err := h.db.QueryRow("SELECT audit_school FROM storage.audit WHERE audit_target=$1 AND audit_action=$2", target, action).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	if got := school(shared.ID, "storage.content.protection.requested.v1"); got != "school-a" {
		t.Errorf("pending move belongs to %s", got)
	}
	i.Admissions = append(i.Admissions, storage.Admission{Class: "public", Scope: "school-b", Plaintext: true, ExpiresAt: i.ExpiresAt})
	// Refresh the instance revision and counters before adding the second school.
	current, err := h.s.Instances(h.ctx, h.actor, 100, "")
	if err != nil {
		t.Fatal(err)
	}
	updated := current[0]
	updated.Admissions = i.Admissions
	if _, err = h.s.UpdateInstance(h.ctx, h.actor, "admit-b", updated); err != nil {
		t.Fatal(err)
	}
	o := h.object(t, "object-school", data)
	h.ingest(t, o.ID, data)
	h.provider.mu.Lock()
	for id := range h.provider.files[i.ID] {
		h.provider.files[i.ID][id] = []byte("incomplete")
	}
	h.provider.mu.Unlock()
	h.provider.readStarted = make(chan struct{}, 1)
	wait := make(chan struct{})
	h.provider.readWait = wait
	result := make(chan error, 1)
	go func() { result <- h.s.ReviewDownload(h.ctx, h.actor, o.ID, io.Discard) }()
	select {
	case <-h.provider.readStarted:
	case <-time.After(5 * time.Second):
		close(wait)
		t.Fatal("read did not start")
	}
	_, err = h.s.ChangeProtection(h.ctx, h.actor, o.ID, "move-before-corruption", o.Revision, next)
	close(wait)
	downloadErr := <-result
	if err != nil || downloadErr == nil {
		t.Fatalf("move=%v download=%v", err, downloadErr)
	}
	if got := school(o.ID, "storage.replica.corrupt.v1"); got != "school-b" {
		t.Fatalf("committed corruption belongs to %s", got)
	}
}
func TestOutboxDeliveryResumesOlderCommittedAndExcludedEvents(t *testing.T) {
	h := harnessFor(t)
	// Allocate an older sequence in an open transaction. The other subject
	// commits independently and is acknowledged before the first becomes visible.
	tx, err := h.admin.BeginTx(h.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`INSERT INTO storage.outbox(id,data) VALUES('late','{"id":"late","subject":"object/late"}')`); err != nil {
		t.Fatal(err)
	}
	if _, err = h.admin.Exec(`INSERT INTO storage.outbox(id,data) VALUES('blocked','{"id":"blocked","subject":"object/blocked"}'),('ready','{"id":"ready","subject":"object/ready"}')`); err != nil {
		t.Fatal(err)
	}
	first, err := h.repo.PendingEventsExcluding(h.ctx, 10, []string{"object/blocked"})
	if err != nil || len(first) != 1 || first[0].ID != "ready" {
		t.Fatal(first, err)
	}
	if err = h.repo.AcknowledgeEvent(h.ctx, first[0].ID); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	next, err := h.repo.PendingEvents(h.ctx, 10)
	if err != nil || len(next) != 2 || next[0].ID != "late" || next[1].ID != "blocked" {
		t.Fatal(next, err)
	}
}
