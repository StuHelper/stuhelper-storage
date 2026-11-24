package storage_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/StuHelper/stuhelper-storage/storagetest"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	storage "github.com/StuHelper/stuhelper-storage"
	protocol "github.com/StuHelper/stuhelper-storage-bhpan"
	"github.com/StuHelper/stuhelper-storage/custody"
	"github.com/StuHelper/stuhelper-storage/drivers/bhpan"
	"github.com/StuHelper/stuhelper-storage/postgres"
	"github.com/jackc/pgx/v5"
)

type recordingObserver struct {
	mu    sync.Mutex
	items []storage.Diagnostic
}

func (o *recordingObserver) Observe(d storage.Diagnostic) {
	o.mu.Lock()
	o.items = append(o.items, d)
	o.mu.Unlock()
}

func (o *recordingObserver) snapshot() []storage.Diagnostic {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]storage.Diagnostic, len(o.items))
	copy(out, o.items)
	return out
}

type failingBHpanClient struct {
	failUpload error
}

func (f *failingBHpanClient) Identity(context.Context) (protocol.Identity, error) {
	return protocol.Identity{ID: "uid-obs-1"}, nil
}
func (f *failingBHpanClient) Libraries(context.Context) ([]protocol.Library, error) {
	return []protocol.Library{{ID: "gns://lib-obs", Type: "user_doc_lib"}}, nil
}
func (f *failingBHpanClient) Quota(context.Context) (protocol.Quota, error) {
	return protocol.Quota{Allocated: 1 << 30}, nil
}
func (f *failingBHpanClient) List(context.Context, string) (protocol.Directory, error) {
	return protocol.Directory{}, nil
}
func (f *failingBHpanClient) CreateDirectory(_ context.Context, parent, _ string) (string, error) {
	return parent + "/root-obs", nil
}
func (f *failingBHpanClient) FileInfo(context.Context, string) (protocol.FileMetadata, error) {
	return protocol.FileMetadata{}, protocol.ErrNotFound
}
func (f *failingBHpanClient) BeginUpload(context.Context, string, string, int64) (protocol.Upload, error) {
	return protocol.Upload{}, f.failUpload
}
func (f *failingBHpanClient) WriteUpload(context.Context, protocol.Upload, io.Reader) (string, error) {
	return "", protocol.ErrUnavailable
}
func (f *failingBHpanClient) FinishUpload(context.Context, string, string) error {
	return protocol.ErrUnavailable
}
func (f *failingBHpanClient) Download(context.Context, string, io.Writer) (int64, error) {
	return 0, protocol.ErrUnavailable
}
func (f *failingBHpanClient) Delete(context.Context, string) error { return protocol.ErrUnavailable }
func (f *failingBHpanClient) RecycleBin(context.Context, string, int, int) (protocol.Directory, error) {
	return protocol.Directory{}, nil
}
func (f *failingBHpanClient) Purge(context.Context, string) error { return protocol.ErrUnavailable }
func (f *failingBHpanClient) Close()                              {}

type gatingReader struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	data    []byte
	offset  int
}

func (g *gatingReader) Read(p []byte) (int, error) {
	g.once.Do(func() { close(g.entered) })
	<-g.release
	if g.offset >= len(g.data) {
		return 0, io.EOF
	}
	n := copy(p, g.data[g.offset:])
	g.offset += n
	return n, nil
}

func TestObservabilitySanitizedDiagnosticsRuntimeMetricsAndOutboxNotify(t *testing.T) {
	obs := &recordingObserver{}
	h := harnessFor(t, func(cfg *storage.Config) {
		cfg.Observer = obs
		cfg.BytesPerSecond = 512 << 10
		cfg.AccountBytesPerSecond = 512 << 10
		cfg.ParallelTransfers = 3
	})
	h.repo.Observer = obs

	// 1. EmitDiagnostic scrubs any URL, SQL text, credential or out-of-range HTTP status.
	storage.EmitDiagnostic(obs, storage.Diagnostic{
		Component:  "https://bhpan.buaa.edu.cn/secret?token=TopSecretValue",
		Operation:  "SELECT * FROM secret WHERE password='TopSecretValue'",
		ObjectID:   "obj/with/slash",
		JobID:      "password=TopSecretValue",
		Category:   "raw transport error: TopSecretValue",
		HTTPStatus: 9999,
	})
	first := obs.snapshot()
	if len(first) != 1 || first[0].Component != "redacted" || first[0].Operation != "redacted" || first[0].ObjectID != "redacted" || first[0].JobID != "redacted" || first[0].Category != "redacted" || first[0].HTTPStatus != 0 {
		t.Fatalf("unsafe diagnostic was not scrubbed: %+v", first)
	}

	// 2. PostgreSQL foreign-key error emits only 5-char SQLSTATE, never table/constraint details.
	_ = h.repo.Transaction(h.ctx, func(tx storage.Transaction) error {
		return tx.SaveReplica(storage.Replica{ID: "orphan-rep", ObjectID: "missing-obj", InstanceID: "missing-inst", State: "pending"})
	})
	foundPG := false
	for _, d := range obs.snapshot() {
		if d.Component == "postgres" && d.Category == "sqlstate_23503" {
			foundPG = true
		}
	}
	if !foundPG {
		t.Fatalf("expected sanitized postgres sqlstate_23503 diagnostic, got %+v", obs.snapshot())
	}

	// 3. BHpan Pool observer captures sanitized operation, category and HTTP status 502.
	pool := bhpan.NewPool()
	defer pool.Close()
	pool.SetObserver(obs)
	bhInst, err := pool.Provision(h.ctx, "cred-obs-1", 1, &failingBHpanClient{
		failUpload: &protocol.Error{Operation: "begin-upload", Status: 502, Kind: protocol.ErrUnavailable},
	}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	_, err = pool.Write(h.ctx, bhInst, strings.Repeat("a", 32), 4, bytes.NewReader([]byte("test")), func(storage.Locator) error { return nil })
	if !errors.Is(err, storage.ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable, got %v", err)
	}
	foundBH := false
	for _, d := range obs.snapshot() {
		if d.Component == "bhpan" && d.Operation == "begin-upload" && d.Category == "bhpan_unavailable" && d.HTTPStatus == 502 {
			foundBH = true
		}
	}
	if !foundBH {
		t.Fatalf("expected bhpan 502 diagnostic, got %+v", obs.snapshot())
	}

	// 4. Custody observer records sanitized failure code without exposing password payload.
	custodyAuth := &custodyAuth{}
	student := storage.Principal{Issuer: "test-issuer", Subject: "student-obs"}
	cProv := &custodyProvider{h: h}
	cProv.failCommit.Store(true)
	cSvc, err := custody.New(&postgres.CustodyRepository{Repository: h.repo}, custodyAuth, h.s, cProv, custody.Config{
		Actor:        h.actor,
		Policy:       custody.Policy{Version: "custody-v1", Digest: strings.Repeat("b", 64), URL: "https://example.invalid/custody", MaxTermSeconds: 86400 * 30},
		PublicScopes: []string{"school-a"},
		Clock:        h.clock.Now,
		Timeout:      time.Minute,
		Observer:     obs,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = cSvc.Submit(h.ctx, student, "", "11111111-1111-4111-8111-111111111111", custody.Request{
		Adapter:    "bhpan",
		Credential: json.RawMessage(`{"username":"u1","password":"UltraSecretPassword99"}`),
		Until:      h.clock.Now().Add(24 * time.Hour),
		Consent:    custody.Consent{Accepted: true, Version: "custody-v1", Digest: strings.Repeat("b", 64)},
	})
	rawObs, _ := json.Marshal(obs.snapshot())
	if strings.Contains(string(rawObs), "UltraSecretPassword99") || strings.Contains(string(rawObs), "TopSecretValue") {
		t.Fatalf("observer leaked secret: %s", rawObs)
	}
	foundCustody := false
	for _, d := range obs.snapshot() {
		if d.Component == "custody" && d.Operation == "execute" && d.Category == "dependency_unavailable" {
			foundCustody = true
		}
	}
	if !foundCustody {
		t.Fatalf("expected custody diagnostic, got %+v", obs.snapshot())
	}

	// 5. RuntimeMetrics accurately tracks active transfer slots, staging bytes and pacer waits.
	var dbName string
	if err := h.db.QueryRowContext(h.ctx, `SELECT current_database()`).Scan(&dbName); err != nil {
		t.Fatal(err)
	}
	listenConn, err := pgx.Connect(h.ctx, os.Getenv("STUHELPER_STORAGE_TEST_DSN")+" dbname="+dbName+" user=storage_test_runtime")
	if err != nil {
		t.Fatal(err)
	}
	defer listenConn.Close(context.Background())
	if _, err := listenConn.Exec(h.ctx, `LISTEN storage_outbox`); err != nil {
		t.Fatal(err)
	}

	// Rolled-back transaction must NOT emit a PostgreSQL notification.
	_ = h.repo.Transaction(h.ctx, func(tx storage.Transaction) error {
		if e := tx.Event(storage.Event{ID: "rollback-evt", Type: "storage.object.created", ObjectID: "rollback-obj", Revision: 1, Time: h.clock.Now(), Actor: h.actor}); e != nil {
			return e
		}
		return errors.New("abort")
	})
	quietCtx, quietCancel := context.WithTimeout(h.ctx, 120*time.Millisecond)
	_, err = listenConn.WaitForNotification(quietCtx)
	quietCancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("rolled-back transaction delivered notification: %v", err)
	}

	// Clear any prior outbox events before verifying traceparent/schoolid + LISTEN wakeup.
	prior, err := h.repo.PendingEvents(h.ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range prior {
		if err := h.repo.AcknowledgeEvent(h.ctx, ev.ID); err != nil {
			t.Fatal(err)
		}
	}

	traceVal := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	tracedCtx := storage.WithTraceParent(h.ctx, traceVal)
	inst, err := storagetest.RegisterContribution(tracedCtx, h.s, h.actor, "reg-obs-1", storage.Instance{
		ID:                 "inst-obs-1",
		Adapter:            "test",
		AccountDomain:      "alias",
		OwnerDomain:        "plat",
		Ownership:          "contributor",
		CredentialRef:      "inst-obs-1",
		CredentialRevision: 1,
		Root:               "isolated",
		State:              "active",
		Authorized:         true,
		Limit:              1 << 20,
		ExpiresAt:          h.clock.Now().Add(24 * time.Hour),
		Admissions:         []storage.Admission{{Class: "public", Scope: "school-a", Plaintext: true, ExpiresAt: h.clock.Now().Add(24 * time.Hour)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 { // Enrollment and contribution activation both notify the instance stream.
		notifyCtx1, cancel1 := context.WithTimeout(h.ctx, 2*time.Second)
		n1, err := listenConn.WaitForNotification(notifyCtx1)
		cancel1()
		if err != nil || n1.Channel != "storage_outbox" || n1.Payload != "instance/"+inst.ID {
			t.Fatalf("unexpected instance notification: %+v %v", n1, err)
		}
	}

	data := bytes.Repeat([]byte("z"), 48<<10) // >32 KiB burst so pacer waits at least once
	sum := sha256.Sum256(data)
	created, err := h.s.Create(tracedCtx, h.actor, "create-obs-1", storage.CreateRequest{
		Size:       int64(len(data)),
		SHA256:     hex.EncodeToString(sum[:]),
		Protection: storage.Protection{Class: "public", Scope: "school-a", Public: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	notifyCtx2, cancel2 := context.WithTimeout(h.ctx, 2*time.Second)
	n2, err := listenConn.WaitForNotification(notifyCtx2)
	cancel2()
	if err != nil || n2.Payload != "object/"+created.ID {
		t.Fatalf("unexpected object notification: %+v %v", n2, err)
	}

	pending, err := h.repo.PendingEvents(h.ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	var sawInstance, sawObject bool
	for _, ev := range pending {
		if ev.Subject == "instance/"+inst.ID {
			sawInstance = true
			if ev.TraceParent != traceVal || ev.SchoolID != "" {
				t.Fatalf("platform instance event mismatch: traceparent=%q schoolid=%q", ev.TraceParent, ev.SchoolID)
			}
		}
		if ev.Subject == "object/"+created.ID {
			sawObject = true
			if ev.TraceParent != traceVal || ev.SchoolID != "school-a" {
				t.Fatalf("school-scoped object event mismatch: traceparent=%q schoolid=%q", ev.TraceParent, ev.SchoolID)
			}
		}
	}
	if !sawInstance || !sawObject {
		t.Fatalf("missing expected outbox events: %+v", pending)
	}

	// Invalid traceparent values are rejected cleanly.
	if got := storage.TraceParentFromContext(storage.WithTraceParent(context.Background(), "00-00000000000000000000000000000000-00f067aa0ba902b7-01")); got != "" {
		t.Fatalf("accepted all-zero trace id: %q", got)
	}

	// Verify RuntimeMetrics while transfer is in flight and after completion.
	gate := &gatingReader{entered: make(chan struct{}), release: make(chan struct{}), data: data}
	doneCh := make(chan error, 1)
	go func() {
		_, ingestErr := h.s.Ingest(h.ctx, h.actor, created.ID, "ingest-obs-1", gate)
		doneCh <- ingestErr
	}()
	<-gate.entered
	mid := h.s.RuntimeMetrics()
	if mid.ParallelTransfers != 3 || mid.ActiveTransfers != 1 || mid.StagingFiles != 1 || mid.StagingReservedBytes != int64(len(data))+1 || mid.Stopping {
		close(gate.release)
		t.Fatalf("unexpected in-flight RuntimeMetrics: %+v", mid)
	}
	close(gate.release)
	if err := <-doneCh; err != nil {
		t.Fatal(err)
	}
	after := h.s.RuntimeMetrics()
	if after.ActiveTransfers != 0 || after.StagingFiles != 0 || after.StagingReservedBytes != 0 || after.BandwidthWaits == 0 || after.BandwidthWaitNanos == 0 {
		t.Fatalf("unexpected post-transfer RuntimeMetrics: %+v", after)
	}
}
