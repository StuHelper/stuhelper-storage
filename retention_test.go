package storage_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	storage "github.com/StuHelper/stuhelper-storage"
	"github.com/StuHelper/stuhelper-storage/custody"
	"github.com/StuHelper/stuhelper-storage/executor"
	"github.com/StuHelper/stuhelper-storage/postgres"
)

func TestBoundedRetentionCleanupPreservesActiveAndUnexpiredRecords(t *testing.T) {
	h := harnessFor(t, func(c *storage.Config) { c.MaxAttempts = 1 })
	h.provider.verificationClock = h.clock.Now

	// Reject invalid retention durations.
	for _, bad := range []func(*storage.Config){
		func(c *storage.Config) { c.OutboxRetention = 30 * time.Minute },
		func(c *storage.Config) { c.JobRetention = 10 * time.Minute },
		func(c *storage.Config) { c.CustodyOperationRetention = 12 * time.Hour },
	} {
		cfg := h.cfg
		cfg.TemporaryDirectory = t.TempDir()
		bad(&cfg)
		if svc, err := storage.New(h.repo, h.auth, h.provider, h.provider, cfg); !errors.Is(err, storage.ErrInput) {
			if svc != nil {
				_ = svc.Close(h.ctx)
			}
			t.Fatalf("invalid retention config accepted: %v", err)
		}
	}

	h.instance(t, "i1", "owner-1", "platform", 4096)

	// Create two objects with ingest jobs -> produces idempotency rows, done jobs, and outbox events.
	for n := 1; n <= 2; n++ {
		data := []byte(fmt.Sprintf("retention-payload-%d", n))
		obj := h.object(t, fmt.Sprintf("ret-obj-%d", n), data)
		if _, err := h.s.Ingest(h.ctx, h.actor, obj.ID, fmt.Sprintf("ret-up-%d", n), bytes.NewReader(data)); err != nil {
			t.Fatal(err)
		}
	}

	// Create one blocked job that must NEVER be deleted by retention cleanup.
	blockedObj := h.object(t, "ret-blocked", []byte("blocked"))
	h.provider.lostBegin = true
	if _, err := h.s.Ingest(h.ctx, h.actor, blockedObj.ID, "ret-up-blocked", bytes.NewReader([]byte("blocked"))); !errors.Is(err, storage.ErrUnknown) {
		t.Fatal(err)
	}
	h.provider.lostBegin = false

	// Acknowledge two outbox events, leaving remaining outbox events undelivered.
	events, err := h.repo.PendingEvents(h.ctx, 100)
	if err != nil || len(events) < 3 {
		t.Fatalf("expected >= 3 outbox events, got %d %v", len(events), err)
	}
	for n := 0; n < 2; n++ {
		if err := h.repo.AcknowledgeEvent(h.ctx, events[n].ID); err != nil {
			t.Fatal(err)
		}
	}
	undeliveredExpected := len(events) - 2

	// Create two completed custody operations and one incomplete custody operation.
	cProv := &custodyProvider{h: h}
	cAuth := &custodyAuth{}
	cSvc, err := custody.New(&postgres.CustodyRepository{Repository: h.repo}, cAuth, h.s, cProv, custody.Config{
		Actor:        h.actor,
		Policy:       custody.Policy{Version: "custody-v1", Digest: strings.Repeat("a", 64), URL: "https://example.invalid/custody", MaxTermSeconds: 86400 * 365},
		PublicScopes: []string{"school-a"},
		Clock:        h.clock.Now,
		Timeout:      time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	user := storage.Principal{Issuer: "test-issuer", Subject: "user"}
	cReq := custody.Request{
		Adapter:    "bhpan",
		Credential: json.RawMessage(`{"mode":"local","username":"u1","password":"p1"}`),
		Until:      h.clock.Now().Add(180 * 24 * time.Hour),
		Consent:    custody.Consent{Accepted: true, Version: "custody-v1", Digest: strings.Repeat("a", 64)},
	}
	for n := 1; n <= 2; n++ {
		v, err := cSvc.Submit(h.ctx, user, "", fmt.Sprintf("60000000-0000-4000-8000-%012d", n), cReq)
		if err != nil || v.State != "ready" {
			t.Fatalf("custody submit %d: %+v %v", n, v, err)
		}
	}
	cProv.failPrepare.Store(true)
	if v, err := cSvc.Submit(h.ctx, user, "", "60000000-0000-4000-8000-000000000003", cReq); err != nil || v.State != "credentials_required" {
		t.Fatalf("incomplete custody op setup failed: %+v %v", v, err)
	}
	cProv.failPrepare.Store(false)

	countRows := func(query string) int {
		t.Helper()
		var n int
		if err := h.db.QueryRowContext(h.ctx, query).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// Authorization boundary check.
	h.auth.denied.Store(true)
	if _, err := h.s.PurgeExpired(h.ctx, h.actor, 10); !errors.Is(err, storage.ErrDenied) {
		t.Fatalf("expected ErrDenied for unauthorized PurgeExpired, got %v", err)
	}
	h.auth.denied.Store(false)

	// At t+23h: nothing has reached any retention deadline (24h, 7d, 30d, 90d).
	h.clock.Add(23 * time.Hour)
	res, err := h.s.PurgeExpired(h.ctx, h.actor, 100)
	if err != nil || res.Total() != 0 {
		t.Fatalf("premature purge removed records at 23h: %+v %v", res, err)
	}

	// At t+25h: idempotency records (>24h) expire; bounded limit=1 removes 1 per call.
	h.clock.Add(2 * time.Hour)
	firstBatch, err := h.s.PurgeExpired(h.ctx, h.actor, 1)
	if err != nil || firstBatch.Idempotency != 1 || firstBatch.DeliveredOutbox != 0 || firstBatch.CompletedJobs != 0 || firstBatch.CustodyOperations != 0 {
		t.Fatalf("unexpected 25h batch=1 result: %+v %v", firstBatch, err)
	}
	if _, err := h.s.PurgeExpired(h.ctx, h.actor, 100); err != nil {
		t.Fatal(err)
	}
	if countRows(`SELECT count(*) FROM storage.idempotency`) != 0 {
		t.Fatal("expired idempotency rows not drained")
	}

	// Add a fresh instance and object at t+25h to verify unexpired records coexist safely.
	h.instance(t, "i2", "owner-2", "platform", 4096)
	freshObj := h.object(t, "fresh-after-25h", []byte("fresh"))
	if _, err := h.s.Ingest(h.ctx, h.actor, freshObj.ID, "fresh-up", bytes.NewReader([]byte("fresh"))); err != nil {
		t.Fatal(err)
	}

	// Advance to t+8d (total): early done jobs (>7d) expire, while t+25h done job (6d23h old) and blocked job remain!
	h.clock.Add(7*24*time.Hour - time.Hour)
	jobPurge, err := h.s.PurgeExpired(h.ctx, h.actor, 100)
	if err != nil || jobPurge.CompletedJobs != 2 || jobPurge.CustodyOperations != 0 || jobPurge.DeliveredOutbox != 0 {
		t.Fatalf("unexpected 8d purge: %+v %v", jobPurge, err)
	}
	if countRows(`SELECT count(*) FROM storage.jobs WHERE state='done'`) != 1 {
		t.Fatal("unexpired done job was deleted or expired jobs remained")
	}
	if countRows(`SELECT count(*) FROM storage.jobs WHERE state='blocked'`) != 1 {
		t.Fatal("blocked job was deleted by retention cleanup")
	}

	// Advance to t+31d (total): completed custody operations (>30d) expire, incomplete custody operation remains; outbox (31d < 90d) remains.
	h.clock.Add(23 * 24 * time.Hour)
	custodyPurge, err := h.s.PurgeExpired(h.ctx, h.actor, 100)
	if err != nil || custodyPurge.CustodyOperations != 2 || custodyPurge.DeliveredOutbox != 0 {
		t.Fatalf("unexpected 31d purge: %+v %v", custodyPurge, err)
	}
	if countRows(`SELECT count(*) FROM storage.custody_operations`) != 1 {
		t.Fatal("incomplete custody operation was removed or completed ones remained")
	}

	// Advance to t+91d (total) and run Executor with BatchSize=1 to verify automatic multi-page sweep drains both delivered outbox events while preserving undelivered events.
	h.clock.Add(60 * 24 * time.Hour)
	exec, err := executor.New(h.s, executor.Config{
		Clock:               h.clock.Now,
		ID:                  "retention-worker",
		Principal:           h.actor,
		Workers:             1,
		PollInterval:        50 * time.Millisecond,
		MaintenanceInterval: time.Hour,
		MaintenanceTimeout:  5 * time.Second,
		BatchSize:           1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := exec.Start(h.ctx); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !exec.Snapshot().LastMaintenance.IsZero() {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	stopCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := exec.Stop(stopCtx); err != nil {
		t.Fatal(err)
	}
	if countRows(`SELECT count(*) FROM storage.outbox WHERE delivered`) != 0 {
		t.Fatal("executor maintenance sweep did not purge expired delivered outbox events")
	}
	// Undelivered outbox events (original undelivered + custody/fresh events) must all remain intact.
	if countRows(`SELECT count(*) FROM storage.outbox WHERE NOT delivered`) < undeliveredExpected {
		t.Fatal("retention cleanup deleted undelivered outbox events")
	}
}
