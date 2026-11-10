package storage_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	storage "github.com/StuHelper/stuhelper-storage"
	"github.com/StuHelper/stuhelper-storage/executor"
)

func TestDisabledInstanceCannotTriggerProviderRefresh(t *testing.T) {
	for _, mode := range []string{"revoked", "unauthorized", "expired"} {
		t.Run(mode, func(t *testing.T) {
			h := harnessFor(t)
			i := h.instance(t, "account", "owner", "platform", 1024)
			if mode == "expired" {
				h.clock.Add(365 * 24 * time.Hour)
			} else {
				if mode == "revoked" {
					i.State = "revoked"
				} else {
					i.Authorized = false
				}
				if _, err := h.s.UpdateInstance(h.ctx, h.actor, "stop", i); err != nil {
					t.Fatal(err)
				}
			}
			h.provider.mu.Lock()
			before := h.provider.verifyCalls
			h.provider.mu.Unlock()
			if err := h.s.RefreshInstance(h.ctx, h.actor, i.ID); !errors.Is(err, storage.ErrDenied) {
				t.Fatalf("disabled refresh allowed: %v", err)
			}
			h.provider.mu.Lock()
			defer h.provider.mu.Unlock()
			if h.provider.verifyCalls != before {
				t.Fatal("used supplier after instance authorization ended")
			}
		})
	}
}

func TestDisabledReplicaDoesNotSchedulePeriodicVerification(t *testing.T) {
	for _, mode := range []string{"revoked", "unauthorized", "expired"} {
		t.Run(mode, func(t *testing.T) {
			h := harnessFor(t)
			h.provider.verificationClock = h.clock.Now
			first := h.instance(t, "a", "a", "platform", 1024)
			for _, id := range []string{"b", "c"} {
				h.instance(t, id, id, "platform", 1024)
			}
			data := []byte("idle instance remains idle")
			o := h.object(t, "create", data)
			h.ingest(t, o.ID, data)
			h.reconcile(t)
			h.run(t)
			h.run(t)
			switch mode {
			case "revoked":
				first.State = "revoked"
			case "unauthorized":
				first.Authorized = false
			case "expired":
				first.ExpiresAt = h.clock.Now().Add(time.Minute)
				for n := range first.Admissions {
					first.Admissions[n].ExpiresAt = first.ExpiresAt
				}
			}
			var err error
			first, err = h.s.UpdateInstance(h.ctx, h.actor, "disable", first)
			if err != nil {
				t.Fatal(err)
			}
			h.clock.Add(31 * time.Minute)
			h.reconcile(t)
			var count int
			if err = h.db.QueryRow(`SELECT count(*) FROM storage.jobs j JOIN storage.replicas r ON r.id=j.data->>'replica_id' WHERE r.instance_id='a' AND j.data->>'kind'='verify' AND j.state IN ('pending','running','blocked')`).Scan(&count); err != nil || count != 0 {
				t.Fatalf("disabled verification queued: %d %v", count, err)
			}
			h.run(t)
			h.run(t)
			out, err := h.s.Operations(h.ctx, h.actor, 100, "", "")
			if err != nil || out.Jobs.Blocked != 0 {
				t.Fatalf("idle account caused an actionable blockage: %v %+v", err, out.Jobs)
			}
			first.Authorized = true
			first.State = "active"
			first.ExpiresAt = h.clock.Now().Add(time.Hour)
			for n := range first.Admissions {
				first.Admissions[n].ExpiresAt = first.ExpiresAt
			}
			if _, err = h.s.UpdateInstance(h.ctx, h.actor, "renew", first); err != nil {
				t.Fatal(err)
			}
			h.reconcile(t)
			h.run(t)
			st, err := h.s.Status(h.ctx, h.actor, o.ID)
			if err != nil || st.Healthy != 3 {
				t.Fatalf("renewed account did not verify: %v %+v", err, st)
			}
		})
	}
}

func TestTransferAdmissionAndShutdownCancellation(t *testing.T) {
	h := harnessFor(t, func(c *storage.Config) { c.ParallelTransfers = 1 })
	for _, id := range []string{"a", "b", "c"} {
		h.instance(t, id, id, "platform", 1024)
	}
	data := []byte("shutdown download")
	o := h.object(t, "create", data)
	h.ingest(t, o.ID, data)
	h.reconcile(t)
	h.run(t)
	h.provider.readStarted = make(chan struct{}, 4)
	h.provider.readWait = make(chan struct{})
	result := make(chan error, 1)
	go func() { result <- h.s.Download(h.ctx, h.actor, o.ID, io.Discard) }()
	select {
	case <-h.provider.readStarted:
	case <-time.After(time.Second):
		t.Fatal("read not started")
	}
	if err := h.s.Download(h.ctx, h.actor, o.ID, io.Discard); !errors.Is(err, storage.ErrCapacity) {
		t.Fatalf("unbounded wait queue: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := h.s.Close(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("canceled read succeeded")
		}
	case <-ctx.Done():
		t.Fatal("I/O did not stop")
	}
	if _, err := h.s.Create(h.ctx, h.actor, "after-close", storage.CreateRequest{Size: o.Size, SHA256: o.SHA256, Protection: o.Protection}); !errors.Is(err, storage.ErrUnavailable) {
		t.Fatalf("admitted after shutdown: %v", err)
	}
	s, err := storage.New(h.repo, h.auth, h.provider, h.provider, h.cfg)
	if err != nil {
		t.Fatal("staging lock not released", err)
	}
	if err = s.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestQueueBudgetDefersReplicationAndDeletion(t *testing.T) {
	h := harnessFor(t, func(c *storage.Config) { c.MaxOutstandingJobs = 1 })
	for _, id := range []string{"a", "b", "c"} {
		h.instance(t, id, id, "platform", 1024)
	}
	data := []byte("bounded queue")
	o := h.object(t, "create", data)
	h.ingest(t, o.ID, data)
	for n := 0; n < 2; n++ {
		h.reconcile(t)
		var count int
		if err := h.db.QueryRow(`SELECT count(*) FROM storage.jobs WHERE state IN ('pending','running')`).Scan(&count); err != nil || count != 1 {
			t.Fatalf("queue=%d error=%v", count, err)
		}
		if _, err := h.s.RunOne(h.ctx, "worker"); err != nil {
			t.Fatal(err)
		}
	}
	status, err := h.s.Status(h.ctx, h.actor, o.ID)
	if err != nil || status.Healthy != 3 {
		t.Fatalf("not repaired: %+v %v", status, err)
	}
	status, err = h.s.Delete(h.ctx, h.actor, o.ID, "delete", status.Revision)
	if err != nil || status.State != "deleting" {
		t.Fatalf("queue blocked logical deletion: %v", err)
	}
	var dst bytes.Buffer
	if err := h.s.Download(h.ctx, h.actor, o.ID, &dst); !errors.Is(err, storage.ErrUnavailable) || dst.Len() != 0 {
		t.Fatal("deleting content still served")
	}
	for n := 0; n < 3; n++ {
		h.reconcile(t)
		if _, err := h.s.RunOne(h.ctx, "cleanup"); err != nil {
			t.Fatal(err)
		}
	}
	status, err = h.s.Status(h.ctx, h.actor, o.ID)
	if err != nil || status.State != "deleted" {
		t.Fatalf("deferred deletion stuck: %+v %v", status, err)
	}
}

func TestBlockedJobsKeepRetryLimit(t *testing.T) {
	h := harnessFor(t)
	h.instance(t, "a", "owner", "platform", 1024)
	data := []byte("ambiguous upload")
	o := h.object(t, "create", data)
	h.provider.lostBegin = true
	if _, err := h.s.Ingest(h.ctx, h.actor, o.ID, "upload", bytes.NewReader(data)); !errors.Is(err, storage.ErrUnknown) {
		t.Fatal(err)
	}
	for n := 0; n < 2; n++ {
		h.clock.Add(time.Minute)
		if _, err := h.s.RunOne(h.ctx, "worker"); !errors.Is(err, storage.ErrUnknown) {
			t.Fatal(err)
		}
	}
	// Binding unchanged: routine reconciliation must preserve exhaustion.
	for n := 0; n < 3; n++ {
		h.reconcile(t)
		h.clock.Add(time.Minute)
	}
	worked, err := h.s.RunOne(h.ctx, "worker")
	if err != nil || worked || h.provider.writes != 1 {
		t.Fatalf("retried blocked write: worked=%v error=%v writes=%d", worked, err, h.provider.writes)
	}
}

func TestBlockedPeriodicVerificationDoesNotRestart(t *testing.T) {
	h := harnessFor(t)
	for _, id := range []string{"a", "b", "c"} {
		h.instance(t, id, id, "platform", 1024)
	}
	data := []byte("verify retry limit")
	o := h.object(t, "create", data)
	h.ingest(t, o.ID, data)
	h.reconcile(t)
	h.run(t)
	h.clock.Add(31 * time.Minute)
	h.reconcile(t)
	h.provider.readUnavailable = true
	for attempt := 0; attempt < 3; attempt++ {
		for n := 0; n < 3; n++ {
			worked, err := h.s.RunOne(h.ctx, "verify")
			if !worked || !errors.Is(err, storage.ErrUnavailable) {
				t.Fatalf("verification: %v %v", worked, err)
			}
		}
		h.clock.Add(time.Minute)
	}
	h.reconcile(t)
	worked, err := h.s.RunOne(h.ctx, "verify")
	if worked || err != nil {
		t.Fatalf("exhausted verification restarted: %v %v", worked, err)
	}
	var blocked int
	if err := h.db.QueryRow(`SELECT count(*) FROM storage.jobs WHERE state='blocked'`).Scan(&blocked); err != nil || blocked != 3 {
		t.Fatalf("blocked=%d error=%v", blocked, err)
	}
}

func TestExecutorRestartFinishesDurableReplicas(t *testing.T) {
	h := harnessFor(t)
	for _, id := range []string{"a", "b", "c"} {
		h.instance(t, id, id, "platform", 1024)
	}
	data := []byte("restart source")
	o := h.object(t, "create", data)
	h.ingest(t, o.ID, data)
	h.reconcile(t)
	if err := h.s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	s, err := storage.New(h.repo, h.auth, h.provider, h.provider, h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	e, err := executor.New(s, executor.Config{ID: "restarted", Principal: h.actor, Workers: 2, PollInterval: 50 * time.Millisecond, MaintenanceInterval: time.Second, MaintenanceTimeout: time.Second, BatchSize: 10})
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Start(h.ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := e.Stop(ctx); err != nil {
			t.Error(err)
		}
	})
	deadline := time.Now().Add(3 * time.Second)
	for {
		st, err := s.Status(h.ctx, h.actor, o.ID)
		if err != nil {
			t.Fatal(err)
		}
		if st.Healthy == 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("restart did not recover replicas: %+v", st)
		}
		time.Sleep(10 * time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err = e.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	h.provider.mu.Lock()
	writes := h.provider.writes
	h.provider.mu.Unlock()
	if writes != 3 {
		t.Fatalf("restart duplicated uploads: %d", writes)
	}
	var dst bytes.Buffer
	if err := s.Download(h.ctx, h.actor, o.ID, &dst); err != nil || !bytes.Equal(dst.Bytes(), data) {
		t.Fatalf("restored bytes: %v", err)
	}
}
