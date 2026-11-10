package storage_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	storage "github.com/StuHelper/stuhelper-storage"
	"github.com/StuHelper/stuhelper-storage/httpapi"
	"github.com/StuHelper/stuhelper-storage/sdk"
)

func TestOperatorInstanceCommandsFenceReplayAndPreserveCustody(t *testing.T) {
	h := harnessFor(t)
	i := h.instance(t, "instance", "platform", "platform", 1024)
	o := h.object(t, "object", []byte("data"))
	h.ingest(t, o.ID, []byte("data"))
	probes := h.provider.verifyCalls
	command := storage.InstanceCommand{Revision: i.Revision, Action: "pause"}
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			out, err := h.s.CommandInstance(h.ctx, h.actor, i.ID, "pause", command)
			if err != nil || out.State != "paused" || out.Revision != i.Revision+1 {
				t.Errorf("duplicate command: %+v %v", out, err)
			}
		})
	}
	wg.Wait()
	h.auth.denied.Store(true)
	if _, err := h.s.CommandInstance(h.ctx, h.actor, i.ID, "pause", command); !errors.Is(err, storage.ErrDenied) {
		t.Fatal("replay bypassed permission", err)
	}
	h.auth.denied.Store(false)
	command.Action = "drain"
	if _, err := h.s.CommandInstance(h.ctx, h.actor, i.ID, "pause", command); !errors.Is(err, storage.ErrConflict) {
		t.Fatal("key accepted new content", err)
	}
	if _, err := h.s.CommandInstance(h.ctx, h.actor, i.ID, "stale", command); !errors.Is(err, storage.ErrStale) {
		t.Fatal("stale revision accepted", err)
	}
	command.Revision++
	command.Action = "quota"
	low := int64(3)
	command.LimitBytes = &low
	if _, err := h.s.CommandInstance(h.ctx, h.actor, i.ID, "quota", command); !errors.Is(err, storage.ErrConflict) {
		t.Fatal("quota erased used bytes", err)
	}
	limit := int64(2048)
	command.LimitBytes = &limit
	quota, err := h.s.CommandInstance(h.ctx, h.actor, i.ID, "quota", command)
	if err != nil || quota.LimitBytes != limit || quota.UsedBytes != 4 || quota.ReservedBytes != 0 {
		t.Fatal("quota changed accounting", quota, err)
	}
	for _, action := range []string{"resume", "drain", "revoke"} {
		quota, err = h.s.CommandInstance(h.ctx, h.actor, i.ID, action, storage.InstanceCommand{Revision: quota.Revision, Action: action})
		if err != nil {
			t.Fatal(action, err)
		}
	}
	if _, err = h.s.CommandInstance(h.ctx, h.actor, i.ID, "revive", storage.InstanceCommand{Revision: quota.Revision, Action: "resume"}); !errors.Is(err, storage.ErrDenied) {
		t.Fatal("revoked account revived", err)
	}
	instances, err := h.s.Instances(h.ctx, h.actor, 100, "")
	if err != nil || instances[0].Authorized || instances[0].CredentialRef != i.CredentialRef || instances[0].ExpiresAt != i.ExpiresAt || h.provider.verifyCalls != probes {
		t.Fatal("custody changed or supplier probed", err)
	}
	var count int
	if err = h.db.QueryRowContext(h.ctx, `SELECT count(*) FROM storage.audit WHERE data->'event'->>'type'='storage.instance.pause.v1'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("audit duplicated", count, err)
	}
	if err = h.db.QueryRowContext(h.ctx, `SELECT count(*) FROM storage.outbox WHERE data->>'type'='storage.instance.pause.v1'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("outbox duplicated", count, err)
	}
}

func blockedUnknownIngest(t *testing.T, h *harness) (storage.Status, storage.JobFailure) {
	t.Helper()
	h.instance(t, "instance", "platform", "platform", 1024)
	data := []byte("uncertain write")
	o := h.object(t, "object", data)
	h.provider.lostBegin = true
	if _, err := h.s.Ingest(h.ctx, h.actor, o.ID, "ingest", bytes.NewReader(data)); !errors.Is(err, storage.ErrUnknown) {
		t.Fatal(err)
	}
	h.provider.lostBegin = false
	out, err := h.s.Operations(h.ctx, h.actor, 100, "", "")
	if err != nil || len(out.Failures) != 1 || out.Failures[0].State != "blocked" {
		t.Fatal("missing blockage", err)
	}
	return o, out.Failures[0]
}

func TestOperatorRetryPreservesUnknownWriteAndIsIdempotent(t *testing.T) {
	h := harnessFor(t, func(c *storage.Config) { c.MaxAttempts = 1 })
	o, j := blockedUnknownIngest(t, h)
	var wg sync.WaitGroup
	for range 3 {
		wg.Go(func() {
			out, err := h.s.RetryJob(h.ctx, h.actor, o.ID, j.ID, "retry", j.Generation)
			if err != nil || out.State != "pending" || out.Generation != j.Generation+1 || out.Attempts != 0 {
				t.Errorf("retry: %+v %v", out, err)
			}
		})
	}
	wg.Wait()
	if _, err := h.s.RetryJob(h.ctx, h.actor, o.ID, j.ID, "retry", j.Generation+1); !errors.Is(err, storage.ErrConflict) {
		t.Fatal("retry key changed", err)
	}
	h.auth.denied.Store(true)
	if _, err := h.s.RetryJob(h.ctx, h.actor, o.ID, j.ID, "retry", j.Generation); !errors.Is(err, storage.ErrDenied) {
		t.Fatal("retry replay bypassed permission", err)
	}
	h.auth.denied.Store(false)
	if _, err := h.s.RunOne(h.ctx, "worker"); !errors.Is(err, storage.ErrUnknown) {
		t.Fatal("unknown write bypassed reconciliation", err)
	}
	instances, err := h.s.Instances(h.ctx, h.actor, 100, "")
	if err != nil || h.provider.writes != 1 || instances[0].Reserved != o.Size {
		t.Fatal("retry duplicated remote write or released capacity", err)
	}
	if _, err = h.s.RetryJob(h.ctx, h.actor, o.ID, j.ID, "stale", j.Generation); !errors.Is(err, storage.ErrStale) {
		t.Fatal("old generation reused", err)
	}
	var count int
	if err = h.db.QueryRowContext(h.ctx, `SELECT count(*) FROM storage.audit WHERE data->'event'->>'type'='storage.job.retried.v1'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("retry audit duplicated", count, err)
	}
}

func TestOperatorRetryRejectsRevocationSupersessionAndQueueOverflow(t *testing.T) {
	for _, reason := range []string{"revoked", "expired", "superseded", "full"} {
		t.Run(reason, func(t *testing.T) {
			h := harnessFor(t, func(c *storage.Config) { c.MaxAttempts = 1; c.MaxOutstandingJobs = 1 })
			o, j := blockedUnknownIngest(t, h)
			want := storage.ErrDenied
			switch reason {
			case "revoked":
				if _, err := h.s.CommandInstance(h.ctx, h.actor, "instance", "revoke", storage.InstanceCommand{Revision: 1, Action: "revoke"}); err != nil {
					t.Fatal(err)
				}
			case "expired":
				h.clock.Add(25 * time.Hour)
			case "superseded":
				want = storage.ErrStale
				if _, err := h.s.CommandInstance(h.ctx, h.actor, "instance", "pause", storage.InstanceCommand{Revision: 1, Action: "pause"}); err != nil {
					t.Fatal(err)
				}
			case "full":
				want = storage.ErrCapacity
				if err := h.repo.Transaction(h.ctx, func(tx storage.Transaction) error {
					return tx.SaveJob(storage.Job{ID: "occupied", ObjectID: o.ID, State: "pending", AvailableAt: h.clock.Now()})
				}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := h.s.RetryJob(h.ctx, h.actor, o.ID, j.ID, "retry", j.Generation); !errors.Is(err, want) {
				t.Fatal(reason, err)
			}
			if err := h.repo.Transaction(h.ctx, func(tx storage.Transaction) error {
				current, err := tx.Job(j.ID)
				if err == nil && (current.Generation != j.Generation || current.State != "blocked" || current.Attempts != 1) {
					t.Error("denied retry changed job")
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if h.provider.writes != 1 {
				t.Fatal("denied retry called provider")
			}
		})
	}
}

func TestOperatorCommandHTTPContract(t *testing.T) {
	fixture, err := os.ReadFile("contracts/operations.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var sample sdk.Operations
	if err = json.Unmarshal(fixture, &sample); err != nil || sample.Instances[0].Revision != 1 || sample.Failures[0].Generation != 2 {
		t.Fatal("shared consumer example", err)
	}
	h := harnessFor(t, func(c *storage.Config) { c.MaxAttempts = 1 })
	o, j := blockedUnknownIngest(t, h)
	handler, err := httpapi.New(h.s, operatorAuth{}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	client, err := sdk.NewClientWithResponses(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := client.RetryStorageJobWithResponse(h.ctx, o.ID, j.ID, &sdk.RetryStorageJobParams{IdempotencyKey: "retry"}, sdk.RetryJob{Generation: j.Generation})
	if err != nil || retry.JSON200 == nil || retry.JSON200.Generation != j.Generation+1 {
		t.Fatal("retry SDK", err)
	}
	pause, err := client.CommandStorageInstanceWithResponse(h.ctx, "instance", &sdk.CommandStorageInstanceParams{IdempotencyKey: "pause"}, sdk.InstanceCommand{Revision: 1, Action: sdk.Pause})
	if err != nil || pause.JSON200 == nil || pause.JSON200.State != "paused" {
		t.Fatal("command SDK", err)
	}
	h.auth.denied.Store(true)
	pause, err = client.CommandStorageInstanceWithResponse(h.ctx, "instance", &sdk.CommandStorageInstanceParams{IdempotencyKey: "pause"}, sdk.InstanceCommand{Revision: 1, Action: sdk.Pause})
	if err != nil || pause.StatusCode() != 403 {
		t.Fatal("HTTP permission bypass", err)
	}
}

func TestOperatorRetryRecoversTransientVerificationFailure(t *testing.T) {
	h := harnessFor(t, func(c *storage.Config) { c.MaxAttempts = 1; c.VerificationAge = time.Minute })
	h.instance(t, "instance", "platform", "platform", 1024)
	o := h.object(t, "object", []byte("data"))
	h.ingest(t, o.ID, []byte("data"))
	h.clock.Add(31 * time.Second)
	h.reconcile(t)
	h.provider.readUnavailable = true
	if _, err := h.s.RunOne(h.ctx, "worker"); !errors.Is(err, storage.ErrUnavailable) {
		t.Fatal(err)
	}
	h.provider.readUnavailable = false
	out, err := h.s.Operations(h.ctx, h.actor, 100, "", "")
	if err != nil || len(out.Failures) != 1 {
		t.Fatal(err)
	}
	j := out.Failures[0]
	if _, err = h.s.RetryJob(h.ctx, h.actor, o.ID, j.ID, "retry", j.Generation); err != nil {
		t.Fatal(err)
	}
	h.run(t)
	out, err = h.s.Operations(h.ctx, h.actor, 100, "", "")
	if err != nil || len(out.Failures) != 0 || out.Jobs.Blocked != 0 || out.Objects[0].Healthy != 1 || h.provider.writes != 1 {
		t.Fatal("verification did not recover without rewriting", out, err)
	}
}
