package storage_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	storage "github.com/StuHelper/stuhelper-storage"
)

func TestConfiguredQuotaValidityControlsWritesAndRefresh(t *testing.T) {
	for _, validity := range []time.Duration{0, 30 * time.Minute} {
		t.Run(validity.String(), func(t *testing.T) {
			h := harnessFor(t, func(c *storage.Config) { c.QuotaValidity = validity })
			h.provider.verificationClock = h.clock.Now
			i := h.instance(t, "quota", "quota-owner", "platform", 1024)
			expected := validity
			if expected == 0 {
				expected = 5 * time.Minute
			}
			if !i.QuotaExpiresAt.Equal(h.clock.Now().Add(expected)) {
				t.Fatal("registration ignored configured quota validity")
			}
			data := []byte("configured quota freshness")
			o := h.object(t, "quota-object", data)
			h.clock.Add(expected + time.Second)
			if _, err := h.s.Ingest(h.ctx, h.actor, o.ID, "upload", bytes.NewReader(data)); !errors.Is(err, storage.ErrCapacity) {
				t.Fatalf("expired sample admitted an upload: %v", err)
			}
			if h.provider.writes != 0 {
				t.Fatal("provider wrote with an expired quota sample")
			}
			h.provider.verificationClock = func() time.Time { return h.clock.Now().Add(-2 * time.Minute) }
			if err := h.s.RefreshInstance(h.ctx, h.actor, i.ID); !errors.Is(err, storage.ErrConflict) {
				t.Fatal("stale provider evidence accepted")
			}
			if err := h.repo.Transaction(h.ctx, func(tx storage.Transaction) error {
				current, err := tx.Instance(i.ID)
				if err == nil && (!current.QuotaExpiresAt.Equal(i.QuotaExpiresAt) || current.QuotaRevision != i.QuotaRevision) {
					t.Error("failed refresh extended quota validity")
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			h.provider.verificationClock = h.clock.Now
			if err := h.s.RefreshInstance(h.ctx, h.actor, i.ID); err != nil {
				t.Fatal(err)
			}
			if err := h.repo.Transaction(h.ctx, func(tx storage.Transaction) error {
				current, err := tx.Instance(i.ID)
				if err == nil && (!current.QuotaExpiresAt.Equal(h.clock.Now().Add(expected)) || current.QuotaRevision != i.QuotaRevision+1) {
					t.Error("refresh did not persist the configured quota window and revision")
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			h.ingest(t, o.ID, data)
			if h.provider.writes != 1 {
				t.Fatal("fresh sample did not permit exactly one upload")
			}
		})
	}
}

func TestConfiguredVerificationAgeControlsPeriodicJobs(t *testing.T) {
	for _, interval := range []time.Duration{time.Minute, 10 * time.Minute} {
		t.Run(interval.String(), func(t *testing.T) {
			h := harnessFor(t, func(c *storage.Config) { c.VerificationAge = 2 * interval })
			h.provider.verificationClock = h.clock.Now
			for _, id := range []string{"a", "b", "c"} {
				h.instance(t, id, id, "platform", 1024)
			}
			data := []byte("periodic content verification")
			o := h.object(t, "verify-object", data)
			h.ingest(t, o.ID, data)
			h.reconcile(t)
			h.run(t)
			h.run(t)
			queued := func() int {
				var count int
				if err := h.db.QueryRow(`SELECT count(*) FROM storage.jobs WHERE data->>'kind'='verify' AND state IN ('pending','running')`).Scan(&count); err != nil {
					t.Fatal(err)
				}
				return count
			}
			h.clock.Add(interval - time.Second)
			h.reconcile(t)
			if queued() != 0 {
				t.Fatal("verification queued before the configured interval")
			}
			h.clock.Add(2 * time.Second)
			h.reconcile(t)
			if queued() != 3 {
				t.Fatal("due verification did not enqueue all three replicas")
			}
			for n := 0; n < 3; n++ {
				h.run(t)
			}
			if queued() != 0 {
				t.Fatal("verified jobs remained pending")
			}
			if err := h.repo.Transaction(h.ctx, func(tx storage.Transaction) error {
				replicas, err := tx.Replicas(o.ID)
				for _, r := range replicas {
					if r.State != "healthy" || !r.VerifiedAt.Equal(h.clock.Now()) {
						t.Error("periodic verification did not refresh replica evidence")
					}
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestQuotaValidityRejectsInvalidDurations(t *testing.T) {
	h := harnessFor(t)
	for _, validity := range []time.Duration{-time.Second, time.Minute - time.Nanosecond, 24*time.Hour + time.Nanosecond} {
		cfg := h.cfg
		cfg.QuotaValidity = validity
		service, err := storage.New(h.repo, h.auth, h.provider, h.provider, cfg)
		if service != nil {
			service.Close(h.ctx)
		}
		if !errors.Is(err, storage.ErrInput) {
			t.Fatalf("invalid quota validity accepted: %s", validity)
		}
	}
}
