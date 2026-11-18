package storage_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	storage "github.com/StuHelper/stuhelper-storage"
	"github.com/StuHelper/stuhelper-storage/executor"
)

func TestCrossComponentConfigurationValidation(t *testing.T) {
	h := harnessFor(t)

	// 1. 1 GiB MaxObjectSize at 16 MiB/s AccountBytesPerSecond requires 128s (write + verify readback); 1m Lease must be rejected.
	_, err := storage.New(h.repo, h.auth, h.provider, h.provider, storage.Config{
		Clock:                 h.clock.Now,
		MaxObjectSize:         1 << 30,
		TemporaryDirectory:    t.TempDir(),
		ParallelTransfers:     1,
		Lease:                 time.Minute,
		VerificationAge:       time.Hour,
		QuotaValidity:         5 * time.Minute,
		MaxAttempts:           3,
		BytesPerSecond:        64 << 20,
		AccountBytesPerSecond: 16 << 20,
	})
	if !errors.Is(err, storage.ErrInput) || !strings.Contains(err.Error(), "2m8s") {
		t.Fatalf("expected ErrInput citing 2m8s minimum transfer duration, got %v", err)
	}

	// Also reject when aggregate BytesPerSecond is the bottleneck (8 MiB/s -> 256s > 3m).
	_, err = storage.New(h.repo, h.auth, h.provider, h.provider, storage.Config{
		Clock:                 h.clock.Now,
		MaxObjectSize:         1 << 30,
		TemporaryDirectory:    t.TempDir(),
		ParallelTransfers:     1,
		Lease:                 3 * time.Minute,
		VerificationAge:       time.Hour,
		QuotaValidity:         5 * time.Minute,
		MaxAttempts:           3,
		BytesPerSecond:        8 << 20,
		AccountBytesPerSecond: 16 << 20,
	})
	if !errors.Is(err, storage.ErrInput) {
		t.Fatalf("expected ErrInput when aggregate BytesPerSecond makes lease insufficient, got %v", err)
	}

	// Self-consistent 3m Lease for 1 GiB @ 16 MiB/s is accepted.
	svc, err := storage.New(h.repo, h.auth, h.provider, h.provider, storage.Config{
		Clock:                 h.clock.Now,
		MaxObjectSize:         1 << 30,
		TemporaryDirectory:    t.TempDir(),
		ParallelTransfers:     1,
		Lease:                 3 * time.Minute,
		VerificationAge:       time.Hour,
		QuotaValidity:         5 * time.Minute,
		MaxAttempts:           3,
		BytesPerSecond:        64 << 20,
		AccountBytesPerSecond: 16 << 20,
	})
	if err != nil {
		t.Fatalf("valid Service config rejected: %v", err)
	}
	defer func() { _ = svc.Close(context.Background()) }()

	summary := svc.BudgetSummary()
	if summary.QuotaValidity != 5*time.Minute || summary.MaxObjectSize != 1<<30 || summary.Lease != 3*time.Minute || summary.AccountBytesPerSecond != 16<<20 {
		t.Fatalf("unexpected BudgetSummary: %+v", summary)
	}

	// 2. QuotaValidity=5m + QuotaRefreshAhead=1m leaves a 4m refresh window; MaintenanceInterval=1h must be rejected.
	_, err = executor.New(svc, executor.Config{
		ID:                  "bad-interval",
		Principal:           h.actor,
		Workers:             1,
		PollInterval:        time.Second,
		MaintenanceInterval: 4 * time.Minute,
		MaintenanceTimeout:  10 * time.Second,
		QuotaRefreshAhead:   time.Minute,
		BatchSize:           10,
	})
	if !errors.Is(err, storage.ErrInput) {
		t.Fatalf("interval outside the one-minute advance window, got %v", err)
	}

	// QuotaRefreshAhead >= QuotaValidity must also be rejected.
	_, err = executor.New(svc, executor.Config{
		ID:                  "bad-ahead",
		Principal:           h.actor,
		Workers:             1,
		PollInterval:        time.Second,
		MaintenanceInterval: time.Minute,
		MaintenanceTimeout:  10 * time.Second,
		QuotaRefreshAhead:   5 * time.Minute,
		BatchSize:           10,
	})
	if !errors.Is(err, storage.ErrInput) {
		t.Fatalf("expected ErrInput when QuotaRefreshAhead >= QuotaValidity, got %v", err)
	}

	// A two-minute schedule fits in a four-minute advance window.
	execOK, err := executor.New(svc, executor.Config{
		ID:                  "ok-interval",
		Principal:           h.actor,
		Workers:             1,
		PollInterval:        time.Second,
		MaintenanceInterval: 2 * time.Minute,
		MaintenanceTimeout:  10 * time.Second,
		QuotaRefreshAhead:   4 * time.Minute,
		BatchSize:           10,
	})
	if err != nil || execOK == nil {
		t.Fatalf("valid Executor config rejected: %v", err)
	}
}
