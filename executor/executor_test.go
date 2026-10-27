package executor

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	storage "github.com/StuHelper/stuhelper-storage"
)

type testBackend struct {
	start   chan struct{}
	release chan struct{}
	calls   atomic.Int64
}

func (b *testBackend) RunOne(ctx context.Context, _ string) (bool, error) {
	b.calls.Add(1)
	b.start <- struct{}{}
	select {
	case <-b.release:
		return true, nil
	case <-ctx.Done():
		return true, ctx.Err()
	}
}
func (*testBackend) Reconcile(context.Context, storage.Principal, int, string) (storage.MaintenanceResult, error) {
	return storage.MaintenanceResult{}, nil
}
func (*testBackend) Instances(context.Context, storage.Principal, int, string) ([]storage.Instance, error) {
	return nil, nil
}
func (*testBackend) RefreshInstance(context.Context, storage.Principal, string) error { return nil }
func config() Config {
	return Config{ID: "test", Principal: storage.Principal{Issuer: "test", Subject: "worker"}, Workers: 2, PollInterval: 50 * time.Millisecond, MaintenanceInterval: time.Second, MaintenanceTimeout: time.Second, BatchSize: 10}
}
func wait(t *testing.T, c <-chan struct{}) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(time.Second):
		t.Fatal("worker did not progress")
	}
}
func TestBoundedWorkersAndGracefulStop(t *testing.T) {
	b := &testBackend{start: make(chan struct{}, 8), release: make(chan struct{})}
	e, err := New(b, config())
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	wait(t, b.start)
	wait(t, b.start)
	if e.Snapshot().Active != 2 {
		t.Fatal("unexpected worker count")
	}
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		if err := e.Stop(context.Background()); err != nil {
			t.Error(err)
		}
	}()
	deadline := time.Now().Add(time.Second)
	for !e.stopping() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	close(b.release)
	wait(t, stopped)
	if b.calls.Load() != 2 || e.Snapshot().Running || e.Snapshot().Completed != 2 {
		t.Fatal("claimed jobs after stopping")
	}
	if err = e.Start(context.Background()); !errors.Is(err, storage.ErrConflict) {
		t.Fatal("executor restarted without new identity")
	}
}
func TestStopDeadlineCancelsAndWaitsForCleanup(t *testing.T) {
	b := &testBackend{start: make(chan struct{}, 8), release: make(chan struct{})}
	e, err := New(b, config())
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	wait(t, b.start)
	wait(t, b.start)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err = e.Stop(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	wait(t, e.Done())
	if e.Snapshot().Active != 0 || e.Snapshot().LastError != "canceled" {
		t.Fatalf("bad cancellation state: %+v", e.Snapshot())
	}
}

type refreshBackend struct {
	instance  storage.Instance
	refreshes atomic.Int64
}

func (*refreshBackend) RunOne(context.Context, string) (bool, error) { return false, nil }
func (*refreshBackend) Reconcile(context.Context, storage.Principal, int, string) (storage.MaintenanceResult, error) {
	return storage.MaintenanceResult{}, nil
}
func (b *refreshBackend) Instances(context.Context, storage.Principal, int, string) ([]storage.Instance, error) {
	return []storage.Instance{b.instance}, nil
}
func (b *refreshBackend) RefreshInstance(context.Context, storage.Principal, string) error {
	b.refreshes.Add(1)
	b.instance.QuotaExpiresAt = b.instance.QuotaExpiresAt.Add(2 * time.Hour)
	return nil
}

func TestConfiguredQuotaRefreshWindowAndAuthorization(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name       string
		ahead      time.Duration
		authorized bool
		state      string
		grant      time.Duration
		want       int64
	}{
		{"default", 0, true, "active", time.Hour, 1},
		{"not-yet-due", 10 * time.Second, true, "active", time.Hour, 0},
		{"custom-window", 45 * time.Second, true, "active", time.Hour, 1},
		{"revoked", time.Minute, true, "revoked", time.Hour, 0},
		{"unauthorized", time.Minute, false, "active", time.Hour, 0},
		{"expired", time.Minute, true, "active", -time.Second, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := &refreshBackend{instance: storage.Instance{ID: "account", Authorized: tc.authorized, State: tc.state, ExpiresAt: now.Add(tc.grant), QuotaExpiresAt: now.Add(30 * time.Second)}}
			cfg := config()
			cfg.Clock = func() time.Time { return now }
			cfg.QuotaRefreshAhead = tc.ahead
			e, err := New(b, cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err = e.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { e.Stop(context.Background()) })
			deadline := time.Now().Add(time.Second)
			for e.Snapshot().LastMaintenance.IsZero() && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if err = e.Stop(context.Background()); err != nil {
				t.Fatal(err)
			}
			if !e.Snapshot().LastMaintenance.Equal(now) || b.refreshes.Load() != tc.want {
				t.Fatalf("unexpected scheduled provider calls: %d", b.refreshes.Load())
			}
		})
	}
	for _, ahead := range []time.Duration{-time.Second, time.Second - time.Nanosecond, time.Hour + time.Nanosecond} {
		cfg := config()
		cfg.QuotaRefreshAhead = ahead
		if _, err := New(&refreshBackend{}, cfg); !errors.Is(err, storage.ErrInput) {
			t.Fatal("invalid refresh window accepted")
		}
	}
}
