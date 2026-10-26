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
