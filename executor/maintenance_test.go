package executor

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	storage "github.com/StuHelper/stuhelper-storage"
)

type sweepBackend struct {
	mu           sync.Mutex
	now          time.Time
	objectPages  []string
	accounts     []string
	refreshed    []string
	failRefresh  string
	endlessPages bool
	block        bool
	entered      chan struct{}
}

func (*sweepBackend) RunOne(context.Context, string) (bool, error) { return false, nil }
func (b *sweepBackend) Reconcile(ctx context.Context, _ storage.Principal, limit int, after string) (storage.MaintenanceResult, error) {
	if b.block {
		close(b.entered)
		<-ctx.Done()
		return storage.MaintenanceResult{}, ctx.Err()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if limit != 2 {
		return storage.MaintenanceResult{}, storage.ErrInput
	}
	b.objectPages = append(b.objectPages, after)
	if b.endlessPages {
		return storage.MaintenanceResult{NextCursor: fmt.Sprintf("object-%06d", len(b.objectPages))}, nil
	}
	switch after {
	case "":
		return storage.MaintenanceResult{NextCursor: "object-2"}, nil
	case "object-2":
		return storage.MaintenanceResult{NextCursor: "object-4"}, nil
	default:
		return storage.MaintenanceResult{}, nil
	}
}
func (b *sweepBackend) Instances(_ context.Context, _ storage.Principal, limit int, after string) ([]storage.Instance, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if limit != 1 {
		return nil, storage.ErrInput
	}
	for _, id := range []string{"account-1", "account-2", "account-3"} {
		if id > after {
			b.accounts = append(b.accounts, id)
			return []storage.Instance{{ID: id, Authorized: true, State: "active", ExpiresAt: b.now.Add(48 * time.Hour), QuotaExpiresAt: b.now.Add(6 * time.Hour)}}, nil
		}
	}
	return nil, nil
}
func (b *sweepBackend) RefreshInstance(_ context.Context, _ storage.Principal, id string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refreshed = append(b.refreshed, id)
	if id == b.failRefresh {
		return storage.ErrUnavailable
	}
	return nil
}

func TestLongMaintenanceSweepVisitsAllPagesAndDueAccounts(t *testing.T) {
	for _, failed := range []string{"", "account-2"} {
		t.Run("failed-"+failed, func(t *testing.T) {
			b := &sweepBackend{now: time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC), failRefresh: failed}
			cfg := config()
			cfg.BatchSize = 2
			cfg.MaintenanceInterval = 6 * time.Hour
			cfg.QuotaRefreshAhead = 6 * time.Hour
			cfg.Clock = func() time.Time { return b.now }
			e, err := New(b, cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err = e.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { e.Stop(context.Background()) })
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				s := e.Snapshot()
				if !s.LastMaintenance.IsZero() || s.LastError != "" {
					break
				}
				time.Sleep(time.Millisecond)
			}
			if err = e.Stop(context.Background()); err != nil {
				t.Fatal(err)
			}
			if fmt.Sprint(b.objectPages) != "[ object-2 object-4]" || fmt.Sprint(b.accounts) != "[account-1 account-2 account-3]" || fmt.Sprint(b.refreshed) != "[account-1 account-2 account-3]" {
				t.Fatalf("one sweep did not cover bounded pages and all due accounts: pages=%v accounts=%v refreshes=%v", b.objectPages, b.accounts, b.refreshed)
			}
			if failed == "" && e.Snapshot().LastMaintenance.IsZero() {
				t.Fatal("successful sweep was not recorded")
			}
			if failed != "" && (e.Snapshot().LastError == "" || !e.Snapshot().LastMaintenance.IsZero()) {
				t.Fatal("failed refresh was hidden as a successful sweep")
			}
		})
	}
}

func TestLongMaintenanceSweepStopsInFlightPage(t *testing.T) {
	b := &sweepBackend{block: true, entered: make(chan struct{})}
	cfg := config()
	cfg.MaintenanceInterval = 6 * time.Hour
	e, err := New(b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	wait(t, b.entered)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err = e.Stop(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	wait(t, e.Done())
}

func TestMaintenancePageBudgetRetainsResumeCursor(t *testing.T) {
	b := &sweepBackend{now: time.Now(), endlessPages: true}
	cfg := config()
	cfg.BatchSize = 2
	e, err := New(b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Stop(context.Background()) })
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		b.mu.Lock()
		count := len(b.objectPages)
		b.mu.Unlock()
		if count > maxMaintenancePages {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if err = e.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(b.objectPages) <= maxMaintenancePages || b.objectPages[maxMaintenancePages] != fmt.Sprintf("object-%06d", maxMaintenancePages) {
		t.Fatalf("bounded sweep did not resume from its last page: %d pages", len(b.objectPages))
	}
	if !e.Snapshot().LastMaintenance.IsZero() || e.Snapshot().LastError == "" {
		t.Fatal("unfinished sweep reported success")
	}
}
