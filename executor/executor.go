// Package executor runs bounded workers against the storage-owned durable queue.
// It is usable in the API process or a separate composition entry point.
package executor

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	storage "github.com/StuHelper/stuhelper-storage"
)

type Backend interface {
	RunOne(context.Context, string) (bool, error)
	Reconcile(context.Context, storage.Principal, int, string) (storage.MaintenanceResult, error)
	Instances(context.Context, storage.Principal, int, string) ([]storage.Instance, error)
	RefreshInstance(context.Context, storage.Principal, string) error
}
type Config struct {
	ID                                                    string
	Principal                                             storage.Principal
	Workers                                               int
	PollInterval, MaintenanceInterval, MaintenanceTimeout time.Duration
	BatchSize                                             int
}
type Snapshot struct {
	Running           bool
	Active            int
	Completed, Failed uint64
	LastMaintenance   time.Time
	LastError         string
}
type Executor struct {
	backend Backend
	cfg     Config
	mu      sync.Mutex
	state   Snapshot
	started bool
	stop    chan struct{}
	done    chan struct{}
	cancel  context.CancelFunc
}

func New(b Backend, cfg Config) (*Executor, error) {
	if b == nil || !cfg.Principal.Valid() || len(cfg.ID) < 1 || len(cfg.ID) > 80 || cfg.Workers < 1 || cfg.Workers > 16 || cfg.PollInterval < 50*time.Millisecond || cfg.PollInterval > time.Minute || cfg.MaintenanceInterval < time.Second || cfg.MaintenanceInterval > time.Hour || cfg.MaintenanceTimeout < time.Second || cfg.MaintenanceTimeout > time.Minute || cfg.BatchSize < 1 || cfg.BatchSize > 100 {
		return nil, storage.ErrInput
	}
	for _, c := range cfg.ID {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return nil, storage.ErrInput
		}
	}
	return &Executor{backend: b, cfg: cfg, stop: make(chan struct{}), done: make(chan struct{})}, nil
}
func (e *Executor) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.started {
		return storage.ErrConflict
	}
	e.started = true
	e.state.Running = true
	work, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	var wg sync.WaitGroup
	for n := 0; n < e.cfg.Workers; n++ {
		wg.Add(1)
		go func(n int) { defer wg.Done(); e.worker(work, fmt.Sprintf("%s-%d", e.cfg.ID, n)) }(n)
	}
	wg.Add(1)
	go func() { defer wg.Done(); e.maintenance(work) }()
	go func() {
		wg.Wait()
		cancel()
		e.mu.Lock()
		e.state.Running = false
		e.mu.Unlock()
		close(e.done)
	}()
	return nil
}
func (e *Executor) Snapshot() Snapshot { e.mu.Lock(); defer e.mu.Unlock(); return e.state }
func (e *Executor) stopping() bool {
	select {
	case <-e.stop:
		return true
	default:
		return false
	}
}
func (e *Executor) wait(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return !e.stopping()
	case <-e.stop:
		return false
	case <-ctx.Done():
		return false
	}
}
func (e *Executor) worker(ctx context.Context, id string) {
	backoff := e.cfg.PollInterval
	for !e.stopping() {
		e.mu.Lock()
		if e.stopping() {
			e.mu.Unlock()
			return
		}
		e.state.Active++
		e.mu.Unlock()
		worked, err := e.backend.RunOne(ctx, id)
		e.mu.Lock()
		e.state.Active--
		if worked && err == nil {
			e.state.Completed++
		}
		if err != nil {
			e.state.Failed++
			e.state.LastError = code(err)
		}
		e.mu.Unlock()
		// Empty queues and failures are polled with a fixed lower bound.
		if !worked || err != nil {
			if !e.wait(ctx, backoff) {
				return
			}
		}
		if err != nil {
			backoff = min(30*time.Second, backoff*2)
		} else {
			backoff = e.cfg.PollInterval
		}
	}
}
func (e *Executor) maintenance(ctx context.Context) {
	cursor := ""
	instanceCursor := ""
	for !e.stopping() {
		work, cancel := context.WithTimeout(ctx, e.cfg.MaintenanceTimeout)
		result, err := e.backend.Reconcile(work, e.cfg.Principal, e.cfg.BatchSize, cursor)
		if err == nil || result.NextCursor != "" {
			cursor = result.NextCursor
		}
		// Refresh one account per cycle to spread provider requests over time.
		instances, listErr := e.backend.Instances(work, e.cfg.Principal, 1, instanceCursor)
		if listErr == nil && len(instances) > 0 {
			i := instances[0]
			instanceCursor = i.ID
			if i.Authorized && i.State != "revoked" && i.ExpiresAt.After(time.Now()) && time.Until(i.QuotaExpiresAt) < time.Minute {
				listErr = e.backend.RefreshInstance(work, e.cfg.Principal, i.ID)
			}
		} else if listErr == nil {
			instanceCursor = ""
		}
		cancel()
		e.mu.Lock()
		if err == nil && listErr == nil {
			e.state.LastMaintenance = time.Now()
		} else {
			if err == nil {
				err = listErr
			}
			e.state.LastError = code(err)
		}
		e.mu.Unlock()
		if !e.wait(ctx, e.cfg.MaintenanceInterval) {
			return
		}
	}
}

// Stop stops polling first and lets in-flight jobs finish until the caller's
// deadline. On expiry it cancels I/O; Done closes after cleanup actually exits.
func (e *Executor) Stop(ctx context.Context) error {
	e.mu.Lock()
	if !e.started {
		e.mu.Unlock()
		return nil
	}
	if !e.stopping() {
		close(e.stop)
	}
	e.mu.Unlock()
	select {
	case <-e.done:
		return nil
	case <-ctx.Done():
		e.cancel()
		return ctx.Err()
	}
}
func (e *Executor) Done() <-chan struct{} { return e.done }
func code(err error) string {
	switch {
	case errors.Is(err, storage.ErrDenied):
		return "permission_denied"
	case errors.Is(err, storage.ErrCapacity):
		return "capacity_unavailable"
	case errors.Is(err, storage.ErrStale):
		return "stale_operation"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	default:
		return "operation_unavailable"
	}
}
