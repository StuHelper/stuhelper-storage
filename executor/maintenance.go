package executor

import (
	"context"
	"errors"
	"time"

	storage "github.com/StuHelper/stuhelper-storage"
)

const (
	MaintenanceSweepTimeout = 5 * time.Minute
	maxMaintenancePages     = 1000
	quotaRetryInterval      = time.Minute
	maxQuotaRetries         = 3
)

var errMaintenanceIncomplete = errors.New("storage maintenance sweep incomplete")

type RetentionBackend interface {
	PurgeExpired(context.Context, storage.Principal, int) (storage.RetentionResult, error)
}

type maintenancePosition struct {
	objects, instances string
	quotaRetries       map[string]quotaRetry
}

type quotaRetry struct {
	due       time.Time
	attempted int
}

// A maintenance interval separates sweeps, not individual accounts or pages.
// Each page has its own deadline; the outer deadline and page budget bound the
// whole sweep. On exhaustion the next sweep resumes from the retained cursors.
func (e *Executor) maintenanceSweep(ctx context.Context, position *maintenancePosition) error {
	cleaner, hasRetention := e.backend.(RetentionBackend)
	objectsDone, instancesDone, retentionDone := false, false, !hasRetention
	var firstErr error
	for page := 0; page < maxMaintenancePages; page++ {
		if err := ctx.Err(); err != nil {
			return errors.Join(firstErr, err)
		}
		if e.stopping() {
			return errors.Join(firstErr, context.Canceled)
		}
		if !objectsDone {
			work, cancel := context.WithTimeout(ctx, e.cfg.MaintenanceTimeout)
			result, err := e.backend.Reconcile(work, e.cfg.Principal, e.cfg.BatchSize, position.objects)
			cancel()
			if err == nil && result.NextCursor != "" && result.NextCursor <= position.objects {
				err = errMaintenanceIncomplete
			}
			if err == nil || result.NextCursor > position.objects {
				position.objects = result.NextCursor
			}
			objectsDone = err != nil || position.objects == ""
			if err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if !instancesDone {
			var err error
			instancesDone, err = e.refreshNextInstance(ctx, position)
			if err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if !retentionDone {
			work, cancel := context.WithTimeout(ctx, e.cfg.MaintenanceTimeout)
			purged, err := cleaner.PurgeExpired(work, e.cfg.Principal, e.cfg.BatchSize)
			cancel()
			if err != nil && firstErr == nil {
				firstErr = err
			}
			retentionDone = err != nil || (purged.Idempotency < e.cfg.BatchSize && purged.DeliveredOutbox < e.cfg.BatchSize && purged.CompletedJobs < e.cfg.BatchSize && purged.CustodyOperations < e.cfg.BatchSize)
		}
		if objectsDone && instancesDone && retentionDone {
			return firstErr
		}
	}
	return errors.Join(firstErr, errMaintenanceIncomplete)
}

func (e *Executor) refreshNextInstance(ctx context.Context, position *maintenancePosition) (bool, error) {
	work, cancel := context.WithTimeout(ctx, e.cfg.MaintenanceTimeout)
	defer cancel()
	instances, err := e.backend.Instances(work, e.cfg.Principal, 1, position.instances)
	if err != nil {
		return true, err
	}
	if len(instances) == 0 {
		position.instances = ""
		return true, nil
	}
	i := instances[0]
	if i.ID <= position.instances {
		return true, errMaintenanceIncomplete
	}
	position.instances = i.ID
	delete(position.quotaRetries, i.ID)
	now := e.now()
	if i.Authorized && i.State != "revoked" && i.ExpiresAt.After(now) &&
		(i.QuotaObservation.ObservedAt.IsZero() || i.QuotaObservation.ReadFailed || i.QuotaExpiresAt.Sub(now) <= e.cfg.QuotaRefreshAhead) {
		// A failed account must not prevent the remaining accounts being checked.
		err = e.backend.RefreshInstance(work, e.cfg.Principal, i.ID)
		if retryableQuota(err) {
			if position.quotaRetries == nil {
				position.quotaRetries = make(map[string]quotaRetry)
			}
			position.quotaRetries[i.ID] = quotaRetry{due: time.Now().Add(quotaRetryInterval)}
		}
		return false, err
	}
	return false, nil
}

func retryableQuota(err error) bool {
	return err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, storage.ErrDenied) && !errors.Is(err, storage.ErrNotFound)
}

// Failed quota refreshes receive a separate budget between sweeps. Healthy
// accounts and object or retention maintenance stay on their normal cadence.
func (e *Executor) waitForMaintenance(ctx context.Context, nextSweep time.Time, position *maintenancePosition) bool {
	for time.Now().Before(nextSweep) {
		next := nextSweep
		for _, retry := range position.quotaRetries {
			if retry.due.Before(next) {
				next = retry.due
			}
		}
		if !e.wait(ctx, time.Until(next)) {
			return false
		}
		if time.Now().Before(nextSweep) {
			work, cancel := context.WithDeadline(ctx, nextSweep)
			e.retryQuotas(work, position, time.Now())
			cancel()
		}
	}
	return ctx.Err() == nil && !e.stopping()
}

func (e *Executor) retryQuotas(ctx context.Context, position *maintenancePosition, now time.Time) {
	for id, retry := range position.quotaRetries {
		if ctx.Err() != nil || e.stopping() {
			return
		}
		if retry.due.After(now) {
			continue
		}
		work, cancel := context.WithTimeout(ctx, e.cfg.MaintenanceTimeout)
		err := e.backend.RefreshInstance(work, e.cfg.Principal, id)
		cancel()
		retry.attempted++
		if retry.attempted == maxQuotaRetries || !retryableQuota(err) {
			delete(position.quotaRetries, id)
			continue
		}
		retry.due = time.Now().Add(quotaRetryInterval << retry.attempted)
		position.quotaRetries[id] = retry
	}
}
