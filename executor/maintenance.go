package executor

import (
	"context"
	"errors"
)

const maxMaintenancePages = 1000

var errMaintenanceIncomplete = errors.New("storage maintenance sweep incomplete")

type maintenancePosition struct {
	objects, instances string
}

// A maintenance interval separates sweeps, not individual accounts or pages.
// Each page has its own deadline; the outer deadline and page budget bound the
// whole sweep. On exhaustion the next sweep resumes from the retained cursors.
func (e *Executor) maintenanceSweep(ctx context.Context, position *maintenancePosition) error {
	objectsDone, instancesDone := false, false
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
			instancesDone, err = e.refreshNextInstance(ctx, &position.instances)
			if err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if objectsDone && instancesDone {
			return firstErr
		}
	}
	return errors.Join(firstErr, errMaintenanceIncomplete)
}

func (e *Executor) refreshNextInstance(ctx context.Context, cursor *string) (bool, error) {
	work, cancel := context.WithTimeout(ctx, e.cfg.MaintenanceTimeout)
	defer cancel()
	instances, err := e.backend.Instances(work, e.cfg.Principal, 1, *cursor)
	if err != nil {
		return true, err
	}
	if len(instances) == 0 {
		*cursor = ""
		return true, nil
	}
	i := instances[0]
	if i.ID <= *cursor {
		return true, errMaintenanceIncomplete
	}
	*cursor = i.ID
	now := e.now()
	if i.Authorized && i.State != "revoked" && i.ExpiresAt.After(now) && i.QuotaExpiresAt.Sub(now) <= e.cfg.QuotaRefreshAhead {
		// A failed account must not prevent the remaining accounts being checked.
		return false, e.backend.RefreshInstance(work, e.cfg.Principal, i.ID)
	}
	return false, nil
}
