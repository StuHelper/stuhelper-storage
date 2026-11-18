package storage

import (
	"context"
	"time"
)

type RetentionCutoffs struct {
	IdempotencyBefore      time.Time
	DeliveredOutboxBefore  time.Time
	CompletedJobsBefore    time.Time
	CompletedCustodyBefore time.Time
}

type RetentionResult struct {
	Idempotency       int `json:"idempotency"`
	DeliveredOutbox   int `json:"delivered_outbox"`
	CompletedJobs     int `json:"completed_jobs"`
	CustodyOperations int `json:"custody_operations"`
}

func (r RetentionResult) Total() int {
	return r.Idempotency + r.DeliveredOutbox + r.CompletedJobs + r.CustodyOperations
}

// PurgeExpired removes one bounded batch of expired idempotency responses,
// delivered outbox events, finished background jobs and completed custody operations.
func (s *Service) PurgeExpired(ctx context.Context, p Principal, limit int) (RetentionResult, error) {
	var out RetentionResult
	if limit < 1 || limit > 1000 {
		return out, ErrInput
	}
	if err := s.authorize(ctx, p, "storage.maintenance", "", Protection{}); err != nil {
		return out, err
	}
	now := s.now()
	cutoffs := RetentionCutoffs{
		IdempotencyBefore:      now,
		DeliveredOutboxBefore:  now.Add(-s.cfg.OutboxRetention),
		CompletedJobsBefore:    now.Add(-s.cfg.JobRetention),
		CompletedCustodyBefore: now.Add(-s.cfg.CustodyOperationRetention),
	}
	err := s.repo.Transaction(ctx, func(tx Transaction) error {
		if err := s.authorize(ctx, p, "storage.maintenance", "", Protection{}); err != nil {
			return err
		}
		var err error
		out, err = tx.PurgeRetention(cutoffs, limit)
		return err
	})
	return out, err
}
