package storage

import (
	"context"
	"time"
)

type InstanceCommand struct {
	Revision   int64  `json:"revision"`
	Action     string `json:"action"`
	LimitBytes *int64 `json:"limit_bytes,omitempty"`
}

// CommandInstance deliberately cannot change identity, credentials, admissions
// or authorization deadlines. Restoring revoked custody requires fresh evidence.
func (s *Service) CommandInstance(ctx context.Context, p Principal, id, key string, command InstanceCommand) (InstanceHealth, error) {
	var out InstanceHealth
	if !validID(id) || command.Revision < 1 || (command.Action == "quota") != (command.LimitBytes != nil) {
		return out, ErrInput
	}
	if command.LimitBytes != nil && (*command.LimitBytes < 0 || *command.LimitBytes > 1<<60) {
		return out, ErrInput
	}
	switch command.Action {
	case "pause", "resume", "drain", "revoke", "quota":
	default:
		return out, ErrInput
	}
	authorize := func(Transaction) error { return s.authorize(ctx, p, "storage.operations.manage", id, Protection{}) }
	err := s.mutation(ctx, p, "storage.operations.manage", id, key, command, authorize, func(tx Transaction) (any, error) {
		i, err := tx.Instance(id)
		if err != nil {
			return nil, err
		}
		if i.Revision != command.Revision {
			return nil, ErrStale
		}
		switch command.Action {
		case "pause":
			if i.State != "active" {
				return nil, ErrConflict
			}
			i.State = "paused"
		case "resume", "drain":
			if !i.Authorized || !i.ExpiresAt.After(s.now()) {
				return nil, ErrDenied
			}
			if command.Action == "resume" {
				if i.State != "paused" {
					return nil, ErrConflict
				}
				i.State = "active"
			} else {
				if i.State != "active" && i.State != "paused" {
					return nil, ErrConflict
				}
				i.State = "draining"
			}
		case "revoke":
			if i.State == "revoked" {
				return nil, ErrConflict
			}
			i.State, i.Authorized = "revoked", false
		case "quota":
			if i.ContributionControl != nil && *command.LimitBytes > i.ContributionControl.LimitBytes {
				return nil, ErrDenied
			}
			if *command.LimitBytes < i.Used+i.Reserved {
				return nil, ErrConflict
			}
			i.Limit = *command.LimitBytes
		}
		i.Revision++
		if err = authorize(tx); err != nil {
			return nil, err
		}
		if err = tx.SaveInstance(i); err != nil {
			return nil, err
		}
		if err = s.emit(tx, p, "storage.instance."+command.Action, i.ID, i.Revision); err != nil {
			return nil, err
		}
		return instanceHealth(i, s.now()), nil
	}, &out)
	return out, err
}

// RetryJob does not reconstruct a write. It requeues the original intent only
// when the bindings still agree, leaving unknown-write reconciliation to workers.
func (s *Service) RetryJob(ctx context.Context, p Principal, objectID, jobID, key string, generation int64) (JobFailure, error) {
	var out JobFailure
	if !validID(objectID) || !validID(jobID) || generation < 1 {
		return out, ErrInput
	}
	var object Object
	guard := func(tx Transaction) error {
		if err := tx.Lock("object:" + objectID); err != nil {
			return err
		}
		var err error
		object, err = tx.Object(objectID)
		if err != nil {
			return err
		}
		return s.authorize(ctx, p, "storage.operations.retry", jobID, object.Protection)
	}
	err := s.mutation(ctx, p, "storage.operations.retry", jobID, key, struct {
		ObjectID   string
		Generation int64
	}{objectID, generation}, guard, func(tx Transaction) (any, error) {
		// Read the binding without a job lock, then acquire instance -> job.
		// The object lock serializes binding changes; Claim may still change state.
		snapshot, err := tx.JobSnapshot(jobID)
		if err != nil {
			return nil, err
		}
		if snapshot.ObjectID != object.ID {
			return nil, ErrNotFound
		}
		replicas, err := tx.Replicas(object.ID)
		if err != nil {
			return nil, err
		}
		r, err := findReplica(replicas, snapshot.ReplicaID)
		if err != nil {
			return nil, err
		}
		i, err := tx.Instance(r.InstanceID)
		if err != nil {
			return nil, err
		}
		j, err := tx.Job(jobID)
		if err != nil {
			return nil, err
		}
		if j.State != "blocked" || j.Generation != generation || j.ReplicaID != r.ID || j.ObjectID != object.ID {
			return nil, ErrStale
		}
		if !i.Authorized || !i.ExpiresAt.After(s.now()) || i.State == "revoked" {
			return nil, ErrDenied
		}
		if j.Intent != r.Intent || j.ObjectRevision != r.ObjectRevision || j.InstanceRevision != r.InstanceRevision || j.CredentialRevision != r.CredentialRevision || i.CredentialRevision != r.CredentialRevision || r.State == "deleted" {
			return nil, ErrStale
		}
		switch j.Kind {
		case "delete":
			if r.State != "cleanup" {
				return nil, ErrConflict
			}
			active, err := tx.ActiveWrites(r.ID, s.now())
			if err != nil {
				return nil, err
			}
			if active {
				return nil, ErrConflict
			}
		case "verify", "replicate", "ingest":
			if object.State == "deleted" || object.State == "deleting" || r.State == "cleanup" || r.ObjectRevision != object.Revision || i.Revision != r.InstanceRevision {
				return nil, ErrStale
			}
			if !i.Allows(object.Protection, s.now()) {
				return nil, ErrDenied
			}
		default:
			return nil, ErrInput
		}
		j.Generation++
		j.State, j.ErrorCode, j.LeaseOwner = "pending", "", ""
		j.Attempts, j.LeaseUntil, j.AvailableAt = 0, time.Time{}, s.now()
		if err = s.authorize(ctx, p, "storage.operations.retry", jobID, object.Protection); err != nil {
			return nil, err
		}
		if err = s.queue(tx, j); err != nil {
			return nil, err
		}
		if err = tx.Event(Event{ID: newID(), Type: "storage.job.retried", ObjectID: object.ID, JobID: j.ID, Revision: object.Revision, Time: s.now(), Actor: p}); err != nil {
			return nil, err
		}
		return jobFailure(j), nil
	}, &out)
	return out, err
}
