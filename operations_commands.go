package storage

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode"
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
				if i.Ownership == "contributor" && (i.ContributionControl == nil || i.ContributionControl.State != "active" || !i.ContributionControl.Until.After(s.now())) {
					return nil, ErrDenied
				}
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
			if i.Ownership == "contributor" && i.ContributionControl == nil && *command.LimitBytes > 0 {
				return nil, ErrDenied
			}
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
		if err = s.emit(ctx, tx, p, "storage.instance."+command.Action, i.ID, i.Revision); err != nil {
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
			if (j.Kind == "ingest" || j.Kind == "replicate") && i.ContributionControl != nil && (i.ContributionControl.State != "active" || !i.ContributionControl.Until.After(s.now())) {
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
		if err = tx.Event(Event{ID: newID(), Type: "storage.job.retried", ObjectID: object.ID, JobID: j.ID, Revision: object.Revision, Time: s.now(), Actor: p, TraceParent: TraceParentFromContext(ctx), SchoolID: eventSchoolID(object.Protection), AuditResult: "success", AuditSchool: object.Protection.Scope}); err != nil {
			return nil, err
		}
		return jobFailure(j), nil
	}, &out)
	return out, err
}

type ReplicaWriteOff struct {
	ObjectRevision   int64  `json:"object_revision"`
	InstanceRevision int64  `json:"instance_revision"`
	Reason           string `json:"reason"`
}
type ReplicaWriteOffResult struct {
	Instance InstanceHealth `json:"instance"`
	Object   Status         `json:"object"`
}

func validVerificationReason(reason string) bool {
	trimmed := strings.TrimSpace(reason)
	return trimmed != "" && len(reason) <= 512 && !strings.ContainsFunc(reason, unicode.IsControl)
}

// WriteOffUnknownReplica releases frozen capacity on an ambiguous unknown-begin
// replica (issued_write=true && remote.id=="") after an operator verifies that
// no remote object was created in the isolated directory.
func (s *Service) WriteOffUnknownReplica(ctx context.Context, p Principal, objectID, replicaID, key string, input ReplicaWriteOff) (ReplicaWriteOffResult, error) {
	var out ReplicaWriteOffResult
	if !validID(objectID) || !validID(replicaID) || input.ObjectRevision < 1 || input.InstanceRevision < 1 || !validVerificationReason(input.Reason) {
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
		return s.authorize(ctx, p, "storage.operations.manage", objectID, object.Protection)
	}
	err := s.mutation(ctx, p, "storage.operations.writeoff", objectID+":"+replicaID, key, input, guard, func(tx Transaction) (any, error) {
		if object.Revision != input.ObjectRevision {
			return nil, ErrStale
		}
		replicas, err := tx.Replicas(object.ID)
		if err != nil {
			return nil, err
		}
		r, err := findReplica(replicas, replicaID)
		if err != nil {
			return nil, err
		}
		// Lock order: object -> instances in sorted ID order -> job.
		// Collect all instances referenced by this object so status() below needs no out-of-order lock.
		instanceIDs := map[string]bool{r.InstanceID: true}
		for _, copy := range replicas {
			instanceIDs[copy.InstanceID] = true
		}
		ordered := make([]string, 0, len(instanceIDs))
		for id := range instanceIDs {
			ordered = append(ordered, id)
		}
		for a := 0; a < len(ordered); a++ {
			for b := a + 1; b < len(ordered); b++ {
				if ordered[b] < ordered[a] {
					ordered[a], ordered[b] = ordered[b], ordered[a]
				}
			}
		}
		lockedInstances := make(map[string]Instance, len(ordered))
		for _, instID := range ordered {
			inst, err := tx.Instance(instID)
			if err != nil {
				return nil, err
			}
			lockedInstances[instID] = inst
		}
		i := lockedInstances[r.InstanceID]
		if err := s.authorize(ctx, p, "storage.operations.manage", i.ID, object.Protection); err != nil {
			return nil, err
		}
		if i.Revision != input.InstanceRevision {
			return nil, ErrStale
		}
		if r.State == "deleted" || r.State == "healthy" || !r.IssuedWrite || r.Remote.ID != "" {
			return nil, ErrConflict
		}
		active, err := tx.ActiveWrites(r.ID, s.now())
		if err != nil {
			return nil, err
		}
		if active {
			return nil, ErrConflict
		}
		for _, kind := range []string{"delete", "ingest", "replicate"} {
			jobID := requestHash([]string{object.ID, r.ID, kind})
			j, err := tx.Job(jobID)
			if errors.Is(err, ErrNotFound) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if j.State == "running" && j.LeaseUntil.After(s.now()) {
				return nil, ErrConflict
			}
			if j.State != "done" {
				j.Generation++
				j.State = "done"
				j.ErrorCode = ""
				j.LeaseOwner = ""
				j.LeaseUntil = time.Time{}
				if err := tx.SaveJob(j); err != nil {
					return nil, err
				}
			}
		}
		// Ingest jobs use a random ID; scan failed/blocked jobs for this replica and mark done.
		for cursor := ""; ; {
			failed, err := tx.FailedJobs(100, cursor)
			if err != nil {
				return nil, err
			}
			for _, fJob := range failed {
				if fJob.ObjectID == object.ID && fJob.ReplicaID == r.ID {
					j, err := tx.Job(fJob.ID)
					if err != nil {
						return nil, err
					}
					if j.State == "running" && j.LeaseUntil.After(s.now()) {
						return nil, ErrConflict
					}
					if j.State != "done" {
						j.Generation++
						j.State = "done"
						j.ErrorCode = ""
						j.LeaseOwner = ""
						j.LeaseUntil = time.Time{}
						if err := tx.SaveJob(j); err != nil {
							return nil, err
						}
					}
				}
			}
			if len(failed) < 100 {
				break
			}
			cursor = failed[len(failed)-1].ID
		}
		if r.Reserved {
			i.Reserved = max(0, i.Reserved-r.Size)
			r.Reserved = false
		}
		if r.Accounted {
			i.Used = max(0, i.Used-r.Size)
			r.Accounted = false
		}
		r.State = "deleted"
		// Releasing a reservation does not change instance admission or fence other uploads.
		if err := tx.SaveInstance(i); err != nil {
			return nil, err
		}
		if err := tx.SaveReplica(r); err != nil {
			return nil, err
		}
		if object.State == "deleting" {
			updatedReplicas, err := tx.Replicas(object.ID)
			if err != nil {
				return nil, err
			}
			allDeleted := true
			for _, copy := range updatedReplicas {
				if copy.State != "deleted" {
					allDeleted = false
					break
				}
			}
			if allDeleted {
				object.State = "deleted"
				if err := tx.SaveObject(object); err != nil {
					return nil, err
				}
			}
		}
		if err := tx.Event(Event{ID: newID(), Type: "storage.replica.writeoff", ObjectID: object.ID, Revision: object.Revision, Time: s.now(), Actor: p, Reason: strings.TrimSpace(input.Reason), AuditResult: "success", AuditSchool: object.Protection.Scope, TraceParent: TraceParentFromContext(ctx), SchoolID: eventSchoolID(object.Protection)}); err != nil {
			return nil, err
		}
		st, err := s.status(tx, object)
		if err != nil {
			return nil, err
		}
		return ReplicaWriteOffResult{Instance: instanceHealth(i, s.now()), Object: st}, nil
	}, &out)
	return out, err
}
