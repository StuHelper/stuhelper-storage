package storage

import (
	"context"
	"time"
)

type InstanceHealth struct {
	Revision               int64     `json:"revision"`
	LimitBytes             int64     `json:"limit_bytes"`
	UsedBytes              int64     `json:"used_bytes"`
	ReservedBytes          int64     `json:"reserved_bytes"`
	ID                     string    `json:"id"`
	State                  string    `json:"state"`
	Reason                 string    `json:"reason"`
	AvailableBytes         int64     `json:"available_bytes"`
	AuthorizationExpiresAt time.Time `json:"authorization_expires_at"`
	QuotaExpiresAt         time.Time `json:"quota_expires_at"`
}
type ObjectHealth struct {
	ID      string `json:"id"`
	State   string `json:"state"`
	Healthy int    `json:"healthy"`
	Desired int    `json:"desired"`
	Missing int    `json:"missing"`
	Reason  string `json:"reason"`
}
type ObjectTotals struct {
	Pending     int64 `json:"pending"`
	Ready       int64 `json:"ready"`
	Degraded    int64 `json:"degraded"`
	Unavailable int64 `json:"unavailable"`
	Deleting    int64 `json:"deleting"`
}
type JobTotals struct {
	Pending int64 `json:"pending"`
	Running int64 `json:"running"`
	Blocked int64 `json:"blocked"`
}
type JobFailure struct {
	Generation  int64     `json:"generation"`
	ID          string    `json:"id"`
	ObjectID    string    `json:"object_id"`
	ReplicaID   string    `json:"replica_id,omitempty"`
	Kind        string    `json:"kind"`
	State       string    `json:"state"`
	Attempts    int       `json:"attempts"`
	ErrorCode   string    `json:"error_code"`
	NextAttempt time.Time `json:"next_attempt"`
}
type Operations struct {
	GeneratedAt        time.Time        `json:"generated_at"`
	Instances          []InstanceHealth `json:"instances"`
	Objects            []ObjectHealth   `json:"objects"`
	ObjectTotals       ObjectTotals     `json:"object_totals"`
	Jobs               JobTotals        `json:"jobs"`
	Failures           []JobFailure     `json:"failures"`
	NextCursor         string           `json:"next_cursor"`
	FailuresNextCursor string           `json:"failures_next_cursor"`
}
type OperationsQuery struct {
	Limit         int
	After         string
	FailuresAfter string
	ObjectFilter  string
	FailureState  string
	FailureKind   string
	ErrorCode     string
}

func instanceHealth(i Instance, now time.Time) InstanceHealth {
	out := InstanceHealth{ID: i.ID, State: i.State, Revision: i.Revision, LimitBytes: i.Limit, UsedBytes: i.Used, ReservedBytes: i.Reserved, AuthorizationExpiresAt: i.ExpiresAt, QuotaExpiresAt: i.QuotaExpiresAt}
	switch {
	case !i.Authorized || i.State == "revoked":
		out.Reason = "authorization_revoked"
	case !i.ExpiresAt.After(now):
		out.Reason = "authorization_expired"
	case i.State != "active":
		out.Reason = "writes_disabled"
	case i.ContributionControl != nil && (i.ContributionControl.State != "active" || !i.ContributionControl.Until.After(now)):
		out.Reason = "writes_disabled"
	case !i.QuotaExpiresAt.After(now):
		out.Reason = "capacity_unknown"
	default:
		out.AvailableBytes = max(0, min(i.Limit-i.Used-i.Reserved, i.ProviderFree-i.PersonalReserve-i.SafetyMargin-i.Reserved))
		if out.AvailableBytes == 0 {
			out.Reason = "capacity_exhausted"
		}
	}
	return out
}

func (s *Service) evaluateObjectHealth(o Object, replicas []Replica, instances []Instance, byID map[string]Instance, now time.Time) ObjectHealth {
	count := 0
	accounts := map[string]bool{}
	owners := map[string]bool{}
	for _, r := range replicas {
		if r.State != "healthy" || r.ObjectRevision != o.Revision || r.VerifiedAt.Before(now.Add(-s.cfg.VerificationAge)) {
			continue
		}
		i, ok := byID[r.InstanceID]
		if !ok || !i.Allows(o.Protection, now) || r.CredentialRevision != i.CredentialRevision || accounts[i.AccountDomain] || (i.Ownership == "contributor" && owners[i.OwnerDomain]) {
			continue
		}
		accounts[i.AccountDomain] = true
		if i.Ownership == "contributor" {
			owners[i.OwnerDomain] = true
		}
		count++
	}
	state := o.State
	if state != "deleting" && state != "deleted" {
		state = "pending"
		if count >= o.Policy.Target {
			state = "ready"
		} else if o.Published || count >= o.Policy.Publish {
			state = "degraded"
		}
		if o.Published && count == 0 {
			state = "unavailable"
		}
	}
	h := ObjectHealth{ID: o.ID, State: state, Healthy: count, Desired: o.Policy.Target}
	if state != "deleted" && state != "deleting" {
		h.Missing = max(0, h.Desired-h.Healthy)
		if h.Missing > 0 {
			h.Reason = "replica_shortage"
			if h.Healthy == 0 {
				h.Reason = "no_healthy_source"
			} else {
				eligible := map[string]bool{}
				eligibleOwners := map[string]bool{}
				for k, v := range accounts {
					eligible[k] = v
				}
				for k, v := range owners {
					eligibleOwners[k] = v
				}
				for _, i := range instances {
					if !i.CanWrite(o.Protection, o.Size, now) || eligible[i.AccountDomain] || (i.Ownership == "contributor" && eligibleOwners[i.OwnerDomain]) {
						continue
					}
					eligible[i.AccountDomain] = true
					if i.Ownership == "contributor" {
						eligibleOwners[i.OwnerDomain] = true
					}
				}
				if len(eligible) < o.Policy.Target {
					h.Reason = "insufficient_eligible_capacity"
				}
			}
		}
	}
	return h
}

func isProblematicObject(h ObjectHealth) bool {
	return h.State == "degraded" || h.State == "unavailable" || h.State == "deleting"
}

// Operations is a global administration privilege, independent of content read
// access. It reads the ledger only and never extends supplier sessions.
func (s *Service) Operations(ctx context.Context, p Principal, limit int, after, failuresAfter string) (Operations, error) {
	return s.QueryOperations(ctx, p, OperationsQuery{Limit: limit, After: after, FailuresAfter: failuresAfter})
}

func (s *Service) QueryOperations(ctx context.Context, p Principal, q OperationsQuery) (Operations, error) {
	out := Operations{GeneratedAt: s.now(), Instances: []InstanceHealth{}, Objects: []ObjectHealth{}, Failures: []JobFailure{}}
	if q.Limit < 1 || q.Limit > 100 || (q.After != "" && !validID(q.After)) || (q.FailuresAfter != "" && !validID(q.FailuresAfter)) || (q.ErrorCode != "" && !validID(q.ErrorCode)) {
		return out, ErrInput
	}
	switch q.ObjectFilter {
	case "", "all", "problematic":
	default:
		return out, ErrInput
	}
	switch q.FailureState {
	case "", "pending", "running", "blocked":
	default:
		return out, ErrInput
	}
	switch q.FailureKind {
	case "", "ingest", "replicate", "verify", "delete":
	default:
		return out, ErrInput
	}
	if err := s.authorize(ctx, p, "storage.operations.read", "", Protection{}); err != nil {
		return out, err
	}
	err := s.repo.Transaction(ctx, func(tx Transaction) error {
		now := s.now()
		instances, err := tx.Instances(100, "")
		if err != nil {
			return err
		}
		byID := make(map[string]Instance, len(instances))
		for _, i := range instances {
			byID[i.ID] = i
			out.Instances = append(out.Instances, instanceHealth(i, now))
		}

		// Aggregate active object totals and optionally collect filtered problematic objects.
		cursor := ""
		for page := 0; page < 1000; page++ {
			batch, err := tx.ActiveObjects(200, cursor)
			if err != nil {
				return err
			}
			if len(batch) == 0 {
				break
			}
			ids := make([]string, len(batch))
			for idx, o := range batch {
				ids[idx] = o.ID
			}
			replicasMap, err := tx.ReplicasByObjects(ids)
			if err != nil {
				return err
			}
			for _, o := range batch {
				h := s.evaluateObjectHealth(o, replicasMap[o.ID], instances, byID, now)
				switch h.State {
				case "pending":
					out.ObjectTotals.Pending++
				case "ready":
					out.ObjectTotals.Ready++
				case "degraded":
					out.ObjectTotals.Degraded++
				case "unavailable":
					out.ObjectTotals.Unavailable++
				case "deleting":
					out.ObjectTotals.Deleting++
				}
				if q.ObjectFilter == "problematic" && o.ID > q.After && isProblematicObject(h) && len(out.Objects) < q.Limit {
					out.Objects = append(out.Objects, h)
				}
			}
			cursor = batch[len(batch)-1].ID
			if len(batch) < 200 {
				break
			}
		}

		if q.ObjectFilter != "problematic" {
			objects, err := tx.Objects(q.Limit, q.After)
			if err != nil {
				return err
			}
			ids := make([]string, len(objects))
			for idx, o := range objects {
				ids[idx] = o.ID
			}
			replicasMap, err := tx.ReplicasByObjects(ids)
			if err != nil {
				return err
			}
			for _, o := range objects {
				out.Objects = append(out.Objects, s.evaluateObjectHealth(o, replicasMap[o.ID], instances, byID, now))
			}
		}
		if len(out.Objects) == q.Limit {
			out.NextCursor = out.Objects[len(out.Objects)-1].ID
		}

		out.Jobs, err = tx.JobTotals()
		if err != nil {
			return err
		}
		jobs, err := tx.FailedJobsFiltered(q.Limit, q.FailuresAfter, q.FailureState, q.FailureKind, q.ErrorCode)
		if err != nil {
			return err
		}
		for _, j := range jobs {
			out.Failures = append(out.Failures, jobFailure(j))
		}
		if len(jobs) == q.Limit {
			out.FailuresNextCursor = jobs[len(jobs)-1].ID
		}
		return s.authorize(ctx, p, "storage.operations.read", "", Protection{})
	})
	return out, err
}

func jobFailure(j Job) JobFailure {
	return JobFailure{ID: j.ID, ObjectID: j.ObjectID, ReplicaID: j.ReplicaID, Kind: j.Kind, State: j.State, Generation: j.Generation, Attempts: j.Attempts, ErrorCode: j.ErrorCode, NextAttempt: j.AvailableAt}
}
