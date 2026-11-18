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

func (s *Service) evaluateObjectHealth(o Object, copies []Replica, instances []Instance, lookup func(string) (Instance, error), now time.Time) (ObjectHealth, error) {
	st, err := s.statusFromLoaded(o, copies, lookup, now)
	if err != nil {
		return ObjectHealth{}, err
	}
	h := ObjectHealth{ID: o.ID, State: st.State, Healthy: st.Healthy, Desired: st.Desired}
	if st.State != "deleted" && st.State != "deleting" {
		h.Missing = max(0, st.Desired-st.Healthy)
		if h.Missing > 0 {
			h.Reason = "replica_shortage"
			if st.Healthy == 0 {
				h.Reason = "no_healthy_source"
			} else {
				seen := newIndependentSet()
				for _, r := range copies {
					i, e := lookup(r.InstanceID)
					if e != nil {
						return ObjectHealth{}, e
					}
					if healthyVerifiedReplica(r, o, i, now, s.cfg.VerificationAge) {
						seen.add(i)
					}
				}
				for _, i := range instances {
					if !i.CanWrite(o.Protection, o.Size, now) || seen.seen(i) {
						continue
					}
					seen.add(i)
				}
				if len(seen.accounts) < o.Policy.Target {
					h.Reason = "insufficient_eligible_capacity"
				}
			}
		}
	}
	return h, nil
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
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
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
	err := s.readTx(ctx, func(tx Transaction) error {
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

		lookup := func(id string) (Instance, error) {
			if inst, ok := byID[id]; ok {
				return inst, nil
			}
			inst, e := tx.InstanceSnapshot(id)
			if e == nil {
				byID[id] = inst
			}
			return inst, e
		}
		// Aggregate active object totals and optionally collect filtered problematic objects.
		cursor := ""
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
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
				h, err := s.evaluateObjectHealth(o, replicasMap[o.ID], instances, lookup, now)
				if err != nil {
					return err
				}
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
			next := batch[len(batch)-1].ID
			if next <= cursor {
				return ErrUnavailable
			}
			cursor = next
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
				h, err := s.evaluateObjectHealth(o, replicasMap[o.ID], instances, lookup, now)
				if err != nil {
					return err
				}
				out.Objects = append(out.Objects, h)
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
