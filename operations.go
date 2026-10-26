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
type JobTotals struct {
	Pending int64 `json:"pending"`
	Running int64 `json:"running"`
	Blocked int64 `json:"blocked"`
}
type JobFailure struct {
	Generation  int64     `json:"generation"`
	ID          string    `json:"id"`
	ObjectID    string    `json:"object_id"`
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
	Jobs               JobTotals        `json:"jobs"`
	Failures           []JobFailure     `json:"failures"`
	NextCursor         string           `json:"next_cursor"`
	FailuresNextCursor string           `json:"failures_next_cursor"`
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

// Operations is a global administration privilege, independent of content read
// access. It reads the ledger only and never extends supplier sessions.
func (s *Service) Operations(ctx context.Context, p Principal, limit int, after, failuresAfter string) (Operations, error) {
	out := Operations{GeneratedAt: s.now(), Instances: []InstanceHealth{}, Objects: []ObjectHealth{}, Failures: []JobFailure{}}
	if limit < 1 || limit > 100 || (after != "" && !validID(after)) || (failuresAfter != "" && !validID(failuresAfter)) {
		return out, ErrInput
	}
	if err := s.authorize(ctx, p, "storage.operations.read", "", Protection{}); err != nil {
		return out, err
	}
	err := s.repo.Transaction(ctx, func(tx Transaction) error {
		instances, err := tx.Instances(100, "")
		if err != nil {
			return err
		}
		for _, i := range instances {
			out.Instances = append(out.Instances, instanceHealth(i, s.now()))
		}
		objects, err := tx.Objects(limit, after)
		if err != nil {
			return err
		}
		for _, o := range objects {
			st, err := s.status(tx, o)
			if err != nil {
				return err
			}
			h := ObjectHealth{ID: o.ID, State: st.State, Healthy: st.Healthy, Desired: st.Desired}
			if st.State != "deleted" && st.State != "deleting" {
				h.Missing = max(0, st.Desired-st.Healthy)
				if h.Missing > 0 {
					h.Reason = "replica_shortage"
					if st.Healthy == 0 {
						h.Reason = "no_healthy_source"
					} else {
						accounts := map[string]bool{}
						owners := map[string]bool{}
						copies, e := tx.Replicas(o.ID)
						if e != nil {
							return e
						}
						for _, r := range copies {
							for _, i := range instances {
								if i.ID == r.InstanceID && r.State == "healthy" && r.ObjectRevision == o.Revision && r.CredentialRevision == i.CredentialRevision && !r.VerifiedAt.Before(s.now().Add(-s.cfg.VerificationAge)) && i.Allows(o.Protection, s.now()) {
									accounts[i.AccountDomain] = true
									if i.Ownership == "contributor" {
										owners[i.OwnerDomain] = true
									}
								}
							}
						}
						for _, i := range instances {
							if !i.CanWrite(o.Protection, o.Size, s.now()) || accounts[i.AccountDomain] || (i.Ownership == "contributor" && owners[i.OwnerDomain]) {
								continue
							}
							accounts[i.AccountDomain] = true
							if i.Ownership == "contributor" {
								owners[i.OwnerDomain] = true
							}
						}
						if len(accounts) < o.Policy.Target {
							h.Reason = "insufficient_eligible_capacity"
						}
					}
				}
			}
			out.Objects = append(out.Objects, h)
		}
		if len(objects) == limit {
			out.NextCursor = objects[len(objects)-1].ID
		}
		out.Jobs, err = tx.JobTotals()
		if err != nil {
			return err
		}
		jobs, err := tx.FailedJobs(limit, failuresAfter)
		if err != nil {
			return err
		}
		for _, j := range jobs {
			out.Failures = append(out.Failures, jobFailure(j))
		}
		if len(jobs) == limit {
			out.FailuresNextCursor = jobs[len(jobs)-1].ID
		}
		return s.authorize(ctx, p, "storage.operations.read", "", Protection{})
	})
	return out, err
}

func jobFailure(j Job) JobFailure {
	return JobFailure{ID: j.ID, ObjectID: j.ObjectID, Kind: j.Kind, State: j.State, Generation: j.Generation, Attempts: j.Attempts, ErrorCode: j.ErrorCode, NextAttempt: j.AvailableAt}
}
