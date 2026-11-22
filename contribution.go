package storage

import (
	"context"
	"math"
	"time"
)

type ContributionCandidate struct {
	ID                     string    `json:"id"`
	Adapter                string    `json:"adapter"`
	AccountHint            string    `json:"account_hint,omitempty"`
	AvailableBytes         int64     `json:"available_bytes"`
	AuthorizationExpiresAt time.Time `json:"authorization_expires_at"`
	QuotaExpiresAt         time.Time `json:"quota_expires_at"`
	Reason                 string    `json:"reason"`
}
type ContributionCandidates struct {
	Items      []ContributionCandidate `json:"items"`
	NextCursor string                  `json:"next_cursor"`
}

type ContributionSummary struct {
	DeclaredBytes       int64     `json:"declared_bytes"`
	AvailableBytes      int64     `json:"available_bytes"`
	UsedBytes           int64     `json:"used_bytes"`
	ReservedBytes       int64     `json:"reserved_bytes"`
	ActiveInstances     int       `json:"active_instances"`
	RegisteredInstances int       `json:"registered_instances"`
	Status              string    `json:"status"`
	ObservedAt          time.Time `json:"observed_at"`
}

// SummarizeContributions aggregates community contributor capacity from the
// ledger without probing providers or exposing per-instance identifiers.
func (s *Service) SummarizeContributions(ctx context.Context, p Principal) (ContributionSummary, error) {
	out := ContributionSummary{Status: "idle"}
	if err := s.authorize(ctx, p, "storage.contributions.summary", "", Protection{}); err != nil {
		return out, err
	}
	err := s.readTx(ctx, func(tx Transaction) error {
		now := s.now()
		out = ContributionSummary{Status: "idle", ObservedAt: now}
		for page, after := 0, ""; page < 1000; page++ {
			instances, err := tx.Instances(100, after)
			if err != nil {
				return err
			}
			for _, i := range instances {
				if i.Ownership != "contributor" {
					continue
				}
				ctrl := i.ContributionControl
				if ctrl == nil {
					continue
				}
				if i.Used < 0 || i.Reserved < 0 || i.Used > math.MaxInt64-out.UsedBytes || i.Reserved > math.MaxInt64-out.ReservedBytes {
					return ErrUnavailable
				}
				out.UsedBytes += i.Used
				out.ReservedBytes += i.Reserved
				if ctrl.State == "revoked" {
					continue
				}
				out.RegisteredInstances++
				if ctrl.State != "draining" && ctrl.Until.After(now) {
					if ctrl.LimitBytes < 0 || ctrl.LimitBytes > math.MaxInt64-out.DeclaredBytes {
						return ErrUnavailable
					}
					out.DeclaredBytes += ctrl.LimitBytes
				}
				if i.currentPlacementQuota(now) {
					h := instanceHealth(i, now)
					out.ActiveInstances++
					if h.AvailableBytes > math.MaxInt64-out.AvailableBytes {
						return ErrUnavailable
					}
					out.AvailableBytes += h.AvailableBytes
				}
			}
			if len(instances) < 100 {
				break
			}
			after = instances[len(instances)-1].ID
		}
		switch {
		case out.RegisteredInstances == 0:
			out.Status = "idle"
		case out.ActiveInstances == out.RegisteredInstances && out.AvailableBytes > 0:
			out.Status = "healthy"
		case out.ActiveInstances > 0:
			out.Status = "degraded"
		default:
			out.Status = "unavailable"
		}
		return s.authorize(ctx, p, "storage.contributions.summary", "", Protection{})
	})
	if err != nil {
		return ContributionSummary{}, err
	}
	return out, nil
}

func (s *Service) ListContributionCandidates(ctx context.Context, p Principal, owner string, n int, after string) (ContributionCandidates, error) {
	out := ContributionCandidates{Items: []ContributionCandidate{}}
	if !validID(owner) || n < 1 || n > 100 || (after != "" && !validID(after)) {
		return out, ErrInput
	}
	if e := s.authorize(ctx, p, "storage.contributions.read", "", Protection{}); e != nil {
		return out, e
	}
	e := s.readTx(ctx, func(tx Transaction) error {
		now := s.now()
		items, e := tx.ContributionCandidates(owner, now, n+1, after)
		if e != nil {
			return e
		}
		if len(items) > n {
			items = items[:n]
			out.NextCursor = items[n-1].ID
		}
		for _, i := range items {
			health := i.candidateHealth(now)
			out.Items = append(out.Items, ContributionCandidate{
				ID:                     i.ID,
				Adapter:                i.Adapter,
				AvailableBytes:         health.AvailableBytes,
				AuthorizationExpiresAt: i.ExpiresAt,
				QuotaExpiresAt:         i.QuotaExpiresAt,
				Reason:                 health.Reason,
			})
		}
		return s.authorize(ctx, p, "storage.contributions.read", "", Protection{})
	})
	return out, e
}

func (i Instance) candidateHealth(now time.Time) InstanceHealth {
	// Compute potential capacity without enabling the instance. Newly
	// accepted custody has no contribution allocation yet.
	i.State = "active"
	if i.Limit == 0 {
		i.Limit = 1 << 60
	}
	return instanceHealth(i, now)
}

// ContributionControl is a permanent, monotonically revised business binding.
// It contains no provider credential and cannot extend provider authorization.
type ContributionControl struct {
	ID               string    `json:"id"`
	OwnerDomain      string    `json:"owner_domain"`
	Revision         int64     `json:"revision"`
	ExpectedRevision int64     `json:"expected_revision"`
	State            string    `json:"state"`
	LimitBytes       int64     `json:"limit_bytes"`
	PersonalReserve  int64     `json:"personal_reserve"`
	Until            time.Time `json:"until"`
}
type ContributionSnapshot struct {
	InstanceID             string               `json:"instance_id"`
	Adapter                string               `json:"adapter"`
	Revision               int64                `json:"revision"`
	Control                *ContributionControl `json:"control,omitempty"`
	State                  string               `json:"state"`
	Authorized             bool                 `json:"authorized"`
	AuthorizationExpiresAt time.Time            `json:"authorization_expires_at"`
	QuotaExpiresAt         time.Time            `json:"quota_expires_at"`
	UsedBytes              int64                `json:"used_bytes"`
	ReservedBytes          int64                `json:"reserved_bytes"`
	AvailableBytes         int64                `json:"available_bytes"`
	RemainingReplicas      int64                `json:"remaining_replicas"`
	ObservedAt             *time.Time           `json:"observed_at"`
	CapacityStatus         string               `json:"capacity_status"`
	SnapshotAt             time.Time            `json:"-"`
}

func (s *Service) contributionSnapshot(tx Transaction, i Instance) (ContributionSnapshot, error) {
	remaining, err := tx.InstanceReplicas(i.ID)
	now := s.now()
	h := instanceHealth(i, now)
	return ContributionSnapshot{
		InstanceID: i.ID, Adapter: i.Adapter, Revision: i.Revision, Control: i.ContributionControl,
		State: i.State, Authorized: i.Authorized, AuthorizationExpiresAt: i.ExpiresAt, QuotaExpiresAt: i.QuotaExpiresAt,
		UsedBytes: i.Used, ReservedBytes: i.Reserved, AvailableBytes: h.AvailableBytes, RemainingReplicas: remaining,
		ObservedAt: i.quotaObservedAt(), CapacityStatus: i.quotaStatus(now), SnapshotAt: now,
	}, err
}
func (s *Service) InspectContribution(ctx context.Context, p Principal, id, owner string) (ContributionSnapshot, error) {
	var out ContributionSnapshot
	if !validID(id) || !validID(owner) {
		return out, ErrInput
	}
	if err := s.authorize(ctx, p, "storage.contributions.read", id, Protection{}); err != nil {
		return out, err
	}
	err := s.readTx(ctx, func(tx Transaction) error {
		i, err := tx.InstanceSnapshot(id)
		if err != nil {
			return err
		}
		if i.Ownership != "contributor" || i.OwnerDomain != owner {
			return ErrDenied
		}
		out, err = s.contributionSnapshot(tx, i)
		if err != nil {
			return err
		}
		return s.authorize(ctx, p, "storage.contributions.read", id, Protection{})
	})
	return out, err
}
func (s *Service) ApplyContribution(ctx context.Context, p Principal, id string, c ContributionControl) (ContributionSnapshot, error) {
	var out ContributionSnapshot
	if !validID(id) || !validID(c.ID) || !validID(c.OwnerDomain) || c.Revision < 1 || c.ExpectedRevision < 1 || c.LimitBytes < 0 || c.LimitBytes > 1<<60 || c.PersonalReserve < 0 || c.PersonalReserve > 1<<60 || c.Until.IsZero() {
		return out, ErrInput
	}
	switch c.State {
	case "active", "paused", "draining", "revoked":
	default:
		return out, ErrInput
	}
	if err := s.authorize(ctx, p, "storage.contributions.manage", id, Protection{}); err != nil {
		return out, err
	}
	c.Until = c.Until.UTC()
	err := s.repo.Transaction(ctx, func(tx Transaction) error {
		i, err := tx.Instance(id)
		if err != nil {
			return err
		}
		if i.Ownership != "contributor" || i.OwnerDomain != c.OwnerDomain {
			return ErrDenied
		}
		if old := i.ContributionControl; old != nil {
			if old.ID != c.ID || old.Revision > c.Revision {
				return ErrStale
			}
			if (old.State == "revoked" && c.State != "revoked") || (old.State == "draining" && c.State == "paused") {
				return ErrConflict
			}
			if old.Revision == c.Revision {
				want, previous := c, *old
				want.ExpectedRevision = 0
				previous.ExpectedRevision = 0
				want.Until = want.Until.UTC()
				previous.Until = previous.Until.UTC()
				if requestHash(want) != requestHash(previous) {
					return ErrConflict
				}
				out, err = s.contributionSnapshot(tx, i)
				if err != nil {
					return err
				}
				return s.authorize(ctx, p, "storage.contributions.manage", id, Protection{})
			}
		} else {
			remaining, err := tx.InstanceReplicas(id)
			if err != nil {
				return err
			}
			if i.State != "paused" || i.Used != 0 || i.Reserved != 0 || remaining != 0 {
				return ErrConflict
			}
		}
		if i.Revision != c.ExpectedRevision {
			return ErrStale
		}
		if c.State != "revoked" && (!i.Authorized || !i.ExpiresAt.After(s.now()) || i.State == "revoked") {
			return ErrDenied
		}
		if c.State == "active" && !c.Until.After(s.now()) {
			return ErrConflict
		}
		if c.State == "active" && (i.State == "draining" || i.ContributionControl != nil && i.ContributionControl.State == "draining") {
			// A newer consent may reopen its binding only once this locked instance has completed drainage.
			if i.ContributionControl == nil || i.ContributionControl.State != "draining" || i.Used != 0 || i.Reserved != 0 {
				return ErrConflict
			}
			remaining, err := tx.InstanceReplicas(id)
			if err != nil {
				return err
			}
			if remaining != 0 {
				return ErrConflict
			}
		}
		if c.State == "active" && c.LimitBytes < i.Used+i.Reserved {
			return ErrConflict
		}
		if old := i.ContributionControl; (c.State == "active" || c.State == "paused") &&
			(old == nil || old.State == "draining" && c.State == "active" ||
				ContributionConditionsExpand(old.LimitBytes, old.PersonalReserve, c.LimitBytes, c.PersonalReserve)) {
			limit, err := i.ownerCapacity(s.now()).ContributionLimit(c.PersonalReserve)
			if err != nil {
				return err
			}
			if c.LimitBytes > limit {
				return ErrContributionLimitExceeded
			}
		}
		i.ContributionControl = &c
		i.Limit = c.LimitBytes
		i.PersonalReserve = c.PersonalReserve
		i.State = c.State
		i.Revision++
		if c.State == "revoked" {
			i.Authorized = false
		}
		if err = s.authorize(ctx, p, "storage.contributions.manage", id, Protection{}); err != nil {
			return err
		}
		if err = tx.SaveInstance(i); err != nil {
			return err
		}
		if err = s.emit(ctx, tx, p, "storage.instance.contribution", id, i.Revision); err != nil {
			return err
		}
		out, err = s.contributionSnapshot(tx, i)
		return err
	})
	return out, err
}
