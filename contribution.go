package storage

import (
	"context"
	"time"
)

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
	ObservedAt             time.Time            `json:"observed_at"`
}

func (s *Service) contributionSnapshot(tx Transaction, i Instance) (ContributionSnapshot, error) {
	remaining, err := tx.InstanceReplicas(i.ID)
	h := instanceHealth(i, s.now())
	return ContributionSnapshot{InstanceID: i.ID, Adapter: i.Adapter, Revision: i.Revision, Control: i.ContributionControl, State: i.State, Authorized: i.Authorized, AuthorizationExpiresAt: i.ExpiresAt, QuotaExpiresAt: i.QuotaExpiresAt, UsedBytes: i.Used, ReservedBytes: i.Reserved, AvailableBytes: h.AvailableBytes, RemainingReplicas: remaining, ObservedAt: s.now()}, err
}
func (s *Service) InspectContribution(ctx context.Context, p Principal, id, owner string) (ContributionSnapshot, error) {
	var out ContributionSnapshot
	if !validID(id) || !validID(owner) {
		return out, ErrInput
	}
	if err := s.authorize(ctx, p, "storage.contributions.read", id, Protection{}); err != nil {
		return out, err
	}
	err := s.repo.Transaction(ctx, func(tx Transaction) error {
		i, err := tx.Instance(id)
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
			if (old.State == "revoked" && c.State != "revoked") || (old.State == "draining" && c.State != "draining" && c.State != "revoked") {
				return ErrConflict
			}
			if old.Revision == c.Revision {
				want, previous := c, *old
				want.ExpectedRevision = 0
				previous.ExpectedRevision = 0
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
		if c.State == "active" && (!c.Until.After(s.now()) || i.State == "draining") {
			return ErrConflict
		}
		if c.State == "active" && c.LimitBytes < i.Used+i.Reserved {
			return ErrConflict
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
		if err = s.emit(tx, p, "storage.instance.contribution", id, i.Revision); err != nil {
			return err
		}
		out, err = s.contributionSnapshot(tx, i)
		return err
	})
	return out, err
}
