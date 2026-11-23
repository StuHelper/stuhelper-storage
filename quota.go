package storage

import (
	"context"
	"time"
)

const (
	CapacityAvailable  = "available"
	CapacityNotRead    = "not_read"
	CapacityReadFailed = "read_failed"
	CapacityExpired    = "expired"
)

// ProviderQuotaSample holds the provider's reported usage before local
// reservations and placement adjustments.
type ProviderQuotaSample struct {
	TotalBytes int64 `json:"total_bytes"`
	UsedBytes  int64 `json:"used_bytes"`
}

func (q ProviderQuotaSample) remaining() int64 {
	return max(0, q.TotalBytes-q.UsedBytes)
}

// QuotaObservation is persisted by the repository. Instance's HTTP and
// idempotency representations deliberately exclude it.
type QuotaObservation struct {
	RefreshRequested bool                 `json:"refresh_requested,omitempty"`
	Sample           *ProviderQuotaSample `json:"sample,omitempty"`
	ObservedAt       time.Time            `json:"observed_at,omitzero"`
	ReadFailed       bool                 `json:"read_failed,omitempty"`
}

const (
	RecoveryWaitingRetry        = "waiting_retry"
	RecoveryWaitingScan         = "waiting_scan"
	RecoveryCredentialsRequired = "credentials_required"
)

// CustodyRecoverySource reports whether this bound revision can still log in.
// Reading it must not contact the provider.
type CustodyRecoverySource interface {
	CredentialsRequired(context.Context, Instance) bool
}

type ProviderCapacity struct {
	Recovery       string     `json:"recovery,omitempty"`
	TotalBytes     *int64     `json:"total_bytes"`
	UsedBytes      *int64     `json:"used_bytes"`
	RemainingBytes *int64     `json:"remaining_bytes"`
	ObservedAt     *time.Time `json:"observed_at"`
	Status         string     `json:"status"`
}

type OwnerCapacity struct {
	ProviderCapacity        ProviderCapacity `json:"provider_capacity"`
	SafetyMarginBytes       int64            `json:"safety_margin_bytes"`
	MaxContributableBytes   *int64           `json:"max_contributable_bytes"`
	AvailableBytes          int64            `json:"-"`
	UsedBytes               int64            `json:"-"`
	ReservedBytes           int64            `json:"-"`
	HealthReason            string           `json:"-"`
	CandidateAvailableBytes int64            `json:"-"`
	CandidateReason         string           `json:"-"`
	ControlRevision         int64            `json:"-"`
	QuotaExpiresAt          time.Time        `json:"-"`
}

func (c OwnerCapacity) ContributionLimit(personalReserve int64) (int64, error) {
	if personalReserve < 0 || personalReserve > 1<<60 {
		return 0, ErrInput
	}
	if c.ProviderCapacity.Status != CapacityAvailable || c.ProviderCapacity.RemainingBytes == nil {
		return 0, ErrContributionCapacityUnavailable
	}
	return max(0, *c.ProviderCapacity.RemainingBytes-c.SafetyMarginBytes-personalReserve), nil
}

func ContributionConditionsExpand(previousLimit, previousReserve, nextLimit, nextReserve int64) bool {
	return nextLimit > previousLimit || nextReserve < previousReserve
}

func (i Instance) quotaObservedAt() *time.Time {
	if i.QuotaObservation.ObservedAt.IsZero() {
		return nil
	}
	return &i.QuotaObservation.ObservedAt
}

func (i Instance) quotaStatus(now time.Time) string {
	switch {
	case i.QuotaObservation.ReadFailed:
		return CapacityReadFailed
	case i.QuotaObservation.ObservedAt.IsZero():
		return CapacityNotRead
	case !i.QuotaExpiresAt.After(now):
		return CapacityExpired
	default:
		return CapacityAvailable
	}
}

func (i Instance) quotaReason(now time.Time) string {
	switch i.quotaStatus(now) {
	case CapacityReadFailed:
		return "capacity_read_failed"
	case CapacityExpired:
		return "capacity_expired"
	case CapacityNotRead:
		return "capacity_unknown"
	default:
		return ""
	}
}

func (i Instance) ownerCapacity(now time.Time) OwnerCapacity {
	p := ProviderCapacity{Status: i.quotaStatus(now), ObservedAt: i.quotaObservedAt()}
	if p.Status == CapacityAvailable {
		if i.QuotaObservation.Sample == nil {
			p.Status = CapacityNotRead
		} else {
			sample := *i.QuotaObservation.Sample
			remaining := sample.remaining()
			p.TotalBytes, p.UsedBytes, p.RemainingBytes = &sample.TotalBytes, &sample.UsedBytes, &remaining
		}
	}
	health := instanceHealth(i, now)
	out := OwnerCapacity{
		ProviderCapacity: p, SafetyMarginBytes: i.SafetyMargin,
		AvailableBytes: health.AvailableBytes, UsedBytes: health.UsedBytes, ReservedBytes: health.ReservedBytes,
		HealthReason: health.Reason, QuotaExpiresAt: i.QuotaExpiresAt,
	}
	if i.ContributionControl != nil {
		out.ControlRevision = i.ContributionControl.Revision
	}
	if i.State == "paused" && i.ContributionControl == nil {
		health := i.candidateHealth(now)
		out.CandidateAvailableBytes = health.AvailableBytes
		out.CandidateReason = health.Reason
	}
	if limit, err := out.ContributionLimit(0); err == nil {
		out.MaxContributableBytes = &limit
	}
	return out
}

// InspectOwnerCapacities projects private provider readings for one verified
// principal. The calling module separately authorizes the owner. A missing or
// unowned ID has no entry in the returned map.
// SetQuotaRetry reports an actual scheduled retry from the maintenance worker.
func (s *Service) SetQuotaRetry(id string, revision int64, pending bool) {
	if pending {
		s.quotaRetries.Store(id, revision)
	} else {
		s.quotaRetries.Delete(id)
	}
}

func (s *Service) InspectOwnerCapacities(ctx context.Context, actor, owner Principal, ids []string) (map[string]OwnerCapacity, error) {
	result := make(map[string]OwnerCapacity, len(ids))
	if !owner.Valid() || len(ids) > 100 {
		return nil, ErrInput
	}
	for _, id := range ids {
		if !validID(id) {
			return nil, ErrInput
		}
	}
	if err := s.authorize(ctx, actor, "storage.contributions.read", "", Protection{}); err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return result, nil
	}
	domain := ContributionOwnerDomain(owner)
	var failed []Instance
	err := s.readTx(ctx, func(tx Transaction) error {
		instances, err := tx.InstanceSnapshots(ids)
		if err != nil {
			return err
		}
		now := s.now()
		for _, i := range instances {
			if i.Ownership == "contributor" && i.OwnerDomain == domain {
				result[i.ID] = i.ownerCapacity(now)
				if i.QuotaObservation.ReadFailed {
					failed = append(failed, i)
				}
			}
		}
		return s.authorize(ctx, actor, "storage.contributions.read", "", Protection{})
	})
	if err != nil {
		return nil, err
	}
	for _, i := range failed {
		c := result[i.ID]
		c.ProviderCapacity.Recovery = RecoveryWaitingScan
		if rev, ok := s.quotaRetries.Load(i.ID); ok && rev == i.CredentialRevision {
			c.ProviderCapacity.Recovery = RecoveryWaitingRetry
		}
		if source, ok := s.verifier.(CustodyRecoverySource); ok && source.CredentialsRequired(ctx, i) {
			c.ProviderCapacity.Recovery = RecoveryCredentialsRequired
		}
		result[i.ID] = c
	}
	return result, nil
}

func (e InstanceEvidence) validQuota(now time.Time) bool {
	if e.ProviderFree < 0 || e.VerifiedAt.Before(now.Add(-time.Minute)) || e.VerifiedAt.After(now.Add(time.Minute)) {
		return false
	}
	return e.Quota == nil || e.Quota.TotalBytes >= 0 && e.Quota.UsedBytes >= 0 && e.ProviderFree == e.Quota.remaining()
}

func (s *Service) saveQuotaEvidence(i *Instance, evidence InstanceEvidence) {
	i.ProviderFree = evidence.ProviderFree
	i.QuotaExpiresAt = evidence.VerifiedAt.Add(s.cfg.QuotaValidity)
	i.QuotaRevision++
	i.QuotaObservation = QuotaObservation{Sample: evidence.Quota, ObservedAt: evidence.VerifiedAt.UTC()}
}

func (i Instance) quotaLedgerMatches(before Instance) bool {
	return before.Reserved == 0 && i.Reserved == 0 && i.QuotaRevision == before.QuotaRevision &&
		i.Used == before.Used && i.ProviderFree == before.ProviderFree
}

// RequestBoundQuotaRefresh schedules an already authorized instance for the
// next maintenance sweep, including the first sweep after an offline migration.
func (s *Service) RequestBoundQuotaRefresh(ctx context.Context, p Principal, expected Instance) error {
	return s.repo.Transaction(ctx, func(tx Transaction) error {
		if err := s.authorize(ctx, p, "storage.instances.manage", expected.ID, Protection{}); err != nil {
			return err
		}
		i, err := tx.Instance(expected.ID)
		if err != nil {
			return err
		}
		if !i.Authorized || i.State == "revoked" || !i.ExpiresAt.After(s.now()) {
			return ErrDenied
		}
		if i.Adapter != "bhpan" || i.Ownership != "contributor" || i.ContributionApproval == "" ||
			i.OwnerDomain != expected.OwnerDomain || i.AccountDomain != expected.AccountDomain || i.Root != expected.Root ||
			i.CredentialRef != expected.CredentialRef || i.CredentialRevision != expected.CredentialRevision || !i.ExpiresAt.Equal(expected.ExpiresAt) {
			return ErrConflict
		}
		if i.QuotaObservation.RefreshRequested {
			return nil
		}
		i.QuotaObservation.RefreshRequested = true
		return tx.SaveInstance(i)
	})
}
