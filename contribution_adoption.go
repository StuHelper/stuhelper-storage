package storage

import (
	"context"
	"time"
)

// ContributionOwnerDomain binds a contributor to the stable application principal.
func ContributionOwnerDomain(owner Principal) string { return "owner:" + requestHash(owner) }

type ContributionAdoption struct {
	InstanceID        string
	Owner             Principal
	Control           ContributionControl
	ApprovalReference string
}

// AdoptContribution moves an already verified instance into the contribution
// ledger. Authorization, quota, credentials and existing I/O fences stay valid.
func (s *Service) AdoptContribution(ctx context.Context, actor Principal, key string, request ContributionAdoption) (ContributionSnapshot, error) {
	var result ContributionSnapshot
	c := request.Control
	if !validID(request.InstanceID) || !request.Owner.Valid() || !validID(request.ApprovalReference) ||
		!validID(c.ID) || c.OwnerDomain != ContributionOwnerDomain(request.Owner) || c.Revision != 1 ||
		c.State != "active" || c.ExpectedRevision < 1 || c.LimitBytes < 1 || c.PersonalReserve < 0 || c.Until.IsZero() {
		return result, ErrInput
	}
	guard := func(Transaction) error {
		return s.authorize(ctx, actor, "storage.contributions.adopt", request.InstanceID, Protection{})
	}
	err := s.mutation(ctx, actor, "storage.contributions.adopt", request.InstanceID, key, request, guard, func(tx Transaction) (any, error) {
		if err := tx.Lock("instance-registry"); err != nil {
			return nil, err
		}
		i, err := tx.Instance(request.InstanceID)
		if err != nil {
			return nil, err
		}
		if i.Ownership == "contributor" && i.OwnerDomain == c.OwnerDomain && i.ContributionControl != nil &&
			i.ContributionControl.ID == c.ID && i.ContributionApproval == request.ApprovalReference {
			return s.contributionSnapshot(tx, i)
		}
		now := s.now()
		if !canAdopt(i, c, now) {
			return nil, ErrConflict
		}
		policy, err := readAdmissionPolicy(tx)
		if err != nil {
			return nil, err
		}
		i.Ownership, i.OwnerDomain = "contributor", c.OwnerDomain
		i.ContributionControl = &c
		i.ContributionApproval = request.ApprovalReference
		levels := policy.levels(i)
		i.ContributionLevels = &levels
		for _, admission := range i.Admissions {
			protection := Protection{Class: admission.Class, Scope: admission.Scope, Public: admission.Class == "public"}
			if admission.Plaintext && admission.ExpiresAt.After(now) && admission.Class != PaidRestrictedClass && !i.Allows(protection, now) {
				return nil, ErrDenied
			}
		}
		if err := tx.SaveInstance(i); err != nil {
			return nil, err
		}
		snapshot, err := s.contributionSnapshot(tx, i)
		if err != nil {
			return nil, err
		}
		return snapshot, tx.Event(Event{ID: newID(), Type: "storage.instance.contribution_adopted", ObjectID: i.ID,
			Revision: i.Revision, Time: now, Actor: actor, TraceParent: TraceParentFromContext(ctx),
			AuditResult: "success", AuditSchool: "*", Reason: request.ApprovalReference})
	}, &result)
	return result, err
}

func canAdopt(i Instance, control ContributionControl, now time.Time) bool {
	return i.Ownership == "platform" && i.ContributionControl == nil && i.Revision == control.ExpectedRevision &&
		i.Authorized && i.State == "active" && i.ExpiresAt.After(now) && i.QuotaExpiresAt.After(now) &&
		i.Limit == control.LimitBytes && i.PersonalReserve == control.PersonalReserve && i.ExpiresAt.Equal(control.Until)
}
