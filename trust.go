package storage

import (
	"context"
	"slices"
	"time"
)

// TrustConsent records the owner's decision for one instance and one school.
// Paid content authorization covers only the application-encrypted representation.
type TrustConsent struct {
	Scope      string    `json:"scope"`
	Classes    []string  `json:"classes"`
	Until      time.Time `json:"until"`
	RecordedAt time.Time `json:"recorded_at"`
	Source     string    `json:"source"`
}

type TrustConsentRequest struct {
	Revision int64     `json:"revision"`
	Scope    string    `json:"scope"`
	Classes  []string  `json:"classes"`
	Until    time.Time `json:"until"`
}

type TrustState struct {
	Revision        int64         `json:"revision"`
	Trusted         bool          `json:"trusted"`
	Consent         *TrustConsent `json:"consent,omitempty"`
	AvailableScopes []string      `json:"available_scopes"`
	MaximumUntil    time.Time     `json:"maximum_until"`
}

func (i Instance) trustState(now time.Time) TrustState {
	scopes := []string{}
	for _, a := range i.Admissions {
		if a.Class == "public" && a.ExpiresAt.After(now) && !slices.Contains(scopes, a.Scope) {
			scopes = append(scopes, a.Scope)
		}
	}
	slices.Sort(scopes)
	return TrustState{i.Revision, i.trustEffective(now), i.TrustConsent, scopes, i.ExpiresAt}
}

func (i Instance) trustEffective(now time.Time) bool {
	return i.Trusted && i.TrustConsent != nil && i.TrustConsent.Until.After(now) &&
		i.Authorized && i.State != "revoked" && i.ExpiresAt.After(now)
}

func (s *Service) ownTrustInstance(ctx context.Context, tx Transaction, p Principal, id, action string) (Instance, error) {
	if err := s.authorize(ctx, p, action, id, Protection{}); err != nil {
		return Instance{}, err
	}
	i, err := tx.InstanceSnapshot(id)
	if err != nil {
		return Instance{}, err
	}
	if i.Ownership != "contributor" || i.OwnerDomain != ContributionOwnerDomain(p) {
		return Instance{}, ErrDenied
	}
	return i, nil
}

func (s *Service) OwnTrustConsent(ctx context.Context, p Principal, id string) (TrustState, error) {
	var result TrustState
	if !validID(id) {
		return result, ErrInput
	}
	err := s.readTx(ctx, func(tx Transaction) error {
		i, err := s.ownTrustInstance(ctx, tx, p, id, "storage.custody.read")
		if err == nil {
			result = i.trustState(s.now())
		}
		return err
	})
	return result, err
}

func (s *Service) SetOwnTrustConsent(ctx context.Context, p Principal, id, key string, r TrustConsentRequest) (TrustState, error) {
	guard := func(tx Transaction) error {
		_, err := s.ownTrustInstance(ctx, tx, p, id, "storage.custody.manage")
		return err
	}
	return s.recordTrustConsent(ctx, p, id, key, r, "owner_session", time.Time{}, guard)
}

// RecordConfirmedTrustConsent accepts a previously recorded explicit decision through
// the private host's attestation service. No HTTP route grants this authority.
func (s *Service) RecordConfirmedTrustConsent(ctx context.Context, operator, owner Principal, id, key string, r TrustConsentRequest, confirmedAt time.Time) (TrustState, error) {
	if !owner.Valid() || confirmedAt.IsZero() || confirmedAt.After(s.now()) {
		return TrustState{}, ErrInput
	}
	guard := func(tx Transaction) error {
		if err := s.authorize(ctx, operator, "storage.trust.attest", id, Protection{}); err != nil {
			return err
		}
		i, err := tx.InstanceSnapshot(id)
		if err != nil {
			return err
		}
		if i.OwnerDomain != ContributionOwnerDomain(owner) || i.Ownership != "contributor" {
			return ErrDenied
		}
		return nil
	}
	return s.recordTrustConsent(ctx, operator, id, key, r, "confirmed_by_owner", confirmedAt, guard)
}

func (s *Service) recordTrustConsent(ctx context.Context, p Principal, id, key string, r TrustConsentRequest, source string, confirmedAt time.Time, guard func(Transaction) error) (TrustState, error) {
	var out TrustState
	if !validID(id) || !validID(r.Scope) || r.Revision < 1 || !validIDList(r.Classes, 2) {
		return out, ErrInput
	}
	for _, class := range r.Classes {
		if class != "quarantine" && class != "restricted" {
			return out, ErrInput
		}
	}
	payload := struct {
		TrustConsentRequest
		Source      string
		ConfirmedAt time.Time
	}{r, source, confirmedAt}
	err := s.mutation(ctx, p, "storage.trust.consent", id, key, payload, guard, func(tx Transaction) (any, error) {
		if err := tx.Lock("instance-registry"); err != nil {
			return nil, err
		}
		i, err := tx.Instance(id)
		if err != nil {
			return nil, err
		}
		if i.Revision != r.Revision {
			return nil, ErrStale
		}
		now := s.now()
		if len(r.Classes) > 0 {
			if !i.Authorized || i.State == "revoked" || !slices.Contains(i.trustState(now).AvailableScopes, r.Scope) ||
				!r.Until.After(now) || r.Until.After(i.ExpiresAt) {
				return nil, ErrDenied
			}
			at := confirmedAt
			if at.IsZero() {
				at = now
			}
			i.TrustConsent = &TrustConsent{r.Scope, slices.Sorted(slices.Values(r.Classes)), r.Until, at, source}
		} else {
			i.TrustConsent = nil
		}
		// Changed consent always requires a new operator approval.
		i.Trusted = false
		i.Revision++
		if err := tx.SaveInstance(i); err != nil {
			return nil, err
		}
		out := i.trustState(now)
		return out, tx.Event(Event{ID: newID(), Type: "storage.instance.trust_consent", ObjectID: id, Revision: i.Revision,
			Time: now, Actor: p, AuditSchool: r.Scope, AuditResult: "success", TraceParent: TraceParentFromContext(ctx), TrustDecision: &out})
	}, &out)
	return out, err
}
