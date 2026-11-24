// Package storagetest creates synthetic contribution ledgers for integration tests.
package storagetest

import (
	"context"

	storage "github.com/StuHelper/stuhelper-storage"
)

// RegisterContribution follows the same two public service operations as user
// enrollment and consent. Actor must have the permissions for both operations.
func RegisterContribution(ctx context.Context, service *storage.Service, actor storage.Principal, key string, input storage.Instance) (storage.Instance, error) {
	limit := input.Limit
	input.Ownership = "contributor"
	input.State = "paused"
	input.Limit = 0
	i, err := service.Register(ctx, actor, key, input)
	if err != nil {
		return i, err
	}
	if limit == 0 {
		return i, nil
	}
	control := storage.ContributionControl{ID: "fixture-" + i.ID, State: "active", OwnerDomain: i.OwnerDomain, Revision: 1,
		ExpectedRevision: i.Revision, LimitBytes: limit, Until: i.ExpiresAt, PersonalReserve: i.PersonalReserve}
	snap, err := service.ApplyContribution(ctx, actor, i.ID, control)
	if err != nil {
		return storage.Instance{}, err
	}
	i.State, i.Revision, i.Limit, i.ContributionControl = snap.State, snap.Revision, snap.Control.LimitBytes, snap.Control
	return i, nil
}

// Trust records both decisions for an explicitly authorized synthetic instance.
func Trust(ctx context.Context, service *storage.Service, actor storage.Principal, i storage.Instance, scope string, classes []string) (storage.Instance, error) {
	consent, err := service.SetOwnTrustConsent(ctx, actor, i.ID, "consent-"+i.ID, storage.TrustConsentRequest{Revision: i.Revision, Classes: classes, Scope: scope, Until: i.ExpiresAt})
	if err != nil {
		return i, err
	}
	approved, err := service.CommandInstance(ctx, actor, i.ID, "trust-"+i.ID, storage.InstanceCommand{Revision: consent.Revision, Action: "trust"})
	if err != nil {
		return i, err
	}
	i.Trusted, i.TrustConsent, i.Revision = approved.Trusted, approved.TrustConsent, approved.Revision
	return i, nil
}
