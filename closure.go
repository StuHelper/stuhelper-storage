package storage

import (
	"context"
	"errors"
)

var ErrOwnerNotDrained = errors.New("storage_owner_not_drained")
var ErrClosureProgress = errors.New("storage_closure_processing")

// SetOwnerClosure overlays a group-wide write barrier on current instance
// settings. Cancel removes only this closure, preserving independent revocations.
func (s *Service) SetOwnerClosure(ctx context.Context, actor Principal, owner, closureID string, cancel bool) error {
	if !validID(owner) || !validID(closureID) {
		return ErrInput
	}
	if err := s.authorize(ctx, actor, "storage.instances.manage", owner, Protection{}); err != nil {
		return err
	}
	return s.repo.Transaction(ctx, func(tx Transaction) error { return tx.SetOwnerClosure(owner, closureID, cancel) })
}

func (s *Service) OwnerDrainComplete(ctx context.Context, actor Principal, owner, closureID string) (bool, error) {
	if !validID(owner) || !validID(closureID) {
		return false, ErrInput
	}
	if err := s.authorize(ctx, actor, "storage.instances.read", owner, Protection{}); err != nil {
		return false, err
	}
	var done bool
	err := s.readTx(ctx, func(tx Transaction) error {
		var err error
		done, err = tx.OwnerDrainComplete(owner, closureID)
		return err
	})
	return done, err
}

func (s *Service) OwnerInstances(ctx context.Context, actor Principal, owner, after string, limit int) ([]Instance, error) {
	if !validID(owner) || (after != "" && !validID(after)) || limit < 1 || limit > 100 {
		return nil, ErrInput
	}
	if err := s.authorize(ctx, actor, "storage.instances.read", owner, Protection{}); err != nil {
		return nil, err
	}
	var instances []Instance
	err := s.readTx(ctx, func(tx Transaction) error {
		var err error
		instances, err = tx.OwnerInstances(owner, after, limit)
		return err
	})
	return instances, err
}

func (s *Service) FinalizeOwnerDrain(ctx context.Context, actor Principal, owner, closureID string, principal Principal) (bool, error) {
	if !principal.Valid() || !validID(owner) || !validID(closureID) {
		return false, ErrInput
	}
	if err := s.authorize(ctx, actor, "storage.instances.manage", owner, Protection{}); err != nil {
		return false, err
	}
	var done bool
	err := s.repo.Transaction(ctx, func(tx Transaction) error {
		var err error
		done, err = tx.FinalizeOwnerDrain(owner, closureID, principal.Issuer, principal.Subject)
		return err
	})
	return done, err
}

func (s *Service) OwnerCleanup(ctx context.Context, actor Principal, owner, id string) (OwnerCleanup, error) {
	var out OwnerCleanup
	if !validID(owner) || !validID(id) {
		return out, ErrInput
	}
	if err := s.authorize(ctx, actor, "storage.instances.manage", owner, Protection{}); err != nil {
		return out, err
	}
	err := s.readTx(ctx, func(tx Transaction) error { var err error; out, err = tx.OwnerCleanup(owner, id); return err })
	return out, err
}
func (s *Service) AdvanceOwnerCleanup(ctx context.Context, actor Principal, owner, id string, prior, next OwnerCleanup) error {
	if !validID(owner) || !validID(id) || prior.InstancesDone && !next.InstancesDone || prior.BindingsDone && !next.BindingsDone || next.InstanceCursor < prior.InstanceCursor || next.BindingCursor < prior.BindingCursor {
		return ErrInput
	}
	if err := s.authorize(ctx, actor, "storage.instances.manage", owner, Protection{}); err != nil {
		return err
	}
	return s.repo.Transaction(ctx, func(tx Transaction) error { return tx.AdvanceOwnerCleanup(owner, id, prior, next) })
}
