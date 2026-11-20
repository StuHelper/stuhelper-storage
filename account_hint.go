package storage

import "context"

// AccountHintSource projects a masked provider login from trusted local account
// facts. An empty result means no verified hint is available.
type AccountHintSource interface {
	AccountHint(context.Context, Instance) string
}

// ContributionAccountHints reads hints for a page of authorized contribution
// views. The map associates instance IDs with the expected contributor domains.
// Missing, inaccessible or unavailable facts are omitted.
func (s *Service) ContributionAccountHints(ctx context.Context, p Principal, ownersByInstance map[string]string) map[string]string {
	if s.accountHints == nil || len(ownersByInstance) == 0 || len(ownersByInstance) > 100 {
		return nil
	}
	ids := make([]string, 0, len(ownersByInstance))
	for id := range ownersByInstance {
		if s.authorize(ctx, p, "storage.contributions.read", id, Protection{}) == nil {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	var instances []Instance
	if err := s.readTx(ctx, func(tx Transaction) error {
		var err error
		instances, err = tx.InstanceSnapshots(ids)
		return err
	}); err != nil {
		return nil
	}

	hints := make(map[string]string, len(instances))
	for _, i := range instances {
		if i.Ownership != "contributor" || i.OwnerDomain != ownersByInstance[i.ID] || !i.Authorized {
			continue
		}
		if hint := s.accountHints.AccountHint(ctx, i); hint != "" {
			hints[i.ID] = hint
		}
	}
	return hints
}
