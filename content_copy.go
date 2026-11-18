package storage

import "context"

func (s *Service) changeContentProtection(ctx context.Context, p Principal, id, key string, revision int64, protection Protection) (Status, error) {
	if !protection.Valid() {
		return Status{}, ErrInput
	}
	var h ContentHandle
	var g ContentGroup
	var out Status
	cancelledGroup := ""
	err := s.mutation(ctx, p, "storage.protection.change", id, key, struct {
		Revision   int64
		Protection Protection
	}{revision, protection}, func(tx Transaction) error {
		var e error
		h, g, e = s.contentGuard(ctx, tx, p, "storage.protection.change", id)
		if e != nil {
			return e
		}
		return s.authorize(ctx, p, "storage.protection.assign", id, protection)
	}, func(tx Transaction) (any, error) {
		if h.State != "active" || h.Revision != revision || len(h.References) > 0 || !h.Verified {
			return nil, ErrConflict
		}
		if g.Protection == protection {
			if h.PendingGroup != "" {
				cancelledGroup = h.PendingGroup
				h.PendingGroup = ""
				h.Revision++
				if e := tx.SaveContentHandle(h); e != nil {
					return nil, e
				}
				if e := s.releaseContentGroup(tx, cancelledGroup); e != nil {
					return nil, e
				}
				if e := s.emit(tx, p, "storage.content.protection.cancelled", id, h.Revision); e != nil {
					return nil, e
				}
			}
			return s.contentView(tx, h, g)
		}
		target, e := s.contentGroup(tx, p, CreateRequest{Size: g.Size, SHA256: g.SHA256, Protection: protection, Policy: g.Policy})
		if e != nil {
			return nil, e
		}
		if h.PendingGroup != "" && h.PendingGroup != target.ID {
			return nil, ErrConflict
		}
		h.PendingGroup = target.ID
		if e = tx.SaveContentHandle(h); e != nil {
			return nil, e
		}
		if e = s.emit(tx, p, "storage.content.protection.requested", id, h.Revision); e != nil {
			return nil, e
		}
		return s.contentView(tx, h, g)
	}, &out)
	if err != nil {
		return out, err
	}
	if cancelledGroup != "" {
		if err = s.cleanupContentGroup(ctx, p, cancelledGroup); err != nil {
			return out, err
		}
		return s.contentStatusAction(ctx, p, id, "storage.protection.change")
	}
	if out.Protection == protection {
		return out, nil
	}
	if err = s.resumeContentCopy(ctx, p, id, h.PendingGroup, revision); err != nil {
		return out, err
	}
	return s.contentStatusAction(ctx, p, id, "storage.protection.change")
}

// A pending destination and source pin are durable. Copying is resumable after
// timeout, response loss or restart; the immutable destination is reconciled
// before any new provider write. Restrictive changes block the handle immediately.
func (s *Service) resumeContentCopy(ctx context.Context, p Principal, id, pendingGroup string, revision int64) error {
	var h ContentHandle
	var source Object
	var target ContentGroup
	var previous ContentGroup
	err := s.repo.Transaction(ctx, func(tx Transaction) error {
		if !validID(id) {
			return ErrInput
		}
		if e := tx.Lock("content-ledger"); e != nil {
			return e
		}
		var e error
		h, e = tx.ContentHandle(id)
		if e != nil {
			return e
		}
		previous, e = tx.ContentGroup(h.GroupID)
		if e != nil {
			return e
		}
		if h.Owner != p {
			return ErrDenied
		}
		if h.State != "active" || h.PendingGroup != pendingGroup || (revision != 0 && (h.Revision != revision || pendingGroup == "")) {
			return nil
		}
		target = previous
		if h.PendingGroup != "" {
			if e = s.authorize(ctx, p, "storage.protection.change", id, previous.Protection); e != nil {
				return e
			}
			target, e = tx.ContentGroup(h.PendingGroup)
			if e != nil {
				return e
			}
			if e = s.authorize(ctx, p, "storage.protection.assign", id, target.Protection); e != nil {
				return e
			}
			source, e = tx.Object(previous.ObjectID)
			if e != nil {
				return e
			}
		} else if h.SourceObject != "" {
			if e = s.authorize(ctx, p, "storage.objects.create", id, previous.Protection); e != nil {
				return e
			}
			source, _, e = s.contentSource(ctx, tx, p, h.SourceID)
			if e != nil {
				return e
			}
			if source.ID != h.SourceObject {
				return ErrConflict
			}
		} else {
			return nil
		}
		if target.State != "active" || source.Size != target.Size || source.SHA256 != target.SHA256 {
			return ErrConflict
		}
		st, e := s.status(tx, source)
		if e != nil {
			return e
		}
		if st.Healthy < 1 || source.State == "deleted" || source.State == "deleting" {
			return ErrUnavailable
		}
		return nil
	})
	if err != nil || source.ID == "" {
		return err
	}
	st, err := s.ensureContentObject(ctx, p, target)
	if err != nil {
		return err
	}
	if st.State == "deleting" || st.State == "deleted" {
		return ErrConflict
	}
	if st.Healthy < 1 {
		work, release, e := s.begin(ctx)
		if e != nil {
			return e
		}
		f, e := s.readSource(work, source, "")
		release()
		if e != nil {
			return e
		}
		defer removeTemporary(f)
		checkAuth := func(tx Transaction) error {
			if h.PendingGroup != "" {
				if e := s.authorize(ctx, p, "storage.protection.change", id, previous.Protection); e != nil {
					return e
				}
				return s.authorize(ctx, p, "storage.protection.assign", id, target.Protection)
			}
			if e := s.authorize(ctx, p, "storage.objects.create", id, previous.Protection); e != nil {
				return e
			}
			_, _, e := s.contentSource(ctx, tx, p, h.SourceID)
			return e
		}
		if e = s.writeContentObject(ctx, target, f, checkAuth); e != nil {
			return e
		}
	}
	var released []string
	err = s.repo.Transaction(ctx, func(tx Transaction) error {
		if e := tx.Lock("content-ledger"); e != nil {
			return e
		}
		current, e := tx.ContentHandle(id)
		if e != nil {
			return e
		}
		g, e := tx.ContentGroup(current.GroupID)
		if e != nil {
			return e
		}
		if current.Owner != p {
			return ErrDenied
		}
		if current.State != "active" || current.Revision != h.Revision || current.PendingGroup != h.PendingGroup || current.SourceObject != h.SourceObject || g.ID != previous.ID {
			return ErrConflict
		}
		if current.PendingGroup != "" {
			if e = s.authorize(ctx, p, "storage.protection.change", id, g.Protection); e != nil {
				return e
			}
			if e = s.authorize(ctx, p, "storage.protection.assign", id, target.Protection); e != nil {
				return e
			}
			released = append(released, current.GroupID)
			current.GroupID = current.PendingGroup
			current.PendingGroup = ""
			current.Revision++
		} else if current.SourceID != "" {
			if e = s.authorize(ctx, p, "storage.objects.create", id, g.Protection); e != nil {
				return e
			}
			if _, _, e = s.contentSource(ctx, tx, p, current.SourceID); e != nil {
				return e
			}
		}
		current.Verified = true
		released = append(released, current.SourceGroup)
		current.SourceGroup = ""
		current.SourceObject = ""
		current.SourceID = ""
		if e = tx.SaveContentHandle(current); e != nil {
			return e
		}
		for _, gid := range released {
			if e = s.releaseContentGroup(tx, gid); e != nil {
				return e
			}
		}
		return s.emit(tx, p, "storage.content.reused", id, current.Revision)
	})
	if err != nil {
		return err
	}
	for _, gid := range released {
		if gid != "" {
			if e := s.cleanupContentGroup(ctx, p, gid); e != nil {
				return e
			}
		}
	}
	return nil
}
