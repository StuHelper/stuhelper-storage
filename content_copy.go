package storage

import (
	"context"
	"io"
)

func (s *Service) changeContentProtection(ctx context.Context, p Principal, id, key string, revision int64, protection Protection) (Status, error) {
	if !protection.Valid() {
		return Status{}, ErrInput
	}
	var h ContentHandle
	var g ContentGroup
	var out Status
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
	if err = s.resumeContentCopy(ctx, p, id); err != nil {
		return out, err
	}
	return s.contentStatus(ctx, p, id)
}

// A pending destination and source pin are durable. Copying is resumable after
// timeout, response loss or restart; the immutable destination is reconciled
// before any new provider write. Restrictive changes block the handle immediately.
func (s *Service) resumeContentCopy(ctx context.Context, p Principal, id string) error {
	var h ContentHandle
	var source Object
	var target ContentGroup
	var previous ContentGroup
	err := s.repo.Transaction(ctx, func(tx Transaction) error {
		var e error
		h, previous, e = s.contentGuard(ctx, tx, p, "storage.objects.create", id)
		if e != nil {
			return e
		}
		if h.State != "active" {
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
	st, err := s.ensureContentObject(ctx, target)
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
		if _, e = f.Seek(0, io.SeekStart); e != nil {
			return ErrUnavailable
		}
		if _, e = s.Ingest(ctx, p, target.ObjectID, "content-copy:"+target.ID, f); e != nil {
			return e
		}
	}
	var released []string
	err = s.repo.Transaction(ctx, func(tx Transaction) error {
		current, g, e := s.contentGuard(ctx, tx, p, "storage.objects.create", id)
		if e != nil {
			return e
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
			if e := s.cleanupContentGroup(ctx, gid); e != nil {
				return e
			}
		}
	}
	return nil
}
