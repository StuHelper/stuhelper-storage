package storage

import (
	"context"
	"errors"
	"io"
	"strings"
	"time"
)

// ContentGroup owns one immutable physical object. Handles retain independent
// authorization, references and publication state. Group identity includes the
// service principal and every placement requirement; a digest is not access proof.
type ContentGroup struct {
	CleanupCheckedAt time.Time  `json:"cleanup_checked_at"`
	ID               string     `json:"id"`
	Fingerprint      string     `json:"fingerprint"`
	ObjectID         string     `json:"object_id"`
	Owner            Principal  `json:"owner"`
	Size             int64      `json:"size"`
	SHA256           string     `json:"sha256"`
	Protection       Protection `json:"protection"`
	Policy           Policy     `json:"policy"`
	State            string     `json:"state"`
}
type ContentHandle struct {
	CreatedAt    time.Time   `json:"created_at"`
	ID           string      `json:"id"`
	GroupID      string      `json:"group_id"`
	Owner        Principal   `json:"owner"`
	CreationHash string      `json:"creation_hash"`
	Revision     int64       `json:"revision"`
	State        string      `json:"state"`
	Verified     bool        `json:"verified"`
	Published    bool        `json:"published"`
	References   []Reference `json:"references"`
	SourceGroup  string      `json:"source_group,omitempty"`
	SourceObject string      `json:"source_object,omitempty"`
	SourceID     string      `json:"source_id,omitempty"`
	PendingGroup string      `json:"pending_group,omitempty"`
}

func contentID(id string) bool { return strings.HasPrefix(id, "content-") }

// The global content ledger lock covers short metadata transactions only. It
// orders handle/group changes and pins. Provider transfers never hold this lock.
func (s *Service) contentGuard(ctx context.Context, tx Transaction, p Principal, action, id string) (ContentHandle, ContentGroup, error) {
	if !validID(id) {
		return ContentHandle{}, ContentGroup{}, ErrInput
	}
	if err := tx.Lock("content-ledger"); err != nil {
		return ContentHandle{}, ContentGroup{}, err
	}
	h, err := tx.ContentHandle(id)
	if err != nil {
		return h, ContentGroup{}, err
	}
	g, err := tx.ContentGroup(h.GroupID)
	if err != nil {
		return h, g, err
	}
	if h.Owner != p {
		return h, g, ErrDenied
	}
	return h, g, s.authorize(ctx, p, action, id, g.Protection)
}
func (s *Service) contentGroup(tx Transaction, p Principal, r CreateRequest) (ContentGroup, error) {
	fingerprint := requestHash(struct {
		Owner      Principal
		Size       int64
		SHA256     string
		Protection Protection
		Policy     Policy
	}{p, r.Size, r.SHA256, r.Protection, r.Policy})
	g, err := tx.ActiveContentGroup(fingerprint)
	if err == nil {
		return g, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return g, err
	}
	g = ContentGroup{ID: newID(), Fingerprint: fingerprint, Owner: p, Size: r.Size, SHA256: r.SHA256, Protection: r.Protection, Policy: r.Policy, State: "active"}
	g.ObjectID = requestHash([]string{"client-object", p.Issuer, p.Subject, "content:" + g.ID})
	return g, tx.SaveContentGroup(g)
}
func (s *Service) contentView(tx Transaction, h ContentHandle, g ContentGroup) (Status, error) {
	out := Status{ID: h.ID, Size: g.Size, SHA256: g.SHA256, Protection: g.Protection, Policy: g.Policy, Revision: h.Revision, State: "pending", Published: h.Published, Desired: g.Policy.Target}
	if h.State != "active" {
		out.State = "deleted"
		if h.Verified && g.State == "deleting" {
			out.State = "deleting"
			o, e := tx.Object(g.ObjectID)
			if e == nil && o.State == "deleted" {
				out.State = "deleted"
			} else if e != nil && !errors.Is(e, ErrNotFound) {
				return out, e
			}
		}
		return out, nil
	}
	if !h.Verified {
		return out, nil
	}
	o, err := tx.Object(g.ObjectID)
	if errors.Is(err, ErrNotFound) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	st, err := s.status(tx, o)
	if err != nil {
		return out, err
	}
	out.Healthy = st.Healthy
	if st.State == "deleting" || st.State == "deleted" {
		return out, ErrUnavailable
	}
	switch {
	case out.Healthy >= g.Policy.Target:
		out.State = "ready"
	case h.Published && out.Healthy == 0:
		out.State = "unavailable"
	case h.Published || out.Healthy >= g.Policy.Publish:
		out.State = "degraded"
	}
	return out, nil
}
func (s *Service) contentStatus(ctx context.Context, p Principal, id string) (Status, error) {
	var out Status
	err := s.repo.Transaction(ctx, func(tx Transaction) error {
		h, g, e := s.contentGuard(ctx, tx, p, "storage.objects.read", id)
		if e != nil {
			return e
		}
		out, e = s.contentView(tx, h, g)
		return e
	})
	return out, err
}
func (s *Service) createContent(ctx context.Context, p Principal, key string, r CreateRequest) (Status, error) {
	if r.Policy == (Policy{}) {
		r.Policy = DefaultPolicy()
	}
	if r.Size < 1 || r.Size > s.cfg.MaxObjectSize || !digest.MatchString(r.SHA256) || !r.Protection.Valid() || !r.Policy.Valid() || (r.ClientKey != "" && !validID(r.ClientKey)) || (r.ReuseFrom != "" && !validID(r.ReuseFrom)) || r.ContentGroup != "" {
		return Status{}, ErrInput
	}
	var out Status
	err := s.mutation(ctx, p, "storage.contents.create", "", key, r, func(tx Transaction) error {
		if e := tx.Lock("content-ledger"); e != nil {
			return e
		}
		return s.authorize(ctx, p, "storage.objects.create", "", r.Protection)
	}, func(tx Transaction) (any, error) {
		id := "content-" + newID()
		if r.ClientKey != "" {
			id = "content-" + requestHash([]string{p.Issuer, p.Subject, r.ClientKey})
		}
		if h, e := tx.ContentHandle(id); e == nil {
			if h.Owner != p || h.CreationHash != requestHash(r) {
				return nil, ErrConflict
			}
			g, e := tx.ContentGroup(h.GroupID)
			if e != nil {
				return nil, e
			}
			return s.contentView(tx, h, g)
		} else if !errors.Is(e, ErrNotFound) {
			return nil, e
		}
		g, e := s.contentGroup(tx, p, r)
		if e != nil {
			return nil, e
		}
		h := ContentHandle{CreatedAt: s.now(), ID: id, GroupID: g.ID, Owner: p, CreationHash: requestHash(r), Revision: 1, State: "active", References: []Reference{}}
		if r.ReuseFrom != "" {
			object, sourceGroup, e := s.contentSource(ctx, tx, p, r.ReuseFrom)
			if e != nil {
				return nil, e
			}
			if object.Size != g.Size || object.SHA256 != g.SHA256 {
				return nil, ErrConflict
			}
			h.SourceID = r.ReuseFrom
			h.SourceObject = object.ID
			h.SourceGroup = sourceGroup
			if sourceGroup == g.ID {
				h.Verified = true
				h.SourceID = ""
				h.SourceObject = ""
				h.SourceGroup = ""
			}
		}
		if e = tx.SaveContentHandle(h); e != nil {
			return nil, e
		}
		if e = s.emit(tx, p, "storage.content.created", h.ID, h.Revision); e != nil {
			return nil, e
		}
		return s.contentView(tx, h, g)
	}, &out)
	if err != nil {
		return out, err
	}
	if err = s.resumeContentCopy(ctx, p, out.ID); err != nil {
		return out, err
	}
	return s.contentStatus(ctx, p, out.ID)
}
func (s *Service) contentSource(ctx context.Context, tx Transaction, p Principal, id string) (Object, string, error) {
	var o Object
	group := ""
	if contentID(id) {
		h, g, e := s.contentGuard(ctx, tx, p, "storage.objects.reuse", id)
		if e != nil {
			return o, group, e
		}
		if h.State != "active" || !h.Verified || h.PendingGroup != "" {
			return o, group, ErrConflict
		}
		group = g.ID
		var e2 error
		o, e2 = tx.Object(g.ObjectID)
		if e2 != nil {
			return o, group, e2
		}
	} else {
		var e error
		o, e = s.objectGuard(ctx, tx, p, "storage.objects.reuse", id)
		if e != nil {
			return o, group, e
		}
		if o.Owner != p || o.ContentGroup != "" {
			return o, group, ErrDenied
		}
	}
	st, e := s.status(tx, o)
	if e != nil {
		return o, group, e
	}
	if o.State == "deleting" || o.State == "deleted" || st.Healthy < 1 {
		return o, group, ErrUnavailable
	}
	return o, group, nil
}
func (s *Service) ensureContentObject(ctx context.Context, g ContentGroup) (Status, error) {
	if _, err := s.Create(ctx, g.Owner, "content-create:"+g.ID, CreateRequest{ClientKey: "content:" + g.ID, Size: g.Size, SHA256: g.SHA256, Protection: g.Protection, Policy: g.Policy, ContentGroup: g.ID}); err != nil {
		return Status{}, err
	}
	return s.Status(ctx, g.Owner, g.ObjectID)
}
func (s *Service) ingestContent(ctx context.Context, p Principal, id, key string, src io.Reader) (Status, error) {
	if !validKey(key) || src == nil {
		return Status{}, ErrInput
	}
	parent := ctx
	ctx, release, err := s.begin(ctx)
	if err != nil {
		return Status{}, err
	}
	var h ContentHandle
	var g ContentGroup
	err = s.repo.Transaction(ctx, func(tx Transaction) error {
		var e error
		h, g, e = s.contentGuard(ctx, tx, p, "storage.objects.upload", id)
		if e != nil {
			return e
		}
		if h.State != "active" || h.PendingGroup != "" {
			return ErrConflict
		}
		return nil
	})
	if err != nil {
		release()
		return Status{}, err
	}
	f, err := s.staging.create(g.Size + 1)
	if err != nil {
		release()
		return Status{}, err
	}
	defer removeTemporary(f)
	_, err = io.Copy(f, io.LimitReader(&pacedReader{ctx: ctx, src: src, global: s.bandwidth}, g.Size+1))
	if err == nil {
		err = verifyFile(ctx, f, Object{Size: g.Size, SHA256: g.SHA256})
	}
	// A verified durable proof permits recovery to observe another concurrent
	// writer's result. It is committed only after checking the actual complete bytes.
	if err == nil {
		err = s.repo.Transaction(ctx, func(tx Transaction) error {
			current, group, e := s.contentGuard(ctx, tx, p, "storage.objects.upload", id)
			if e != nil {
				return e
			}
			if current.State != "active" || group.ID != g.ID || current.PendingGroup != "" {
				return ErrConflict
			}
			current.Verified = true
			current.SourceID = ""
			current.SourceObject = ""
			old := current.SourceGroup
			current.SourceGroup = ""
			if e = tx.SaveContentHandle(current); e != nil {
				return e
			}
			return s.releaseContentGroup(tx, old)
		})
	}
	// Release the read slot before the core ingest reserves its slot. The staged
	// bytes remain included in the shared disk budget throughout both operations.
	release()
	ctx = parent
	if err != nil {
		return Status{}, err
	}
	if _, err = s.ensureContentObject(ctx, g); err != nil {
		return Status{}, err
	}
	if _, err = s.Ingest(ctx, p, g.ObjectID, key, f); err != nil {
		return Status{}, err
	}
	return s.contentStatus(ctx, p, id)
}
func (s *Service) contentReference(ctx context.Context, p Principal, id, key string, ref Reference, attach bool) (Status, error) {
	if !validID(ref.Module) || !validID(ref.ID) {
		return Status{}, ErrInput
	}
	action := "storage.references.release"
	if attach {
		action = "storage.references.attach"
	}
	var h ContentHandle
	var g ContentGroup
	var out Status
	err := s.mutation(ctx, p, action, id, key, ref, func(tx Transaction) error {
		var e error
		h, g, e = s.contentGuard(ctx, tx, p, action, id)
		if e != nil {
			return e
		}
		return s.authorize(ctx, p, action, ref.Module+":"+ref.ID, g.Protection)
	}, func(tx Transaction) (any, error) {
		if h.State != "active" || h.PendingGroup != "" {
			return nil, ErrConflict
		}
		st, e := s.contentView(tx, h, g)
		if e != nil {
			return nil, e
		}
		index := -1
		for i, v := range h.References {
			if v == ref {
				index = i
				break
			}
		}
		if attach {
			if !h.Verified || st.Healthy < g.Policy.Publish {
				return nil, ErrUnavailable
			}
			if index < 0 {
				if len(h.References) >= 1000 {
					return nil, ErrCapacity
				}
				h.References = append(h.References, ref)
			}
			h.Published = true
			physical, e := tx.Object(g.ObjectID)
			if e != nil {
				return nil, e
			}
			physical.Published = true
			if e = tx.SaveObject(physical); e != nil {
				return nil, e
			}
		} else if index >= 0 {
			h.References = append(h.References[:index], h.References[index+1:]...)
		}
		if e = tx.SaveContentHandle(h); e != nil {
			return nil, e
		}
		if e = s.emit(tx, p, action, h.ID, h.Revision); e != nil {
			return nil, e
		}
		return s.contentView(tx, h, g)
	}, &out)
	return out, err
}
func (s *Service) releaseContentGroup(tx Transaction, id string) error {
	if id == "" {
		return nil
	}
	held, e := tx.ContentGroupHeld(id)
	if e != nil || held {
		return e
	}
	g, e := tx.ContentGroup(id)
	if e != nil {
		return e
	}
	if g.State == "active" {
		g.State = "deleting"
		return tx.SaveContentGroup(g)
	}
	return nil
}
func (s *Service) deleteContent(ctx context.Context, p Principal, id, key string, revision int64) (Status, error) {
	var h ContentHandle
	var g ContentGroup
	var out Status
	err := s.mutation(ctx, p, "storage.objects.delete", id, key, revision, func(tx Transaction) error {
		var e error
		h, g, e = s.contentGuard(ctx, tx, p, "storage.objects.delete", id)
		return e
	}, func(tx Transaction) (any, error) {
		if h.State != "active" {
			return s.contentView(tx, h, g)
		}
		if h.Revision != revision || len(h.References) > 0 {
			return nil, ErrConflict
		}
		h.State = "deleted"
		h.Revision++
		if e := tx.SaveContentHandle(h); e != nil {
			return nil, e
		}
		for _, gid := range []string{h.GroupID, h.SourceGroup, h.PendingGroup} {
			if e := s.releaseContentGroup(tx, gid); e != nil {
				return nil, e
			}
		}
		if e := s.emit(tx, p, "storage.content.released", h.ID, h.Revision); e != nil {
			return nil, e
		}
		return s.contentView(tx, h, g)
	}, &out)
	if err == nil {
		err = s.cleanupContentGroup(ctx, g.ID)
	}
	return out, err
}
func (s *Service) downloadContent(ctx context.Context, p Principal, id string, dst io.Writer, review bool) error {
	if dst == nil {
		return ErrInput
	}
	action := "storage.objects.download"
	if review {
		action = "storage.objects.review"
	}
	var object string
	var revision int64
	check := func() error {
		return s.repo.Transaction(ctx, func(tx Transaction) error {
			h, g, e := s.contentGuard(ctx, tx, p, action, id)
			if e != nil {
				return e
			}
			if h.State != "active" || !h.Verified || h.PendingGroup != "" {
				return ErrDenied
			}
			st, e := s.contentView(tx, h, g)
			if e != nil {
				return e
			}
			if st.Healthy < 1 || (!review && !h.Published && st.Healthy < g.Policy.Publish) {
				return ErrUnavailable
			}
			if object != "" && (object != g.ObjectID || revision != h.Revision) {
				return ErrStale
			}
			object = g.ObjectID
			revision = h.Revision
			return nil
		})
	}
	if e := check(); e != nil {
		return e
	}
	// The handle gate above prevents inheriting another handle's publication.
	return s.download(ctx, p, object, &contentWriter{check: check, dst: dst}, review)
}

type contentWriter struct {
	check   func() error
	dst     io.Writer
	checked bool
}

func (w *contentWriter) Write(b []byte) (int, error) {
	if !w.checked {
		if e := w.check(); e != nil {
			return 0, e
		}
		w.checked = true
	}
	return w.dst.Write(b)
}

func (s *Service) cleanupContents(ctx context.Context, p Principal, limit int) error {
	if err := s.expireContentHandles(ctx, p, limit); err != nil {
		return err
	}
	var groups []ContentGroup
	err := s.repo.Transaction(ctx, func(tx Transaction) error { var e error; groups, e = tx.ContentCleanup(limit, ""); return e })
	if err != nil {
		return err
	}
	var first error
	for _, g := range groups {
		if e := s.authorize(ctx, p, "storage.maintenance", g.ObjectID, g.Protection); e != nil {
			return e
		}
		if e := s.cleanupContentGroup(ctx, g.ID); e != nil && first == nil {
			first = e
		}
	}
	return first
}
func (s *Service) cleanupContentGroup(ctx context.Context, id string) error {
	var g ContentGroup
	err := s.repo.Transaction(ctx, func(tx Transaction) error {
		if e := tx.Lock("content-ledger"); e != nil {
			return e
		}
		var e error
		g, e = tx.ContentGroup(id)
		if e != nil {
			return e
		}
		held, e := tx.ContentGroupHeld(id)
		if e != nil {
			return e
		}
		if held || g.State == "active" {
			g = ContentGroup{}
			return nil
		}
		g.CleanupCheckedAt = s.now()
		return tx.SaveContentGroup(g)
	})
	if err != nil || g.ID == "" || g.State == "deleted" {
		return err
	}
	// Materialize a possible lost create response with the stable key before
	// deletion. This prevents a late create from escaping an earlier release.
	st, err := s.ensureContentObject(ctx, g)
	if err != nil {
		return err
	}
	if st.State != "deleted" && st.State != "deleting" {
		st, err = s.deleteObject(ctx, g.Owner, g.ObjectID, "content-delete:"+g.ID, st.Revision, true)
		if err != nil {
			return err
		}
	}
	if st.State != "deleted" {
		return nil
	}
	return s.repo.Transaction(ctx, func(tx Transaction) error {
		if e := tx.Lock("content-ledger"); e != nil {
			return e
		}
		current, e := tx.ContentGroup(id)
		if e != nil {
			return e
		}
		if current.State != "deleting" {
			return ErrConflict
		}
		current.State = "deleted"
		return tx.SaveContentGroup(current)
	})
}

// Storage applies the same 24-hour unreferenced lifetime to both old objects
// and shared handles. A crashed caller cannot pin otherwise unused content forever.
func (s *Service) expireContentHandles(ctx context.Context, p Principal, limit int) error {
	return s.repo.Transaction(ctx, func(tx Transaction) error {
		if e := tx.Lock("content-ledger"); e != nil {
			return e
		}
		rows, e := tx.ExpiredContentHandles(limit, s.now().Add(-24*time.Hour))
		if e != nil {
			return e
		}
		for _, h := range rows {
			g, e := tx.ContentGroup(h.GroupID)
			if e != nil {
				return e
			}
			if e = s.authorize(ctx, p, "storage.maintenance", h.ID, g.Protection); e != nil {
				return e
			}
			if h.State != "active" || len(h.References) > 0 {
				continue
			}
			h.State = "deleted"
			h.Revision++
			if e = tx.SaveContentHandle(h); e != nil {
				return e
			}
			for _, gid := range []string{h.GroupID, h.SourceGroup, h.PendingGroup} {
				if e = s.releaseContentGroup(tx, gid); e != nil {
					return e
				}
			}
			if e = s.emit(tx, p, "storage.content.expired", h.ID, h.Revision); e != nil {
				return e
			}
		}
		return nil
	})
}
