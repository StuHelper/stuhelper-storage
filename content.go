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
	return s.contentViewWith(tx, h, g, tx.Object, s.status)
}
func (s *Service) contentViewSnapshot(tx Transaction, h ContentHandle, g ContentGroup) (Status, error) {
	return s.contentViewWith(tx, h, g, tx.ObjectSnapshot, s.statusSnapshot)
}
func (s *Service) contentViewWith(tx Transaction, h ContentHandle, g ContentGroup, readObj func(string) (Object, error), statusFn func(Transaction, Object) (Status, error)) (Status, error) {
	out := Status{ID: h.ID, Size: g.Size, SHA256: g.SHA256, Protection: g.Protection, Policy: g.Policy, Revision: h.Revision, State: "pending", Published: h.Published, Desired: g.Policy.Target}
	if h.State != "active" {
		out.State = "deleted"
		if !h.Verified && h.SourceObject == "" && h.PendingGroup == "" {
			return out, nil
		}
		for _, id := range []string{h.GroupID, h.SourceGroup, h.PendingGroup} {
			if id == "" {
				continue
			}
			group, e := tx.ContentGroup(id)
			if e != nil {
				return out, e
			}
			if group.State != "deleting" {
				continue
			}
			object, e := readObj(group.ObjectID)
			if errors.Is(e, ErrNotFound) {
				out.State = "deleting"
				continue
			}
			if e != nil {
				return out, e
			}
			if object.State != "deleted" {
				out.State = "deleting"
			}
		}
		return out, nil
	}
	if !h.Verified {
		return out, nil
	}
	o, err := readObj(g.ObjectID)
	if errors.Is(err, ErrNotFound) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	st, err := statusFn(tx, o)
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
	return s.contentStatusAction(ctx, p, id, "storage.objects.read")
}
func (s *Service) contentStatusAction(ctx context.Context, p Principal, id, action string) (Status, error) {
	if !validID(id) {
		return Status{}, ErrInput
	}
	var out Status
	err := s.readTx(ctx, func(tx Transaction) error {
		h, e := tx.ContentHandle(id)
		if e != nil {
			return e
		}
		g, e := tx.ContentGroup(h.GroupID)
		if e != nil {
			return e
		}
		if h.Owner != p {
			return ErrDenied
		}
		if e = s.authorize(ctx, p, action, id, g.Protection); e != nil {
			return e
		}
		out, e = s.contentViewSnapshot(tx, h, g)
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
		if e = s.emitScoped(tx, p, "storage.content.created", h.ID, h.Revision, "success", g.Protection.Scope); e != nil {
			return nil, e
		}
		return s.contentView(tx, h, g)
	}, &out)
	if err != nil {
		return out, err
	}
	if err = s.resumeContentCopy(ctx, p, out.ID, "", 0); err != nil {
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
func (s *Service) ensureContentObject(ctx context.Context, actor Principal, g ContentGroup) (Status, error) {
	var out Status
	err := s.repo.Transaction(ctx, func(tx Transaction) error {
		if err := tx.Lock("object:" + g.ObjectID); err != nil {
			return err
		}
		existing, err := tx.Object(g.ObjectID)
		if err == nil {
			out, err = s.status(tx, existing)
			return err
		}
		if !errors.Is(err, ErrNotFound) {
			return err
		}
		creation := CreateRequest{ClientKey: "content:" + g.ID, Size: g.Size, SHA256: g.SHA256, Protection: g.Protection, Policy: g.Policy}
		o := Object{
			ContentGroup: g.ID,
			CreationHash: requestHash(creation),
			ID:           g.ObjectID,
			Owner:        g.Owner,
			Size:         g.Size,
			SHA256:       g.SHA256,
			Protection:   g.Protection,
			Policy:       g.Policy,
			Revision:     1,
			State:        "pending",
			CreatedAt:    s.now(),
			References:   []Reference{},
		}
		if err := tx.SaveObject(o); err != nil {
			return err
		}
		if err := s.emit(tx, actor, "storage.object.created", o.ID, o.Revision); err != nil {
			return err
		}
		out, err = s.status(tx, o)
		return err
	})
	return out, err
}

func (s *Service) writeContentObject(ctx context.Context, g ContentGroup, f *stagedFile, checkAuth func(Transaction) error) error {
	ctx, release, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer release()
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return ErrUnavailable
	}
	var job Job
	already := false
	err = s.repo.Transaction(ctx, func(tx Transaction) error {
		if checkAuth != nil {
			if err := checkAuth(tx); err != nil {
				return err
			}
		}
		if err := tx.Lock("object:" + g.ObjectID); err != nil {
			return err
		}
		o, err := tx.Object(g.ObjectID)
		if err != nil {
			return err
		}
		if o.State == "deleting" || o.State == "deleted" {
			return ErrStale
		}
		replicas, err := tx.Replicas(o.ID)
		if err != nil {
			return err
		}
		for _, r := range replicas {
			if r.State == "healthy" && r.ObjectRevision == o.Revision {
				already = true
				return nil
			}
			if r.State != "deleted" {
				return ErrConflict
			}
		}
		planned, err := s.plan(tx, o, 1)
		if err != nil {
			return err
		}
		if len(planned) == 0 {
			return ErrCapacity
		}
		replica := planned[0]
		replica.State = "writing"
		if err := tx.SaveReplica(replica); err != nil {
			return err
		}
		job = Job{
			ID:                 newID(),
			ObjectID:           o.ID,
			ReplicaID:          replica.ID,
			Intent:             replica.Intent,
			ObjectRevision:     replica.ObjectRevision,
			InstanceRevision:   replica.InstanceRevision,
			CredentialRevision: replica.CredentialRevision,
			Kind:               "ingest",
			State:              "running",
			Generation:         1,
			LeaseOwner:         newID(),
			LeaseUntil:         s.now().Add(s.cfg.Lease),
			AvailableAt:        s.now(),
			Attempts:           1,
		}
		return s.queue(tx, job)
	})
	if err != nil || already {
		return err
	}
	workCtx, cancel := context.WithTimeout(ctx, s.cfg.Lease)
	defer cancel()
	if err = s.writeReplica(workCtx, job, f); err != nil {
		cleanupCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		_ = s.failJob(cleanupCtx, job, err)
		return err
	}
	return nil
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
	if _, err = s.ensureContentObject(ctx, p, g); err != nil {
		return Status{}, err
	}
	if err = s.writeContentObject(ctx, g, f, func(Transaction) error {
		return s.authorize(ctx, p, "storage.objects.upload", id, g.Protection)
	}); err != nil {
		return Status{}, err
	}
	return s.contentStatusAction(ctx, p, id, "storage.objects.upload")
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
		if e = s.emitScoped(tx, p, action, h.ID, h.Revision, "success", g.Protection.Scope); e != nil {
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
		if e := s.emitScoped(tx, p, "storage.content.released", h.ID, h.Revision, "success", g.Protection.Scope); e != nil {
			return nil, e
		}
		return s.contentView(tx, h, g)
	}, &out)
	if err == nil {
		for _, groupID := range []string{h.GroupID, h.SourceGroup, h.PendingGroup} {
			if groupID != "" {
				if e := s.cleanupContentGroup(ctx, p, groupID); e != nil {
					err = e
					break
				}
			}
		}
	}
	if err != nil {
		return out, err
	}
	return s.contentStatusAction(ctx, p, id, "storage.objects.delete")
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
	check := func(recordReviewAudit bool) error {
		return s.repo.Transaction(ctx, func(tx Transaction) error {
			h, g, e := s.contentGuard(ctx, tx, p, action, id)
			if e != nil {
				return e
			}
			if h.State != "active" || !h.Verified || (h.PendingGroup != "" && !review) {
				return ErrDenied
			}
			if h.PendingGroup != "" && review {
				pending, pe := tx.ContentGroup(h.PendingGroup)
				if pe != nil {
					return pe
				}
				if pe = s.authorize(ctx, p, action, id, pending.Protection); pe != nil {
					return pe
				}
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
			if review && recordReviewAudit {
				return s.emitScoped(tx, p, "storage.content.reviewed", id, h.Revision, "success", g.Protection.Scope)
			}
			return nil
		})
	}
	if e := check(false); e != nil {
		return e
	}
	// The handle gate above prevents inheriting another handle's publication.
	return s.download(ctx, p, object, &contentWriter{check: func() error { return check(true) }, dst: dst}, review, false)
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
		if e := s.cleanupContentGroup(ctx, p, g.ID); e != nil && first == nil {
			first = e
		}
	}
	return first
}
func (s *Service) cleanupContentGroup(ctx context.Context, actor Principal, id string) error {
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
	// deletion so a late create cannot escape an earlier release, using the
	// caller's already-verified cleanup privilege rather than impersonating g.Owner.
	objectDeleted := false
	err = s.repo.Transaction(ctx, func(tx Transaction) error {
		if e := tx.Lock("object:" + g.ObjectID); e != nil {
			return e
		}
		o, e := tx.Object(g.ObjectID)
		if errors.Is(e, ErrNotFound) {
			creation := CreateRequest{ClientKey: "content:" + g.ID, Size: g.Size, SHA256: g.SHA256, Protection: g.Protection, Policy: g.Policy}
			o = Object{
				ContentGroup: g.ID,
				CreationHash: requestHash(creation),
				ID:           g.ObjectID,
				Owner:        g.Owner,
				Size:         g.Size,
				SHA256:       g.SHA256,
				Protection:   g.Protection,
				Policy:       g.Policy,
				Revision:     1,
				State:        "deleted",
				CreatedAt:    s.now(),
				References:   []Reference{},
			}
			if e = tx.SaveObject(o); e != nil {
				return e
			}
			objectDeleted = true
			return s.emit(tx, actor, "storage.object.deleting", o.ID, o.Revision)
		}
		if e != nil {
			return e
		}
		replicas, e := tx.Replicas(o.ID)
		if e != nil {
			return e
		}
		remaining := 0
		for _, r := range replicas {
			if r.State != "deleted" {
				remaining++
			}
		}
		if o.State != "deleted" && o.State != "deleting" {
			o.State = "deleting"
			o.Revision++
			if remaining == 0 {
				o.State = "deleted"
			}
			if e = tx.SaveObject(o); e != nil {
				return e
			}
			for _, r := range replicas {
				if r.State == "deleted" {
					continue
				}
				r.State = "cleanup"
				if e = tx.SaveReplica(r); e != nil {
					return e
				}
				if e = s.enqueue(tx, o.ID, r.ID, "delete"); e != nil {
					return e
				}
			}
			if e = s.emit(tx, actor, "storage.object.deleting", o.ID, o.Revision); e != nil {
				return e
			}
		} else if o.State == "deleting" && remaining == 0 {
			o.State = "deleted"
			if e = tx.SaveObject(o); e != nil {
				return e
			}
		}
		objectDeleted = o.State == "deleted"
		return nil
	})
	if err != nil || !objectDeleted {
		return err
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
			if e = s.emitScoped(tx, p, "storage.content.expired", h.ID, h.Revision, "success", g.Protection.Scope); e != nil {
				return e
			}
		}
		return nil
	})
}
