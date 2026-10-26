package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"time"
)

type boundedWriter struct {
	w         io.Writer
	remaining int64
}

func (w *boundedWriter) Write(b []byte) (int, error) {
	if int64(len(b)) > w.remaining {
		return 0, ErrIntegrity
	}
	n, err := w.w.Write(b)
	w.remaining -= int64(n)
	return n, err
}

func (s *Service) slot(ctx context.Context) (func(), error) {
	select {
	case s.slots <- struct{}{}:
		return func() { <-s.slots }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (s *Service) temporary() (f *os.File, err error) {
	f, err = os.CreateTemp(s.cfg.TemporaryDirectory, "stuhelper-transfer-*")
	if err != nil {
		return nil, ErrUnavailable
	}
	return f, nil
}
func removeTemporary(f *os.File) {
	if f != nil {
		name := f.Name()
		_ = f.Close()
		_ = os.Remove(name)
	}
}
func verifyFile(f *os.File, o Object) error {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return ErrUnavailable
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, o.Size+1))
	if err != nil {
		return ErrUnavailable
	}
	if n != o.Size || hex.EncodeToString(h.Sum(nil)) != o.SHA256 {
		return ErrIntegrity
	}
	_, err = f.Seek(0, io.SeekStart)
	return err
}

// Ingest hashes bounded local staging before any provider write. The staging
// file is removed on return; retry uses the immutable object's size and digest.
func (s *Service) Ingest(ctx context.Context, p Principal, id, key string, src io.Reader) (Status, error) {
	if !validKey(key) || src == nil {
		return Status{}, ErrInput
	}
	release, err := s.slot(ctx)
	if err != nil {
		return Status{}, err
	}
	defer release()
	var o Object
	err = s.repo.Transaction(ctx, func(tx Transaction) error {
		var err error
		o, err = s.objectGuard(ctx, tx, p, "storage.objects.upload", id)
		if err != nil {
			return err
		}
		if o.State == "deleted" || o.State == "deleting" {
			return ErrConflict
		}
		return nil
	})
	if err != nil {
		return Status{}, err
	}
	f, err := s.temporary()
	if err != nil {
		return Status{}, err
	}
	defer removeTemporary(f)
	if _, err = io.Copy(f, io.LimitReader(src, o.Size+1)); err != nil {
		return Status{}, ErrUnavailable
	}
	if err = verifyFile(f, o); err != nil {
		return Status{}, err
	}
	var job Job
	var replica Replica
	already := false
	err = s.repo.Transaction(ctx, func(tx Transaction) error {
		current, err := s.objectGuard(ctx, tx, p, "storage.objects.upload", id)
		if err != nil {
			return err
		}
		if current.Revision != o.Revision || current.State == "deleting" || current.State == "deleted" {
			return ErrStale
		}
		replicas, err := tx.Replicas(id)
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
		replica = planned[0]
		replica.State = "writing"
		if err := tx.SaveReplica(replica); err != nil {
			return err
		}
		job = Job{ID: newID(), ObjectID: id, ReplicaID: replica.ID, Intent: replica.Intent, ObjectRevision: replica.ObjectRevision, InstanceRevision: replica.InstanceRevision, CredentialRevision: replica.CredentialRevision, Kind: "ingest", State: "running", Generation: 1, LeaseOwner: newID(), LeaseUntil: s.now().Add(s.cfg.Lease), AvailableAt: s.now(), Attempts: 1}
		return tx.SaveJob(job)
	})
	if err != nil {
		return Status{}, err
	}
	if already {
		return s.Status(ctx, p, id)
	}
	workCtx, cancel := context.WithTimeout(ctx, s.cfg.Lease)
	defer cancel()
	err = s.writeReplica(workCtx, job, f)
	if err != nil {
		cleanupCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		_ = s.failJob(cleanupCtx, job, err)
		return Status{}, err
	}
	return s.Status(ctx, p, id)
}

// Download buffers within the configured size/concurrency budget so corrupted
// or replaced remote content cannot partially escape before checksum validation.
func (s *Service) Download(ctx context.Context, p Principal, id string, dst io.Writer) error {
	if dst == nil {
		return ErrInput
	}
	release, err := s.slot(ctx)
	if err != nil {
		return err
	}
	defer release()
	var o Object
	err = s.repo.Transaction(ctx, func(tx Transaction) error {
		var err error
		o, err = s.objectGuard(ctx, tx, p, "storage.objects.download", id)
		if err != nil {
			return err
		}
		st, err := s.status(tx, o)
		if err != nil {
			return err
		}
		if o.State == "deleting" || o.State == "deleted" || st.Healthy == 0 || (!o.Published && st.Healthy < o.Policy.Publish) {
			return ErrUnavailable
		}
		return nil
	})
	if err != nil {
		return err
	}
	f, err := s.readSource(ctx, o, "")
	if err != nil {
		return err
	}
	defer removeTemporary(f)
	err = s.repo.Transaction(ctx, func(tx Transaction) error {
		current, err := s.objectGuard(ctx, tx, p, "storage.objects.download", id)
		if err != nil {
			return err
		}
		if current.Revision != o.Revision || current.State == "deleting" || current.State == "deleted" {
			return ErrStale
		}
		return nil
	})
	if err != nil {
		return err
	}
	_, err = io.Copy(dst, f)
	return err
}

func (s *Service) readSource(ctx context.Context, o Object, excluded string) (*os.File, error) {
	var replicas []Replica
	err := s.repo.Transaction(ctx, func(tx Transaction) error { var err error; replicas, err = tx.Replicas(o.ID); return err })
	if err != nil {
		return nil, err
	}
	for _, r := range replicas {
		if r.ID == excluded || r.State != "healthy" || r.ObjectRevision != o.Revision || r.VerifiedAt.Before(s.now().Add(-s.cfg.VerificationAge)) {
			continue
		}
		var instance Instance
		err = s.repo.Transaction(ctx, func(tx Transaction) error {
			current, err := tx.Object(o.ID)
			if err != nil {
				return err
			}
			if current.Revision != o.Revision || current.State == "deleting" || current.State == "deleted" {
				return ErrStale
			}
			instance, err = tx.Instance(r.InstanceID)
			if err != nil {
				return err
			}
			if !instance.Allows(o.Protection, s.now()) || instance.CredentialRevision != r.CredentialRevision {
				return ErrDenied
			}
			return nil
		})
		if err != nil {
			continue
		}
		f, err := s.readRemote(ctx, o, instance, r.Remote)
		if err != nil {
			if errors.Is(err, ErrIntegrity) || errors.Is(err, ErrNotFound) {
				_ = s.markCorrupt(ctx, o, r)
			}
			continue
		}
		err = s.repo.Transaction(ctx, func(tx Transaction) error {
			i, err := tx.Instance(instance.ID)
			if err != nil {
				return err
			}
			if i.Revision != instance.Revision || i.CredentialRevision != instance.CredentialRevision || !i.Allows(o.Protection, s.now()) {
				return ErrStale
			}
			return nil
		})
		if err != nil {
			removeTemporary(f)
			continue
		}
		return f, nil
	}
	return nil, ErrUnavailable
}
func (s *Service) readRemote(ctx context.Context, o Object, i Instance, remote Locator) (*os.File, error) {
	driver, err := s.resolver.Resolve(ctx, i)
	if err != nil {
		return nil, err
	}
	f, err := s.temporary()
	if err != nil {
		return nil, err
	}
	w := &boundedWriter{w: f, remaining: o.Size}
	n, err := driver.Read(ctx, i, remote, w)
	if err == nil && (n != o.Size || w.remaining != 0) {
		err = ErrIntegrity
	}
	if err == nil {
		err = verifyFile(f, o)
	}
	if err != nil {
		removeTemporary(f)
		return nil, err
	}
	return f, nil
}
func (s *Service) markCorrupt(ctx context.Context, o Object, r Replica) error {
	return s.repo.Transaction(ctx, func(tx Transaction) error {
		if err := tx.Lock("object:" + o.ID); err != nil {
			return err
		}
		replicas, err := tx.Replicas(o.ID)
		if err != nil {
			return err
		}
		current, err := findReplica(replicas, r.ID)
		if err != nil {
			return err
		}
		if current.Remote != r.Remote || (current.State != "healthy" && current.State != "checking") {
			return ErrStale
		}
		current.State = "corrupt"
		if err := tx.SaveReplica(current); err != nil {
			return err
		}
		return s.emit(tx, Principal{}, "storage.replica.corrupt", o.ID, o.Revision)
	})
}

func (s *Service) jobState(ctx context.Context, tx Transaction, expected Job, allowCleanup bool) (Object, Replica, Instance, Job, error) {
	if err := tx.Lock("object:" + expected.ObjectID); err != nil {
		return Object{}, Replica{}, Instance{}, Job{}, err
	}
	o, err := tx.Object(expected.ObjectID)
	if err != nil {
		return o, Replica{}, Instance{}, Job{}, err
	}
	replicas, err := tx.Replicas(o.ID)
	if err != nil {
		return o, Replica{}, Instance{}, Job{}, err
	}
	r, err := findReplica(replicas, expected.ReplicaID)
	if err != nil {
		return o, r, Instance{}, Job{}, err
	}
	i, err := tx.Instance(r.InstanceID)
	if err != nil {
		return o, r, i, Job{}, err
	}
	j, err := tx.Job(expected.ID)
	if err != nil {
		return o, r, i, j, err
	}
	if j.State != "running" || j.Generation != expected.Generation || j.LeaseOwner != expected.LeaseOwner || !j.LeaseUntil.After(s.now()) {
		return o, r, i, j, ErrStale
	}
	if expected.Intent != r.Intent || expected.ObjectRevision != r.ObjectRevision || expected.CredentialRevision != r.CredentialRevision || expected.InstanceRevision != r.InstanceRevision {
		return o, r, i, j, ErrStale
	}
	if !i.Authorized || !i.ExpiresAt.After(s.now()) || i.State == "revoked" || i.CredentialRevision != r.CredentialRevision {
		return o, r, i, j, ErrDenied
	}
	if !allowCleanup && (o.State == "deleting" || o.State == "deleted" || r.ObjectRevision != o.Revision || r.State == "cleanup" || r.State == "deleted" || !i.Allows(o.Protection, s.now()) || i.Revision != r.InstanceRevision) {
		return o, r, i, j, ErrStale
	}
	if allowCleanup {
		active, err := tx.ActiveWrites(r.ID, s.now())
		if err != nil {
			return o, r, i, j, err
		}
		if active {
			return o, r, i, j, ErrConflict
		}
	}
	return o, r, i, j, nil
}
func (s *Service) snapshotJob(ctx context.Context, j Job, cleanup bool) (Object, Replica, Instance, error) {
	var o Object
	var r Replica
	var i Instance
	err := s.repo.Transaction(ctx, func(tx Transaction) error {
		var err error
		o, r, i, _, err = s.jobState(ctx, tx, j, cleanup)
		return err
	})
	return o, r, i, err
}
func (s *Service) writeReplica(ctx context.Context, j Job, src io.Reader) error {
	o, r, i, err := s.snapshotJob(ctx, j, false)
	if err != nil {
		return err
	}
	driver, err := s.resolver.Resolve(ctx, i)
	if err != nil {
		return err
	}
	// A retry first reconciles the exact persisted intent. It never blindly starts
	// another remote upload after an ambiguous response or process death.
	remote, err := driver.Find(ctx, i, r.Intent, r.Remote)
	if err == nil {
		f, err := s.readRemote(ctx, o, i, remote)
		if err != nil {
			return ErrUnknown
		}
		removeTemporary(f)
		return s.complete(ctx, j, remote)
	}
	if !errors.Is(err, ErrNotFound) {
		return ErrUnknown
	}
	if r.IssuedWrite {
		return ErrUnknown
	}
	if src == nil {
		return ErrNotFound
	}
	if err := s.repo.Transaction(ctx, func(tx Transaction) error {
		_, current, _, _, err := s.jobState(ctx, tx, j, false)
		if err != nil {
			return err
		}
		if current.IssuedWrite {
			return ErrUnknown
		}
		current.IssuedWrite = true
		current.State = "writing"
		return tx.SaveReplica(current)
	}); err != nil {
		return err
	}
	checkpoint := func(remote Locator) error {
		if remote.ID == "" || len(remote.ID) > 2048 || len(remote.Revision) > 512 {
			return ErrInput
		}
		return s.repo.Transaction(ctx, func(tx Transaction) error {
			_, current, _, _, err := s.jobState(ctx, tx, j, false)
			if err != nil {
				return err
			}
			current.Remote = remote
			current.State = "writing"
			return tx.SaveReplica(current)
		})
	}
	remote, err = driver.Write(ctx, i, r.Intent, o.Size, src, checkpoint)
	if err != nil {
		return err
	}
	if _, _, _, err = s.snapshotJob(ctx, j, false); err != nil {
		return err
	}
	f, err := s.readRemote(ctx, o, i, remote)
	if err != nil {
		return err
	}
	removeTemporary(f)
	return s.complete(ctx, j, remote)
}
func (s *Service) complete(ctx context.Context, j Job, remote Locator) error {
	return s.repo.Transaction(ctx, func(tx Transaction) error {
		o, r, i, current, err := s.jobState(ctx, tx, j, false)
		if err != nil {
			return err
		}
		if remote.ID == "" {
			return ErrInput
		}
		r.Remote = remote
		r.State = "healthy"
		r.VerifiedAt = s.now()
		if r.Reserved {
			i.Reserved -= r.Size
			r.Reserved = false
			i.Used += r.Size
			r.Accounted = true
			if i.ProviderFree >= r.Size {
				i.ProviderFree -= r.Size
			} else {
				i.ProviderFree = 0
			}
		}
		if err := tx.SaveInstance(i); err != nil {
			return err
		}
		if err := tx.SaveReplica(r); err != nil {
			return err
		}
		current.State = "done"
		if err := tx.SaveJob(current); err != nil {
			return err
		}
		return s.emit(tx, Principal{}, "storage.replica.verified", o.ID, o.Revision)
	})
}

// RunOne claims a durable lease and executes one bounded operation. No in-memory
// queue is required to resume after a worker restart.
func (s *Service) RunOne(ctx context.Context, worker string) (bool, error) {
	if !validID(worker) {
		return false, ErrInput
	}
	release, err := s.slot(ctx)
	if err != nil {
		return false, err
	}
	defer release()
	j, err := s.repo.Claim(ctx, worker, s.now(), s.cfg.Lease)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	workCtx, cancel := context.WithTimeout(ctx, s.cfg.Lease)
	defer cancel()
	switch j.Kind {
	case "replicate":
		var o Object
		o, _, _, err = s.snapshotJob(workCtx, j, false)
		if err == nil {
			var f *os.File
			f, err = s.readSource(workCtx, o, j.ReplicaID)
			if err == nil {
				err = s.writeReplica(workCtx, j, f)
				removeTemporary(f)
			}
		}
	case "ingest":
		err = s.writeReplica(workCtx, j, nil)
	case "verify":
		var o Object
		var r Replica
		var i Instance
		o, r, i, err = s.snapshotJob(workCtx, j, false)
		if err == nil {
			var f *os.File
			f, err = s.readRemote(workCtx, o, i, r.Remote)
			if err == nil {
				removeTemporary(f)
				err = s.complete(workCtx, j, r.Remote)
			} else if errors.Is(err, ErrIntegrity) || errors.Is(err, ErrNotFound) {
				_ = s.markCorrupt(workCtx, o, r)
			}
		}
	case "delete":
		err = s.deleteReplica(workCtx, j)
	default:
		err = ErrInput
	}
	if err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if recordErr := s.failJob(cleanupCtx, j, err); recordErr != nil {
			return true, recordErr
		}
	}
	return true, err
}
func (s *Service) failJob(ctx context.Context, expected Job, cause error) error {
	return s.repo.Transaction(ctx, func(tx Transaction) error {
		if err := tx.Lock("object:" + expected.ObjectID); err != nil {
			return err
		}
		j, err := tx.Job(expected.ID)
		if err != nil {
			return err
		}
		if j.Generation != expected.Generation || j.LeaseOwner != expected.LeaseOwner || j.State != "running" {
			return ErrStale
		}
		j.ErrorCode = errorCode(cause)
		j.State = "pending"
		j.AvailableAt = s.now().Add(time.Duration(min(j.Attempts, 60)) * 5 * time.Second)
		if j.Attempts >= s.cfg.MaxAttempts || errors.Is(cause, ErrStale) || errors.Is(cause, ErrDenied) {
			j.State = "blocked"
		}
		return tx.SaveJob(j)
	})
}
func (s *Service) deleteReplica(ctx context.Context, j Job) error {
	_, r, i, err := s.snapshotJob(ctx, j, true)
	if err != nil {
		return err
	}
	driver, err := s.resolver.Resolve(ctx, i)
	if err != nil {
		return err
	}
	remote, err := driver.Find(ctx, i, r.Intent, r.Remote)
	if err == nil {
		if _, _, _, err = s.snapshotJob(ctx, j, true); err != nil {
			return err
		}
		if err = driver.Remove(ctx, i, remote); err != nil {
			return err
		}
	}
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if errors.Is(err, ErrNotFound) && r.IssuedWrite && r.Remote.ID == "" {
		return ErrUnknown
	}
	// Remove's success must mean permanent absence, not a recycle-bin move.
	if _, checkErr := driver.Find(ctx, i, r.Intent, r.Remote); !errors.Is(checkErr, ErrNotFound) {
		if checkErr == nil {
			return ErrUnknown
		}
		return checkErr
	}
	return s.repo.Transaction(ctx, func(tx Transaction) error {
		o, r, i, current, err := s.jobState(ctx, tx, j, true)
		if err != nil {
			return err
		}
		if r.Reserved {
			i.Reserved -= r.Size
			r.Reserved = false
		}
		if r.Accounted {
			i.Used -= r.Size
			r.Accounted = false
		}
		r.State = "deleted"
		// Capacity increases only after a fresh provider sample, never on optimistic delete.
		if err := tx.SaveInstance(i); err != nil {
			return err
		}
		if err := tx.SaveReplica(r); err != nil {
			return err
		}
		current.State = "done"
		if err := tx.SaveJob(current); err != nil {
			return err
		}
		if o.State == "deleting" {
			replicas, err := tx.Replicas(o.ID)
			if err != nil {
				return err
			}
			done := true
			for _, copy := range replicas {
				if copy.State != "deleted" {
					done = false
				}
			}
			if done {
				o.State = "deleted"
				if err := tx.SaveObject(o); err != nil {
					return err
				}
			}
		}
		return s.emit(tx, Principal{}, "storage.replica.deleted", o.ID, o.Revision)
	})
}
