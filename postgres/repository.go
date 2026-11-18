// Package postgres implements the storage-owned transactional ledger.
package postgres

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"strings"
	"time"

	storage "github.com/StuHelper/stuhelper-storage"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
)

//go:embed schema.sql
var Schema string

type Repository struct {
	DB       *sql.DB
	Observer storage.Observer
}
type transaction struct {
	tx  *sql.Tx
	ctx context.Context
	obs storage.Observer
}

func (t *transaction) JobSnapshot(id string) (storage.Job, error) {
	return read[storage.Job](t, `SELECT data FROM storage.jobs WHERE id=$1`, id)
}

func (t *transaction) InstanceReplicas(id string) (int64, error) {
	var count int64
	err := t.tx.QueryRowContext(t.ctx, `SELECT count(*) FROM storage.replicas WHERE instance_id=$1 AND data->>'state'<>'deleted'`, id).Scan(&count)
	return count, t.safe("instance_replicas", err)
}

func (t *transaction) ActiveWrites(replicaID string, now time.Time) (bool, error) {
	var active bool
	err := t.tx.QueryRowContext(t.ctx, `SELECT EXISTS(SELECT 1 FROM storage.jobs WHERE data->>'replica_id'=$1 AND data->>'kind' IN ('ingest','replicate') AND state='running' AND lease_until>$2)`, replicaID, now).Scan(&active)
	return active, t.safe("active_writes", err)
}

func observeDB(obs storage.Observer, op string, err error) error {
	if err == nil || errors.Is(err, sql.ErrNoRows) {
		return safe(err)
	}
	category := "db_unavailable"
	var pg *pgconn.PgError
	switch {
	case errors.As(err, &pg) && len(pg.Code) == 5:
		category = "sqlstate_" + pg.Code
	case errors.Is(err, context.DeadlineExceeded):
		category = "deadline_exceeded"
	case errors.Is(err, context.Canceled):
		category = "canceled"
	}
	storage.EmitDiagnostic(obs, storage.Diagnostic{Component: "postgres", Operation: op, Category: category})
	return safe(err)
}

func (r *Repository) safe(op string, err error) error  { return observeDB(r.Observer, op, err) }
func (t *transaction) safe(op string, err error) error { return observeDB(t.obs, op, err) }

func safe(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return storage.ErrNotFound
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) && (pg.Code == "23505" || pg.Code == "40001" || pg.Code == "40P01") {
		return storage.ErrConflict
	}
	return storage.ErrUnavailable
}
func (r *Repository) Transaction(ctx context.Context, f func(storage.Transaction) error) error {
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return r.safe("tx_begin", err)
	}
	defer tx.Rollback()
	if err = f(&transaction{tx, ctx, r.Observer}); err != nil {
		return err
	}
	return r.safe("tx_commit", tx.Commit())
}
func (r *Repository) ReadTransaction(ctx context.Context, f func(storage.Transaction) error) error {
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return r.safe("read_begin", err)
	}
	defer tx.Rollback()
	if err = f(&transaction{tx, ctx, r.Observer}); err != nil {
		return err
	}
	return r.safe("read_commit", tx.Commit())
}
func (t *transaction) Lock(key string) error {
	_, err := t.tx.ExecContext(t.ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "stuhelper-storage:"+key)
	return t.safe("advisory_lock", err)
}
func read[T any](t *transaction, query string, args ...any) (T, error) {
	var out T
	var b []byte
	if err := t.tx.QueryRowContext(t.ctx, query, args...).Scan(&b); err != nil {
		return out, t.safe("read", err)
	}
	if json.Unmarshal(b, &out) != nil {
		storage.EmitDiagnostic(t.obs, storage.Diagnostic{Component: "postgres", Operation: "read_decode", Category: "decode_failed"})
		return out, storage.ErrUnavailable
	}
	return out, nil
}
func list[T any](t *transaction, query string, args ...any) ([]T, error) {
	rows, err := t.tx.QueryContext(t.ctx, query, args...)
	if err != nil {
		return nil, t.safe("list", err)
	}
	defer rows.Close()
	out := make([]T, 0)
	for rows.Next() {
		var b []byte
		var item T
		if scanErr := rows.Scan(&b); scanErr != nil {
			return nil, t.safe("list_scan", scanErr)
		}
		if json.Unmarshal(b, &item) != nil {
			storage.EmitDiagnostic(t.obs, storage.Diagnostic{Component: "postgres", Operation: "list_decode", Category: "decode_failed"})
			return nil, storage.ErrUnavailable
		}
		out = append(out, item)
	}
	return out, t.safe("list_rows", rows.Err())
}
func (t *transaction) save(query string, item any, args ...any) error {
	b, err := json.Marshal(item)
	if err != nil {
		return storage.ErrInput
	}
	args = append(args, string(b))
	_, err = t.tx.ExecContext(t.ctx, query, args...)
	return t.safe("save", err)
}
func (t *transaction) Instance(id string) (storage.Instance, error) {
	return read[storage.Instance](t, `SELECT data FROM storage.instances WHERE id=$1 FOR UPDATE`, id)
}
func (t *transaction) InstanceSnapshot(id string) (storage.Instance, error) {
	return read[storage.Instance](t, `SELECT data FROM storage.instances WHERE id=$1`, id)
}
func (t *transaction) ContributionCandidates(owner string, now time.Time, limit int, after string) ([]storage.Instance, error) {
	return list[storage.Instance](t, `SELECT i.data FROM storage.instances i WHERE i.id>$1 AND i.data->>'owner_domain'=$2 AND i.data->>'ownership'='contributor' AND i.data->>'state'='paused' AND (i.data->>'authorized')::boolean AND (i.data->>'expires_at')::timestamptz>$3 AND (i.data->'contribution_control' IS NULL OR i.data->'contribution_control'='null'::jsonb) AND (i.data->>'used')::bigint=0 AND (i.data->>'reserved')::bigint=0 AND NOT EXISTS(SELECT 1 FROM storage.replicas r WHERE r.instance_id=i.id AND r.data->>'state'<>'deleted') ORDER BY i.id LIMIT $4`, after, owner, now, limit)
}
func (t *transaction) Instances(limit int, after string) ([]storage.Instance, error) {
	return list[storage.Instance](t, `SELECT data FROM storage.instances WHERE id>$1 ORDER BY id LIMIT $2`, after, limit)
}
func (t *transaction) SaveInstance(v storage.Instance) error {
	return t.save(`INSERT INTO storage.instances(id,account_domain,data) VALUES($1,$2,$3) ON CONFLICT(id) DO UPDATE SET account_domain=excluded.account_domain,data=excluded.data`, v, v.ID, v.AccountDomain)
}
func (t *transaction) Object(id string) (storage.Object, error) {
	return read[storage.Object](t, `SELECT data FROM storage.objects WHERE id=$1 FOR UPDATE`, id)
}
func (t *transaction) ObjectSnapshot(id string) (storage.Object, error) {
	return read[storage.Object](t, `SELECT data FROM storage.objects WHERE id=$1`, id)
}
func (t *transaction) Objects(limit int, after string) ([]storage.Object, error) {
	return list[storage.Object](t, `SELECT data FROM storage.objects WHERE id>$1 ORDER BY id LIMIT $2`, after, limit)
}
func (t *transaction) ActiveObjects(limit int, after string) ([]storage.Object, error) {
	return list[storage.Object](t, `SELECT data FROM storage.objects WHERE id>$1 AND data->>'state'<>'deleted' ORDER BY id LIMIT $2`, after, limit)
}
func (t *transaction) SaveObject(v storage.Object) error {
	return t.save(`INSERT INTO storage.objects(id,data) VALUES($1,$2) ON CONFLICT(id) DO UPDATE SET data=excluded.data`, v, v.ID)
}
func (t *transaction) Replicas(id string) ([]storage.Replica, error) {
	return list[storage.Replica](t, `SELECT data FROM storage.replicas WHERE object_id=$1 ORDER BY instance_id`, id)
}
func (t *transaction) ReplicasByObjects(ids []string) (map[string][]storage.Replica, error) {
	out := make(map[string][]storage.Replica, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	items, err := list[storage.Replica](t, `SELECT data FROM storage.replicas WHERE object_id = ANY($1) ORDER BY object_id, instance_id`, ids)
	if err != nil {
		return nil, err
	}
	for _, r := range items {
		out[r.ObjectID] = append(out[r.ObjectID], r)
	}
	return out, nil
}
func (t *transaction) SaveReplica(v storage.Replica) error {
	return t.save(`INSERT INTO storage.replicas(id,object_id,instance_id,data) VALUES($1,$2,$3,$4) ON CONFLICT(id) DO UPDATE SET data=excluded.data`, v, v.ID, v.ObjectID, v.InstanceID)
}
func (t *transaction) Job(id string) (storage.Job, error) {
	return read[storage.Job](t, `SELECT data FROM storage.jobs WHERE id=$1 FOR UPDATE`, id)
}
func (t *transaction) SaveJob(v storage.Job) error {
	var completedAt any
	if v.State == "done" && !v.CompletedAt.IsZero() {
		completedAt = v.CompletedAt
	}
	return t.save(`INSERT INTO storage.jobs(id,object_id,state,available_at,lease_until,completed_at,data) VALUES($1,$2,$3,$4,$5,CASE WHEN $3='done' THEN COALESCE($6::timestamptz,now()) END,$7) ON CONFLICT(id) DO UPDATE SET state=excluded.state,available_at=excluded.available_at,lease_until=excluded.lease_until,completed_at=CASE WHEN excluded.state='done' THEN COALESCE(storage.jobs.completed_at,excluded.completed_at) ELSE NULL END,data=excluded.data`, v, v.ID, v.ObjectID, v.State, v.AvailableAt, v.LeaseUntil, completedAt)
}
func (t *transaction) OutstandingJobs(exclude string, limit int) (int, error) {
	var count int
	err := t.tx.QueryRowContext(t.ctx, `SELECT count(*) FROM (SELECT 1 FROM storage.jobs WHERE id<>$1 AND state IN ('pending','running') LIMIT $2) bounded`, exclude, limit).Scan(&count)
	return count, t.safe("outstanding_jobs", err)
}
func (t *transaction) JobTotals() (storage.JobTotals, error) {
	var out storage.JobTotals
	err := t.tx.QueryRowContext(t.ctx, `SELECT count(*) FILTER (WHERE state='pending'),count(*) FILTER (WHERE state='running'),count(*) FILTER (WHERE state='blocked') FROM storage.jobs WHERE state IN ('pending','running','blocked')`).Scan(&out.Pending, &out.Running, &out.Blocked)
	return out, t.safe("job_totals", err)
}
func (t *transaction) FailedJobs(limit int, after string) ([]storage.Job, error) {
	return list[storage.Job](t, `SELECT data FROM storage.jobs WHERE id>$1 AND state IN ('pending','running','blocked') AND COALESCE(data->>'error_code','')<>'' ORDER BY id LIMIT $2`, after, limit)
}
func (t *transaction) Idempotency(key string) (storage.Idempotency, error) {
	return read[storage.Idempotency](t, `SELECT data FROM storage.idempotency WHERE key=$1 FOR UPDATE`, key)
}
func (t *transaction) SaveIdempotency(v storage.Idempotency) error {
	return t.save(`INSERT INTO storage.idempotency(key,expires_at,data) VALUES($1,$2,$3) ON CONFLICT(key) DO UPDATE SET expires_at=excluded.expires_at,data=excluded.data`, v, v.Key, v.ExpiresAt)
}
func (t *transaction) PurgeRetention(cutoffs storage.RetentionCutoffs, limit int) (storage.RetentionResult, error) {
	var out storage.RetentionResult
	execDelete := func(query string, cutoff time.Time) (int, error) {
		res, err := t.tx.ExecContext(t.ctx, query, cutoff, limit)
		if err != nil {
			return 0, safe(err)
		}
		rows, err := res.RowsAffected()
		return int(rows), safe(err)
	}
	var err error
	if out.Idempotency, err = execDelete(`DELETE FROM storage.idempotency WHERE ctid IN (SELECT ctid FROM storage.idempotency WHERE expires_at <= $1 ORDER BY expires_at LIMIT $2 FOR UPDATE SKIP LOCKED)`, cutoffs.IdempotencyBefore); err != nil {
		return out, err
	}
	if out.DeliveredOutbox, err = execDelete(`DELETE FROM storage.outbox WHERE ctid IN (SELECT ctid FROM storage.outbox WHERE delivered AND delivered_at <= $1 ORDER BY delivered_at LIMIT $2 FOR UPDATE SKIP LOCKED)`, cutoffs.DeliveredOutboxBefore); err != nil {
		return out, err
	}
	if out.CompletedJobs, err = execDelete(`DELETE FROM storage.jobs WHERE ctid IN (SELECT ctid FROM storage.jobs WHERE state='done' AND completed_at <= $1 ORDER BY completed_at LIMIT $2 FOR UPDATE SKIP LOCKED)`, cutoffs.CompletedJobsBefore); err != nil {
		return out, err
	}
	if out.CustodyOperations, err = execDelete(`DELETE FROM storage.custody_operations WHERE ctid IN (SELECT o.ctid FROM storage.custody_operations o WHERE COALESCE((o.data->>'Complete')::boolean,false) AND o.completed_at <= $1 AND NOT EXISTS (SELECT 1 FROM storage.custody_bindings b WHERE b.data->>'request_id'=o.id AND b.data->>'state'<>'ready') ORDER BY o.completed_at LIMIT $2 FOR UPDATE SKIP LOCKED)`, cutoffs.CompletedCustodyBefore); err != nil {
		return out, err
	}
	return out, nil
}
func (t *transaction) Event(v storage.Event) error {
	v.SpecVersion = "1.0"
	v.Source = "stuhelper://storage"
	v.Subject = "object/" + v.ObjectID
	if strings.HasPrefix(v.Type, "storage.custody.") {
		v.Subject = "custody/" + v.ObjectID
	}
	if strings.HasPrefix(v.Type, "storage.instance.") {
		v.Subject = "instance/" + v.ObjectID
	}
	v.DataContentType = "application/json"
	var revision int64
	if err := t.tx.QueryRowContext(t.ctx, `INSERT INTO storage.event_streams(subject,revision) VALUES($1,1) ON CONFLICT(subject) DO UPDATE SET revision=storage.event_streams.revision+1 RETURNING revision`, v.Subject).Scan(&revision); err != nil {
		return t.safe("event_stream", err)
	}
	v.Data = storage.EventData{Revision: revision, PolicyRevision: v.Revision, ObjectID: v.ObjectID, JobID: v.JobID}
	v.Type += ".v1"
	if err := t.save(`INSERT INTO storage.outbox(id,data) VALUES($1,$2)`, v, v.ID); err != nil {
		return err
	}
	result := v.AuditResult
	switch result {
	case "success", "denied", "failed", "unknown":
	default:
		result = "unknown"
	}
	school := v.AuditSchool
	if school == "" {
		school = "*"
	}
	if err := t.save(`INSERT INTO storage.audit(id,reason,result,audit_school,data) VALUES($1,$2,$3,$4,$5)`, struct {
		Event storage.Event     `json:"event"`
		Actor storage.Principal `json:"actor"`
	}{v, v.Actor}, v.ID, v.Reason, result, school); err != nil {
		return err
	}
	_, err := t.tx.ExecContext(t.ctx, `SELECT pg_notify('storage_outbox', $1)`, v.Subject)
	return t.safe("outbox_notify", err)
}
func (r *Repository) Claim(ctx context.Context, owner string, now time.Time, lease time.Duration) (storage.Job, error) {
	var result storage.Job
	err := r.Transaction(ctx, func(tx storage.Transaction) error {
		t := tx.(*transaction)
		j, err := read[storage.Job](t, `SELECT data FROM storage.jobs WHERE (state='pending' AND available_at<=$1) OR (state='running' AND lease_until<=$1) ORDER BY available_at,id LIMIT 1 FOR UPDATE SKIP LOCKED`, now)
		if err != nil {
			return err
		}
		j.State = "running"
		j.Generation++
		j.Attempts++
		j.LeaseOwner = owner
		j.LeaseUntil = now.Add(lease)
		if err = t.SaveJob(j); err != nil {
			return err
		}
		result = j
		return nil
	})
	return result, err
}
func (r *Repository) PendingEvents(ctx context.Context, limit int) ([]storage.Event, error) {
	return r.PendingEventsExcluding(ctx, limit, nil)
}

// PendingEventsExcluding starts a delivery pass. Only persisted acknowledgements
// suppress delivery between passes. Removing a subject from backoff makes
// all of its pending rows visible, including rows before a prior page cursor.
func (r *Repository) PendingEventsExcluding(ctx context.Context, limit int, excludeSubjects []string) ([]storage.Event, error) {
	return r.PendingEventsAfter(ctx, limit, 0, excludeSubjects)
}

// PendingEventsAfter pages within a pass with a fixed exclusion set. Begin
// each new pass with PendingEventsExcluding: allocation order can differ from
// commit order across subjects, and excluded subjects can become deliverable.
func (r *Repository) PendingEventsAfter(ctx context.Context, limit int, afterSeq int64, excludeSubjects []string) ([]storage.Event, error) {
	if limit < 1 || limit > 100 || afterSeq < 0 || len(excludeSubjects) > 1000 {
		return nil, storage.ErrInput
	}
	if excludeSubjects == nil {
		excludeSubjects = []string{}
	}
	var out []storage.Event
	err := r.Transaction(ctx, func(tx storage.Transaction) error {
		t := tx.(*transaction)
		rows, err := t.tx.QueryContext(t.ctx, `SELECT seq, data FROM storage.outbox WHERE NOT delivered AND seq>$1 AND NOT (data->>'subject' = ANY($2)) ORDER BY seq ASC LIMIT $3`, afterSeq, excludeSubjects, limit)
		if err != nil {
			return safe(err)
		}
		defer rows.Close()
		out = make([]storage.Event, 0)
		for rows.Next() {
			var seq int64
			var b []byte
			var item storage.Event
			if rows.Scan(&seq, &b) != nil || json.Unmarshal(b, &item) != nil {
				return storage.ErrUnavailable
			}
			item.Sequence = seq
			out = append(out, item)
		}
		return safe(rows.Err())
	})
	return out, err
}
func (r *Repository) AcknowledgeEvent(ctx context.Context, id string) error {
	_, err := r.DB.ExecContext(ctx, `UPDATE storage.outbox SET delivered=true, delivered_at=COALESCE(delivered_at,GREATEST(now(),(data->>'time')::timestamptz)) WHERE id=$1`, id)
	return r.safe("acknowledge_event", err)
}
