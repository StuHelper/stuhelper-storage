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

type Repository struct{ DB *sql.DB }
type transaction struct {
	tx  *sql.Tx
	ctx context.Context
}

func (t *transaction) JobSnapshot(id string) (storage.Job, error) {
	return read[storage.Job](t, `SELECT data FROM storage.jobs WHERE id=$1`, id)
}

func (t *transaction) InstanceReplicas(id string) (int64, error) {
	var count int64
	err := t.tx.QueryRowContext(t.ctx, `SELECT count(*) FROM storage.replicas WHERE instance_id=$1 AND data->>'state'<>'deleted'`, id).Scan(&count)
	return count, safe(err)
}

func (t *transaction) ActiveWrites(replicaID string, now time.Time) (bool, error) {
	var active bool
	err := t.tx.QueryRowContext(t.ctx, `SELECT EXISTS(SELECT 1 FROM storage.jobs WHERE data->>'replica_id'=$1 AND data->>'kind' IN ('ingest','replicate') AND state='running' AND lease_until>$2)`, replicaID, now).Scan(&active)
	return active, safe(err)
}

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
		return safe(err)
	}
	defer tx.Rollback()
	if err = f(&transaction{tx, ctx}); err != nil {
		return err
	}
	return safe(tx.Commit())
}
func (t *transaction) Lock(key string) error {
	_, err := t.tx.ExecContext(t.ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "stuhelper-storage:"+key)
	return safe(err)
}
func read[T any](t *transaction, query string, args ...any) (T, error) {
	var out T
	var b []byte
	if err := t.tx.QueryRowContext(t.ctx, query, args...).Scan(&b); err != nil {
		return out, safe(err)
	}
	if json.Unmarshal(b, &out) != nil {
		return out, storage.ErrUnavailable
	}
	return out, nil
}
func list[T any](t *transaction, query string, args ...any) ([]T, error) {
	rows, err := t.tx.QueryContext(t.ctx, query, args...)
	if err != nil {
		return nil, safe(err)
	}
	defer rows.Close()
	out := make([]T, 0)
	for rows.Next() {
		var b []byte
		var item T
		if rows.Scan(&b) != nil || json.Unmarshal(b, &item) != nil {
			return nil, storage.ErrUnavailable
		}
		out = append(out, item)
	}
	return out, safe(rows.Err())
}
func (t *transaction) save(query string, item any, args ...any) error {
	b, err := json.Marshal(item)
	if err != nil {
		return storage.ErrInput
	}
	args = append(args, string(b))
	_, err = t.tx.ExecContext(t.ctx, query, args...)
	return safe(err)
}
func (t *transaction) Instance(id string) (storage.Instance, error) {
	return read[storage.Instance](t, `SELECT data FROM storage.instances WHERE id=$1 FOR UPDATE`, id)
}
func (t *transaction) ContributionCandidates(owner string, limit int, after string) ([]storage.Instance, error) {
	return list[storage.Instance](t, `SELECT i.data FROM storage.instances i WHERE i.id>$1 AND i.data->>'owner_domain'=$2 AND i.data->>'ownership'='contributor' AND i.data->>'state'='paused' AND (i.data->'contribution_control' IS NULL OR i.data->'contribution_control'='null'::jsonb) AND (i.data->>'used')::bigint=0 AND (i.data->>'reserved')::bigint=0 AND NOT EXISTS(SELECT 1 FROM storage.replicas r WHERE r.instance_id=i.id AND r.data->>'state'<>'deleted') ORDER BY i.id LIMIT $3`, after, owner, limit)
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
func (t *transaction) Objects(limit int, after string) ([]storage.Object, error) {
	return list[storage.Object](t, `SELECT data FROM storage.objects WHERE id>$1 ORDER BY id LIMIT $2`, after, limit)
}
func (t *transaction) SaveObject(v storage.Object) error {
	return t.save(`INSERT INTO storage.objects(id,data) VALUES($1,$2) ON CONFLICT(id) DO UPDATE SET data=excluded.data`, v, v.ID)
}
func (t *transaction) Replicas(id string) ([]storage.Replica, error) {
	return list[storage.Replica](t, `SELECT data FROM storage.replicas WHERE object_id=$1 ORDER BY instance_id`, id)
}
func (t *transaction) SaveReplica(v storage.Replica) error {
	return t.save(`INSERT INTO storage.replicas(id,object_id,instance_id,data) VALUES($1,$2,$3,$4) ON CONFLICT(id) DO UPDATE SET data=excluded.data`, v, v.ID, v.ObjectID, v.InstanceID)
}
func (t *transaction) Job(id string) (storage.Job, error) {
	return read[storage.Job](t, `SELECT data FROM storage.jobs WHERE id=$1 FOR UPDATE`, id)
}
func (t *transaction) SaveJob(v storage.Job) error {
	return t.save(`INSERT INTO storage.jobs(id,object_id,state,available_at,lease_until,data) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(id) DO UPDATE SET state=excluded.state,available_at=excluded.available_at,lease_until=excluded.lease_until,data=excluded.data`, v, v.ID, v.ObjectID, v.State, v.AvailableAt, v.LeaseUntil)
}
func (t *transaction) OutstandingJobs(exclude string, limit int) (int, error) {
	var count int
	err := t.tx.QueryRowContext(t.ctx, `SELECT count(*) FROM (SELECT 1 FROM storage.jobs WHERE id<>$1 AND state IN ('pending','running') LIMIT $2) bounded`, exclude, limit).Scan(&count)
	return count, safe(err)
}
func (t *transaction) JobTotals() (storage.JobTotals, error) {
	var out storage.JobTotals
	err := t.tx.QueryRowContext(t.ctx, `SELECT count(*) FILTER (WHERE state='pending'),count(*) FILTER (WHERE state='running'),count(*) FILTER (WHERE state='blocked') FROM storage.jobs`).Scan(&out.Pending, &out.Running, &out.Blocked)
	return out, safe(err)
}
func (t *transaction) FailedJobs(limit int, after string) ([]storage.Job, error) {
	return list[storage.Job](t, `SELECT data FROM storage.jobs WHERE id>$1 AND state IN ('pending','running','blocked') AND COALESCE(data->>'error_code','')<>'' ORDER BY id LIMIT $2`, after, limit)
}
func (t *transaction) Idempotency(key string) (storage.Idempotency, error) {
	return read[storage.Idempotency](t, `SELECT data FROM storage.idempotency WHERE key=$1 FOR UPDATE`, key)
}
func (t *transaction) SaveIdempotency(v storage.Idempotency) error {
	return t.save(`INSERT INTO storage.idempotency(key,data) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET data=excluded.data`, v, v.Key)
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
		return safe(err)
	}
	v.Data = storage.EventData{Revision: revision, PolicyRevision: v.Revision, ObjectID: v.ObjectID, JobID: v.JobID}
	v.Type += ".v1"
	if err := t.save(`INSERT INTO storage.outbox(id,data) VALUES($1,$2)`, v, v.ID); err != nil {
		return err
	}
	return t.save(`INSERT INTO storage.audit(id,data) VALUES($1,$2)`, struct {
		Event storage.Event     `json:"event"`
		Actor storage.Principal `json:"actor"`
	}{v, v.Actor}, v.ID)
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
	if limit < 1 || limit > 100 {
		return nil, storage.ErrInput
	}
	var out []storage.Event
	err := r.Transaction(ctx, func(tx storage.Transaction) error {
		var err error
		out, err = list[storage.Event](tx.(*transaction), `SELECT data FROM storage.outbox WHERE NOT delivered ORDER BY id LIMIT $1`, limit)
		return err
	})
	return out, err
}
func (r *Repository) AcknowledgeEvent(ctx context.Context, id string) error {
	_, err := r.DB.ExecContext(ctx, `UPDATE storage.outbox SET delivered=true WHERE id=$1`, id)
	return safe(err)
}
