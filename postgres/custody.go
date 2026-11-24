package postgres

import (
	"context"
	"encoding/json"
	"time"

	storage "github.com/StuHelper/stuhelper-storage"
	"github.com/StuHelper/stuhelper-storage/custody"
)

// CustodyRepository shares only storage-owned tables and its append-only audit.
// A short registry lock bounds enrollment and serializes account claims. Network
// work is deliberately outside these transactions.
type CustodyRepository struct{ Repository *Repository }
type custodyTx struct{ *transaction }

func (r *CustodyRepository) Transaction(ctx context.Context, f func(custody.Tx) error) error {
	return r.Repository.Transaction(ctx, func(tx storage.Transaction) error {
		t := tx.(*transaction) // Repository.Transaction always creates this concrete transaction.
		if e := t.Lock("custody-registry"); e != nil {
			return e
		}
		return f(&custodyTx{t})
	})
}
func (t *custodyTx) Binding(id string) (custody.Binding, error) {
	return read[custody.Binding](t.transaction, `SELECT data FROM storage.custody_bindings WHERE id=$1`, id)
}
func (t *custodyTx) Operation(id string) (custody.Operation, error) {
	return read[custody.Operation](t.transaction, `SELECT data FROM storage.custody_operations WHERE id=$1`, id)
}
func (t *custodyTx) SaveBinding(b custody.Binding) error {
	if err := t.allowCustodyWrite(b.Owner); err != nil {
		return err
	}
	data, e := json.Marshal(b)
	if e != nil {
		return storage.ErrInput
	}
	_, e = t.tx.ExecContext(t.ctx, `INSERT INTO storage.custody_bindings(id,owner_issuer,owner_subject,account_domain,data) VALUES($1,$2,$3,NULLIF($4,''),$5) ON CONFLICT(id) DO UPDATE SET account_domain=EXCLUDED.account_domain,data=EXCLUDED.data WHERE storage.custody_bindings.owner_issuer=EXCLUDED.owner_issuer AND storage.custody_bindings.owner_subject=EXCLUDED.owner_subject`, b.ID, b.Owner.Issuer, b.Owner.Subject, b.AccountDomain, data)
	return t.safe("save_binding", e)
}
func (t *custodyTx) HasPendingWrites(id string, now time.Time) (bool, error) {
	var pending bool
	err := t.tx.QueryRowContext(t.ctx, `SELECT EXISTS(SELECT 1 FROM storage.custody_operations WHERE data->>'BindingID'=$1
 AND NOT (data->>'Complete')::boolean AND ((data->>'LeaseUntil')::timestamptz>$2 OR COALESCE(data->'Result','null'::jsonb)<>'null'::jsonb))`, id, now).Scan(&pending)
	return pending, t.safe("custody_pending_writes", err)
}
func (t *custodyTx) DeleteBinding(id string, owner storage.Principal, keepAttemptsSince time.Time) error {
	res, e := t.tx.ExecContext(t.ctx, `DELETE FROM storage.custody_bindings WHERE id=$1 AND owner_issuer=$2 AND owner_subject=$3`, id, owner.Issuer, owner.Subject)
	if e != nil {
		return safe(e)
	}
	rows, e := res.RowsAffected()
	if e != nil {
		return safe(e)
	}
	if rows == 0 {
		return storage.ErrNotFound
	}
	_, e = t.tx.ExecContext(t.ctx, `UPDATE storage.custody_operations SET orphan_purge_after=COALESCE((data->>'AttemptedAt')::timestamptz,$2::timestamptz) + interval '5 minutes' WHERE data->>'BindingID'=$1`, id, keepAttemptsSince)
	return t.safe("mark_orphan_operations", e)
}
func (t *custodyTx) SaveOperation(o custody.Operation) error {
	if err := t.allowCustodyWrite(o.Owner); err != nil {
		return err
	}
	data, e := json.Marshal(o)
	if e != nil {
		return storage.ErrInput
	}
	var completedAt any
	if o.Complete {
		ts := o.CompletedAt
		if ts.IsZero() {
			ts = o.AttemptedAt
		}
		if !ts.IsZero() {
			completedAt = ts
		}
	}
	_, e = t.tx.ExecContext(t.ctx, `INSERT INTO storage.custody_operations(id,completed_at,data) VALUES($1,$2,$3) ON CONFLICT(id) DO UPDATE SET completed_at=EXCLUDED.completed_at,data=EXCLUDED.data`, o.ID, completedAt, data)
	return t.safe("save_operation", e)
}

// Include operator-adopted instances in their owner's self-service list. The
// original instance ID is the authorization target. The first explicit update
// materializes a binding in the same transaction as its request and consent.
const ownedBindings = `SELECT b.id,b.data FROM storage.custody_bindings b WHERE b.owner_issuer=$1 AND b.owner_subject=$2
UNION ALL
SELECT i.id,jsonb_build_object(
 'id',i.id,'adapter','bhpan','state','ready','revision',(i.data->>'credential_revision')::bigint,
 'authorization_expires_at',i.data->'expires_at','request_id','','last_error','',
 'Owner',jsonb_build_object('issuer',$1::text,'subject',$2::text),'AccountDomain',i.account_domain,'Instance',i.data)
FROM storage.instances i WHERE i.data->>'ownership'='contributor' AND i.data->>'owner_domain'=$3
 AND i.data->>'adapter'='bhpan' AND i.data->>'state'<>'revoked' AND COALESCE(i.data->>'contribution_approval','')<>''
 AND NOT EXISTS (SELECT 1 FROM storage.custody_bindings b WHERE b.id=i.id)`

func (t *custodyTx) OwnedBinding(p storage.Principal, id string) (custody.Binding, error) {
	return read[custody.Binding](t.transaction, `SELECT data FROM (`+ownedBindings+`) rows WHERE id=$4`, p.Issuer, p.Subject, custody.OwnerDomain(p), id)
}

func (t *custodyTx) List(p storage.Principal, n int, after string) ([]custody.Binding, error) {
	if !p.Valid() {
		return list[custody.Binding](t.transaction, `SELECT data FROM storage.custody_bindings WHERE id>$1 ORDER BY id LIMIT $2`, after, n)
	}
	return list[custody.Binding](t.transaction, `SELECT data FROM (`+ownedBindings+`) rows WHERE id>$4 ORDER BY id LIMIT $5`, p.Issuer, p.Subject, custody.OwnerDomain(p), after, n)
}
func (t *custodyTx) Count(p storage.Principal) (int, error) {
	var n int
	var e error
	const activeFilter = `(COALESCE(b.data->'Instance'->>'id','')<>'' OR b.data->>'state'='pending' OR (b.data->>'state'='blocked' AND EXISTS(SELECT 1 FROM storage.custody_operations o WHERE o.id=b.data->>'request_id' AND o.data->'Result' IS NOT NULL AND o.data->'Result'<>'null'::jsonb)))`
	if !p.Valid() {
		e = t.tx.QueryRowContext(t.ctx, `SELECT count(*) FROM storage.custody_bindings b WHERE `+activeFilter).Scan(&n)
	} else {
		e = t.tx.QueryRowContext(t.ctx, `SELECT count(*) FROM storage.custody_bindings b WHERE b.owner_issuer=$1 AND b.owner_subject=$2 AND `+activeFilter, p.Issuer, p.Subject).Scan(&n)
	}
	return n, t.safe("custody_count", e)
}
func (t *custodyTx) OperationCount() (int, error) {
	var n int
	e := t.tx.QueryRowContext(t.ctx, `SELECT count(*) FROM storage.custody_operations o WHERE NOT COALESCE((o.data->>'Complete')::boolean,false) AND EXISTS(SELECT 1 FROM storage.custody_bindings b WHERE b.id=o.data->>'BindingID' AND b.data->>'request_id'=o.id AND (b.data->>'state'='pending' OR (b.data->>'state'='blocked' AND o.data->'Result'<>'null'::jsonb)))`).Scan(&n)
	return n, t.safe("custody_operation_count", e)
}

func (t *custodyTx) RecentAttempts(p storage.Principal, since time.Time) (int, error) {
	var n int
	e := t.tx.QueryRowContext(t.ctx, `SELECT COALESCE(sum(CASE WHEN jsonb_typeof(data->'AttemptTimes')='array' THEN (SELECT count(*) FROM jsonb_array_elements_text(data->'AttemptTimes') ts WHERE ts::timestamptz >= $3) ELSE (data->>'Attempts')::int END),0) FROM storage.custody_operations WHERE data->'Owner'->>'issuer'=$1 AND data->'Owner'->>'subject'=$2 AND (data->>'AttemptedAt')::timestamptz >= $3`, p.Issuer, p.Subject, since.UTC().Truncate(time.Microsecond)).Scan(&n)
	return n, t.safe("custody_recent_attempts", e)
}
func (t *custodyTx) OldestRecentAttempt(p storage.Principal, since time.Time) (time.Time, error) {
	var raw string
	e := t.tx.QueryRowContext(t.ctx, `SELECT COALESCE((SELECT ts FROM storage.custody_operations CROSS JOIN LATERAL jsonb_array_elements_text(CASE WHEN jsonb_typeof(data->'AttemptTimes')='array' THEN data->'AttemptTimes' ELSE jsonb_build_array(data->>'AttemptedAt') END) ts WHERE data->'Owner'->>'issuer'=$1 AND data->'Owner'->>'subject'=$2 AND ts::timestamptz >= $3 ORDER BY ts::timestamptz ASC, data->>'AttemptedAt' ASC LIMIT 1), '')`, p.Issuer, p.Subject, since.UTC().Truncate(time.Microsecond)).Scan(&raw)
	if e != nil {
		return time.Time{}, safe(e)
	}
	if raw == "" {
		return time.Time{}, nil
	}
	parsed, parseErr := time.Parse(time.RFC3339Nano, raw)
	if parseErr != nil {
		return time.Time{}, storage.ErrUnavailable
	}
	return parsed, nil
}
func (t *custodyTx) Idempotency(key string) (storage.Idempotency, error) {
	return t.transaction.Idempotency(key)
}
func (t *custodyTx) SaveIdempotency(v storage.Idempotency) error {
	return t.transaction.SaveIdempotency(v)
}

func (t *custodyTx) allowCustodyWrite(owner storage.Principal) error {
	domain := custody.OwnerDomain(owner)
	if err := t.Lock("closure:" + domain); err != nil {
		return err
	}
	var blocked bool
	err := t.tx.QueryRowContext(t.ctx, `SELECT EXISTS(SELECT 1 FROM storage.owner_closures WHERE owner_domain=$1 AND finalizing AND NOT cancelled)`, domain).Scan(&blocked)
	if err != nil {
		return t.safe("custody_closure", err)
	}
	if blocked {
		return storage.ErrConflict
	}
	return nil
}
