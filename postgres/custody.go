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
	data, e := json.Marshal(b)
	if e != nil {
		return storage.ErrInput
	}
	_, e = t.tx.ExecContext(t.ctx, `INSERT INTO storage.custody_bindings(id,owner_issuer,owner_subject,account_domain,data) VALUES($1,$2,$3,NULLIF($4,''),$5) ON CONFLICT(id) DO UPDATE SET account_domain=EXCLUDED.account_domain,data=EXCLUDED.data WHERE storage.custody_bindings.owner_issuer=EXCLUDED.owner_issuer AND storage.custody_bindings.owner_subject=EXCLUDED.owner_subject`, b.ID, b.Owner.Issuer, b.Owner.Subject, b.AccountDomain, data)
	return safe(e)
}
func (t *custodyTx) SaveOperation(o custody.Operation) error {
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
	return safe(e)
}
func (t *custodyTx) List(p storage.Principal, n int, after string) ([]custody.Binding, error) {
	if !p.Valid() {
		return list[custody.Binding](t.transaction, `SELECT data FROM storage.custody_bindings WHERE id>$1 ORDER BY id LIMIT $2`, after, n)
	}
	return list[custody.Binding](t.transaction, `SELECT data FROM storage.custody_bindings WHERE owner_issuer=$1 AND owner_subject=$2 AND id>$3 ORDER BY id LIMIT $4`, p.Issuer, p.Subject, after, n)
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
	return n, safe(e)
}
func (t *custodyTx) OperationCount() (int, error) {
	var n int
	e := t.tx.QueryRowContext(t.ctx, `SELECT count(*) FROM storage.custody_operations o WHERE NOT COALESCE((o.data->>'Complete')::boolean,false) AND EXISTS(SELECT 1 FROM storage.custody_bindings b WHERE b.id=o.data->>'BindingID' AND b.data->>'request_id'=o.id AND (b.data->>'state'='pending' OR (b.data->>'state'='blocked' AND o.data->'Result'<>'null'::jsonb)))`).Scan(&n)
	return n, safe(e)
}

func (t *custodyTx) RecentAttempts(p storage.Principal, since time.Time) (int, error) {
	var n int
	e := t.tx.QueryRowContext(t.ctx, `SELECT COALESCE(sum(CASE WHEN jsonb_typeof(data->'AttemptTimes')='array' THEN (SELECT count(*) FROM jsonb_array_elements_text(data->'AttemptTimes') ts WHERE ts::timestamptz >= $3) ELSE (data->>'Attempts')::int END),0) FROM storage.custody_operations WHERE data->'Owner'->>'issuer'=$1 AND data->'Owner'->>'subject'=$2 AND (data->>'AttemptedAt')::timestamptz >= $3`, p.Issuer, p.Subject, since).Scan(&n)
	return n, safe(e)
}
