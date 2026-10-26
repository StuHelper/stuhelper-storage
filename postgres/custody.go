package postgres

import (
	"context"
	"encoding/json"

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
	_, e = t.tx.ExecContext(t.ctx, `INSERT INTO storage.custody_operations(id,data) VALUES($1,$2) ON CONFLICT(id) DO UPDATE SET data=EXCLUDED.data`, o.ID, data)
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
	if !p.Valid() {
		e = t.tx.QueryRowContext(t.ctx, `SELECT count(*) FROM storage.custody_bindings`).Scan(&n)
	} else {
		e = t.tx.QueryRowContext(t.ctx, `SELECT count(*) FROM storage.custody_bindings WHERE owner_issuer=$1 AND owner_subject=$2`, p.Issuer, p.Subject).Scan(&n)
	}
	return n, safe(e)
}
func (t *custodyTx) OperationCount() (int, error) {
	var n int
	e := t.tx.QueryRowContext(t.ctx, `SELECT count(*) FROM storage.custody_operations`).Scan(&n)
	return n, safe(e)
}
