package postgres

import (
	"context"
	storage "github.com/StuHelper/stuhelper-storage"
	"time"
)

func (t *transaction) SetOwnerClosure(owner, closureID string, cancel bool) error {
	if err := t.Lock("closure:" + owner); err != nil {
		return err
	}
	var effective bool
	err := t.tx.QueryRowContext(t.ctx, `INSERT INTO storage.owner_closures(closure_id,owner_domain,cancelled) VALUES($1,$2,$3)
    ON CONFLICT(closure_id) DO UPDATE SET cancelled=storage.owner_closures.cancelled OR EXCLUDED.cancelled, changed_at=CASE WHEN NOT storage.owner_closures.cancelled AND EXCLUDED.cancelled THEN statement_timestamp() ELSE storage.owner_closures.changed_at END
    WHERE storage.owner_closures.owner_domain=EXCLUDED.owner_domain RETURNING NOT cancelled`, closureID, owner, cancel).Scan(&effective)
	if err != nil {
		return t.safe("closure_state", err)
	}
	if !effective {
		if err := t.tx.QueryRowContext(t.ctx, `SELECT EXISTS(SELECT 1 FROM storage.owner_closures WHERE owner_domain=$1 AND NOT cancelled)`, owner).Scan(&effective); err != nil {
			return t.safe("closure_read", err)
		}
	}
	_, err = t.tx.ExecContext(t.ctx, `UPDATE storage.instances SET closure_draining=$2 WHERE data->>'ownership'='contributor'
    AND data->>'owner_domain'=$1 AND closure_draining<>$2`, owner, effective)
	return t.safe("closure_instances", err)
}

func (t *transaction) OwnerDrainComplete(owner, closureID string) (bool, error) {
	var done bool
	err := t.tx.QueryRowContext(t.ctx, `SELECT EXISTS(SELECT 1 FROM storage.owner_closures WHERE owner_domain=$1 AND closure_id=$2 AND NOT cancelled)
        AND NOT EXISTS(SELECT 1 FROM storage.instances i WHERE i.data->>'ownership'='contributor' AND i.data->>'owner_domain'=$1
        AND (NOT i.closure_draining OR (i.data->>'used')::bigint<>0 OR (i.data->>'reserved')::bigint<>0
        OR EXISTS(SELECT 1 FROM storage.replicas r WHERE r.instance_id=i.id AND r.data->>'state'<>'deleted')))`, owner, closureID).Scan(&done)
	return done, t.safe("closure_drain", err)
}

func (t *transaction) OwnerInstances(owner, after string, limit int) ([]storage.Instance, error) {
	return t.instances(`SELECT `+readInstance+` FROM storage.instances WHERE data->>'ownership'='contributor' AND data->>'owner_domain'=$1 AND id>$2 ORDER BY id LIMIT $3`, owner, after, limit)
}

// Serialize the empty check with acquiring custody operation leases. An
// unfinished operation may still create a candidate credential and must settle.
func (t *transaction) FinalizeOwnerDrain(owner, closureID, issuer, subject string) (bool, error) {
	if err := t.Lock("closure:" + owner); err != nil {
		return false, err
	}
	done, err := t.OwnerDrainComplete(owner, closureID)
	if err != nil || !done {
		return false, err
	}
	var pending bool
	err = t.tx.QueryRowContext(t.ctx, `SELECT EXISTS(SELECT 1 FROM storage.custody_operations WHERE completed_at IS NULL AND data->'Owner'->>'issuer'=$1 AND data->'Owner'->>'subject'=$2)`, issuer, subject).Scan(&pending)
	if err != nil || pending {
		return false, t.safe("closure_custody", err)
	}
	_, err = t.tx.ExecContext(t.ctx, `UPDATE storage.owner_closures SET finalizing=true WHERE closure_id=$1 AND owner_domain=$2 AND NOT cancelled`, closureID, owner)
	return err == nil, t.safe("closure_finalize", err)
}

func (t *transaction) OwnerCleanup(owner, closureID string) (storage.OwnerCleanup, error) {
	var v storage.OwnerCleanup
	err := t.tx.QueryRowContext(t.ctx, `SELECT instance_cursor,binding_cursor,instances_done,bindings_done FROM storage.owner_closures WHERE owner_domain=$1 AND closure_id=$2 AND finalizing AND NOT cancelled`, owner, closureID).Scan(&v.InstanceCursor, &v.BindingCursor, &v.InstancesDone, &v.BindingsDone)
	return v, t.safe("closure_cursor", err)
}
func (t *transaction) AdvanceOwnerCleanup(owner, closureID string, prior, next storage.OwnerCleanup) error {
	res, err := t.tx.ExecContext(t.ctx, `UPDATE storage.owner_closures SET instance_cursor=$7,binding_cursor=$8,instances_done=$9,bindings_done=$10 WHERE owner_domain=$1 AND closure_id=$2 AND finalizing AND NOT cancelled AND (instance_cursor,binding_cursor,instances_done,bindings_done)=($3,$4,$5,$6)`, owner, closureID, prior.InstanceCursor, prior.BindingCursor, prior.InstancesDone, prior.BindingsDone, next.InstanceCursor, next.BindingCursor, next.InstancesDone, next.BindingsDone)
	if err != nil {
		return t.safe("closure_checkpoint", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return t.safe("closure_checkpoint", err)
	}
	if n != 1 {
		return storage.ErrConflict
	}
	return nil
}

func (r *Repository) RecordClosureCompletion(ctx context.Context, owner, id string, at time.Time) error {
	_, err := r.DB.ExecContext(ctx, `UPDATE storage.owner_closures SET completed_at=$3 WHERE owner_domain=$1 AND closure_id=$2 AND instances_done AND bindings_done AND completed_at IS NULL`, owner, id, at)
	return err
}
func (r *Repository) PruneClosureMarkers(ctx context.Context, limit int) (int64, error) {
	var n int64
	err := r.DB.QueryRowContext(ctx, `WITH due AS (
    SELECT closure_id FROM storage.owner_closures WHERE ((COALESCE(completed_at,CASE WHEN cancelled THEN changed_at END) AT TIME ZONE 'Asia/Shanghai')+interval '12 months') AT TIME ZONE 'Asia/Shanghai' <= statement_timestamp()
    ORDER BY COALESCE(completed_at,changed_at),closure_id LIMIT $1 FOR UPDATE SKIP LOCKED
 ), removed AS(DELETE FROM storage.owner_closures o USING due WHERE o.closure_id=due.closure_id RETURNING 1) SELECT count(*) FROM removed`, limit).Scan(&n)
	return n, err
}
