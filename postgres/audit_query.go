package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	a "github.com/StuHelper/stuhelper-storage/auditquery"
	"strconv"
	"strings"
	"unicode"
)

var _ a.Reader = (*Repository)(nil)

func auditText(v string, n int) bool {
	return len(v) <= n && !strings.ContainsFunc(v, unicode.IsControl)
}

// ReadAudit reads only explicitly projected fields inside a repeatable-read
// transaction. Visibility excludes late commits; epoch invalidates changed data.
func (r *Repository) ReadAudit(ctx context.Context, q a.Request) (out a.Batch, err error) {
	out.Records = []a.Record{}
	if q.Limit < 1 || q.Limit > 101 || len(q.Scopes) > 1000 || q.Until.IsZero() || (!q.From.IsZero() && !q.From.Before(q.Until)) || len(q.Snapshot) > 256 {
		return out, a.ErrInvalid
	}
	for _, v := range []string{q.Actor, q.Target} {
		if !auditText(v, 2048) {
			return out, a.ErrInvalid
		}
	}
	if !auditText(q.Action, 128) {
		return out, a.ErrInvalid
	}
	for _, s := range q.Scopes {
		for _, v := range []string{s.School, s.Group, s.Module} {
			if v == "" || !auditText(v, 256) {
				return out, a.ErrInvalid
			}
		}
	}
	if q.Before != nil && (q.Before.Time.IsZero() || q.Before.ID == "" || !auditText(q.Before.ID, 256) || q.Before.Source == "" || !auditText(q.Before.Source, 64)) {
		return out, a.ErrInvalid
	}
	defer func() {
		if err != nil && err != a.ErrInvalid {
			if ctx.Err() != nil {
				err = ctx.Err()
			} else {
				err = a.ErrUnavailable
			}
		}
	}()
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	var epoch int64
	if err = tx.QueryRowContext(ctx, `SELECT revision FROM storage.audit_retention WHERE singleton`).Scan(&epoch); err != nil {
		return out, err
	}
	var visibility string
	if q.Snapshot == "" {
		err = tx.QueryRowContext(ctx, `SELECT pg_current_snapshot()::text`).Scan(&visibility)
		if err != nil {
			return out, err
		}
	} else {
		previous, token, ok := strings.Cut(q.Snapshot, "|")
		if !ok || previous != strconv.FormatInt(epoch, 10) {
			return out, a.ErrUnavailable
		}
		visibility = token
	}
	out.Snapshot = strconv.FormatInt(epoch, 10) + "|" + visibility
	if len(out.Snapshot) > 256 {
		return out, a.ErrUnavailable
	}
	scopes, _ := json.Marshal(append([]a.Scope{}, q.Scopes...))
	var from, before any
	if !q.From.IsZero() {
		from = q.From
	}
	source, id := "", ""
	if q.Before != nil {
		before = q.Before.Time
		source = q.Before.Source
		id = q.Before.ID
	}
	rows, err := tx.QueryContext(ctx, `SELECT id::text, audit_actor,audit_target,audit_action,audit_school,audit_group,reason,result,audit_time
 FROM storage.audit a WHERE pg_visible_in_snapshot(recorded_xid,$1::pg_snapshot)
 AND EXISTS(SELECT 1 FROM jsonb_to_recordset($2::jsonb) s(school text,"group" text,module text) WHERE (s.school='*' OR s.school=a.audit_school) AND (s."group"='*' OR s."group"=a.audit_group) AND s.module IN ('*','storage'))
 AND ($3='' OR audit_actor=$3) AND ($4='' OR audit_target=$4) AND ($5='' OR audit_action=$5)
 AND ($6::timestamptz IS NULL OR audit_time >= $6) AND audit_time < $7
 AND ($8::timestamptz IS NULL OR (audit_time,'storage' COLLATE "C",id::text COLLATE "C") < ($8,$9::text COLLATE "C",$10::text COLLATE "C"))
 ORDER BY audit_time DESC,id::text COLLATE "C" DESC LIMIT $11`, visibility, scopes, q.Actor, q.Target, q.Action, from, q.Until, before, source, id, q.Limit)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		v := a.Record{Source: "storage", Scope: a.Scope{Module: "storage"}}
		if err = rows.Scan(&v.ID, &v.Actor, &v.Target, &v.Action, &v.Scope.School, &v.Scope.Group, &v.Reason, &v.Result, &v.CreatedAt); err != nil {
			return out, err
		}
		// Invalid or oversized free-text reasons are omitted from the public summary.
		if !auditText(v.Reason, 512) {
			v.Reason = ""
		}
		out.Records = append(out.Records, v)
	}
	if err = rows.Err(); err != nil {
		return out, err
	}
	err = tx.Commit()
	return out, err
}
