package postgres

import (
	storage "github.com/StuHelper/stuhelper-storage"
	"time"
)

func (t *transaction) ContentGroup(id string) (storage.ContentGroup, error) {
	return read[storage.ContentGroup](t, `SELECT data FROM storage.content_groups WHERE id=$1`, id)
}
func (t *transaction) ActiveContentGroup(fingerprint string) (storage.ContentGroup, error) {
	return read[storage.ContentGroup](t, `SELECT data FROM storage.content_groups WHERE fingerprint=$1 AND active`, fingerprint)
}
func (t *transaction) SaveContentGroup(g storage.ContentGroup) error {
	return t.save(`INSERT INTO storage.content_groups(id,fingerprint,active,data) VALUES($1,$2,$3,$4) ON CONFLICT(id) DO UPDATE SET active=excluded.active,data=excluded.data`, g, g.ID, g.Fingerprint, g.State == "active")
}
func (t *transaction) ContentHandle(id string) (storage.ContentHandle, error) {
	return read[storage.ContentHandle](t, `SELECT data FROM storage.content_handles WHERE id=$1`, id)
}
func (t *transaction) SaveContentHandle(h storage.ContentHandle) error {
	return t.save(`INSERT INTO storage.content_handles(id,group_id,source_group_id,pending_group_id,active,data) VALUES($1,$2,NULLIF($3,''),NULLIF($4,''),$5,$6) ON CONFLICT(id) DO UPDATE SET group_id=excluded.group_id,source_group_id=excluded.source_group_id,pending_group_id=excluded.pending_group_id,active=excluded.active,data=excluded.data`, h, h.ID, h.GroupID, h.SourceGroup, h.PendingGroup, h.State == "active")
}
func (t *transaction) ContentGroupHeld(id string) (bool, error) {
	var held bool
	err := t.tx.QueryRowContext(t.ctx, `SELECT EXISTS(SELECT 1 FROM storage.content_handles WHERE group_id=$1 AND active) OR EXISTS(SELECT 1 FROM storage.content_handles WHERE source_group_id=$1 AND active) OR EXISTS(SELECT 1 FROM storage.content_handles WHERE pending_group_id=$1 AND active)`, id).Scan(&held)
	return held, safe(err)
}
func (t *transaction) ContentCleanup(limit int, after string) ([]storage.ContentGroup, error) {
	return list[storage.ContentGroup](t, `SELECT data FROM storage.content_groups WHERE NOT active AND data->>'state'='deleting' AND id>$1 ORDER BY data->>'cleanup_checked_at',id LIMIT $2`, after, limit)
}

func (t *transaction) ExpiredContentHandles(limit int, before time.Time) ([]storage.ContentHandle, error) {
	return list[storage.ContentHandle](t, `SELECT data FROM storage.content_handles WHERE active AND jsonb_array_length(data->'references')=0 AND (data->>'created_at')::timestamptz<=$1 ORDER BY data->>'created_at',id LIMIT $2`, before, limit)
}
