package postgres

import (
	"context"
	storage "github.com/StuHelper/stuhelper-storage"
	"strings"
)

// CheckRuntime rejects migration/admin identities and missing schema grants.
// It does not create schemas, change permissions, or inspect another module.
func (r *Repository) CheckRuntime(ctx context.Context) error {
	var allowed bool
	err := r.DB.QueryRowContext(ctx, `SELECT NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole FROM pg_roles WHERE rolname=current_user`).Scan(&allowed)
	if err != nil {
		return safe(err)
	}
	if !allowed {
		return storage.ErrDenied
	}
	err = r.DB.QueryRowContext(ctx, `SELECT has_schema_privilege(current_user,'storage','USAGE') AND NOT has_schema_privilege(current_user,'storage','CREATE') AND NOT has_table_privilege(current_user,'storage.audit','UPDATE') AND NOT has_table_privilege(current_user,'storage.audit','DELETE')`).Scan(&allowed)
	if err != nil {
		return safe(err)
	}
	if !allowed {
		return storage.ErrDenied
	}
	for _, table := range []string{"content_groups", "content_handles", "custody_bindings", "custody_operations", "instances", "objects", "replicas", "jobs", "idempotency", "outbox", "event_streams", "audit"} {
		privileges := "SELECT,INSERT,UPDATE,DELETE"
		if table == "audit" {
			privileges = "SELECT,INSERT"
		}
		// has_table_privilege with a list means ANY privilege, so test each.
		for _, privilege := range strings.Split(privileges, ",") {
			err = r.DB.QueryRowContext(ctx, `SELECT has_table_privilege(current_user,$1,$2)`, "storage."+table, privilege).Scan(&allowed)
			if err != nil {
				return safe(err)
			}
			if !allowed {
				return storage.ErrDenied
			}
		}
	}
	return nil
}
