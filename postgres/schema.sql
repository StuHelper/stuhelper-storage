CREATE SCHEMA IF NOT EXISTS storage;

CREATE TABLE IF NOT EXISTS storage.custody_bindings (
    id text PRIMARY KEY,
    owner_issuer text NOT NULL,
    owner_subject text NOT NULL,
    account_domain text UNIQUE,
    data jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS custody_owner ON storage.custody_bindings(owner_issuer,owner_subject,id);
CREATE TABLE IF NOT EXISTS storage.custody_operations (
    id text PRIMARY KEY,
    completed_at timestamptz,
    data jsonb NOT NULL
);
ALTER TABLE storage.custody_operations ADD COLUMN IF NOT EXISTS completed_at timestamptz;
ALTER TABLE storage.custody_operations ADD COLUMN IF NOT EXISTS orphan_purge_after timestamptz;
UPDATE storage.custody_operations o SET orphan_purge_after=COALESCE((o.data->>'AttemptedAt')::timestamptz,transaction_timestamp()) + interval '5 minutes'
WHERE orphan_purge_after IS NULL AND data ? 'BindingID' AND NOT EXISTS (SELECT 1 FROM storage.custody_bindings b WHERE b.id=o.data->>'BindingID');
CREATE INDEX IF NOT EXISTS custody_orphan_purge_after ON storage.custody_operations(orphan_purge_after) WHERE orphan_purge_after IS NOT NULL;
UPDATE storage.custody_operations SET completed_at=transaction_timestamp() WHERE completed_at IS NULL AND (data->>'Complete')::boolean;
CREATE INDEX IF NOT EXISTS custody_operations_completed_at ON storage.custody_operations(completed_at) WHERE completed_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS storage.instances (
    id text PRIMARY KEY,
    account_domain text NOT NULL UNIQUE,
    data jsonb NOT NULL
);
CREATE TABLE IF NOT EXISTS storage.contribution_admission_policy (
    singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
    data jsonb NOT NULL
);
CREATE TABLE IF NOT EXISTS storage.objects (
    id text PRIMARY KEY,
    data jsonb NOT NULL
);
CREATE TABLE IF NOT EXISTS storage.replicas (
    id text PRIMARY KEY,
    object_id text NOT NULL REFERENCES storage.objects(id),
    instance_id text NOT NULL REFERENCES storage.instances(id),
    data jsonb NOT NULL,
    UNIQUE (object_id, instance_id)
);
CREATE TABLE IF NOT EXISTS storage.jobs (
    id text PRIMARY KEY,
    object_id text NOT NULL REFERENCES storage.objects(id),
    state text NOT NULL,
    available_at timestamptz NOT NULL,
    lease_until timestamptz NOT NULL,
    completed_at timestamptz,
    data jsonb NOT NULL
);
ALTER TABLE storage.jobs ADD COLUMN IF NOT EXISTS completed_at timestamptz;
UPDATE storage.jobs SET completed_at=transaction_timestamp() WHERE completed_at IS NULL AND state='done';
CREATE INDEX IF NOT EXISTS objects_reconcile ON storage.objects(id) WHERE data->>'state'<>'deleted';
CREATE INDEX IF NOT EXISTS replicas_instance ON storage.replicas(instance_id);
CREATE INDEX IF NOT EXISTS jobs_active_claim ON storage.jobs(state,available_at,lease_until) WHERE state IN ('pending','running','blocked');
DROP INDEX IF EXISTS storage.jobs_claim;
CREATE INDEX IF NOT EXISTS jobs_failed ON storage.jobs(id) WHERE state IN ('pending','running','blocked') AND COALESCE(data->>'error_code','')<>'';
CREATE INDEX IF NOT EXISTS jobs_completed_at ON storage.jobs(completed_at) WHERE state='done';
CREATE TABLE IF NOT EXISTS storage.idempotency (
    key text PRIMARY KEY,
    expires_at timestamptz,
    data jsonb NOT NULL
);
ALTER TABLE storage.idempotency ADD COLUMN IF NOT EXISTS expires_at timestamptz;
UPDATE storage.idempotency SET expires_at=(data->>'ExpiresAt')::timestamptz WHERE expires_at IS NULL AND data ? 'ExpiresAt';
CREATE INDEX IF NOT EXISTS idempotency_expires_at ON storage.idempotency(expires_at);
CREATE TABLE IF NOT EXISTS storage.outbox (
    seq bigint GENERATED ALWAYS AS IDENTITY,
    id text PRIMARY KEY,
    data jsonb NOT NULL,
    delivered boolean NOT NULL DEFAULT false,
    delivered_at timestamptz
);
ALTER TABLE storage.outbox ADD COLUMN IF NOT EXISTS delivered_at timestamptz;
UPDATE storage.outbox SET delivered_at=transaction_timestamp() WHERE delivered_at IS NULL AND delivered;
-- Existing rows have no global commit order. Preserve each stream's durable
-- revision order and advance the identity past the backfilled rows atomically.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid='storage.outbox'::regclass
                   AND attname='seq' AND NOT attisdropped) THEN
        ALTER TABLE storage.outbox ADD COLUMN seq bigint;
        WITH ranked AS (
            SELECT id, row_number() OVER (ORDER BY data->>'subject', (data#>>'{data,revision}')::bigint, id) AS position
            FROM storage.outbox
        )
        UPDATE storage.outbox o SET seq=ranked.position FROM ranked WHERE o.id=ranked.id;
        ALTER TABLE storage.outbox ALTER COLUMN seq SET NOT NULL;
        ALTER TABLE storage.outbox ALTER COLUMN seq ADD GENERATED ALWAYS AS IDENTITY;
        PERFORM setval(pg_get_serial_sequence('storage.outbox','seq'), COALESCE(max(seq),0)+1, false)
        FROM storage.outbox;
    END IF;
END $$;
CREATE INDEX IF NOT EXISTS outbox_pending ON storage.outbox(id) WHERE NOT delivered;
CREATE INDEX IF NOT EXISTS outbox_delivered_at ON storage.outbox(delivered_at) WHERE delivered;
CREATE INDEX IF NOT EXISTS outbox_pending_seq ON storage.outbox(seq) WHERE NOT delivered;
CREATE TABLE IF NOT EXISTS storage.audit (
    id text PRIMARY KEY,
    data jsonb NOT NULL
, reason text NOT NULL DEFAULT '', result text NOT NULL DEFAULT 'unknown' CHECK(result IN ('success','denied','failed','unknown')), recorded_xid xid8 NOT NULL DEFAULT pg_current_xact_id(), audit_actor text NOT NULL DEFAULT 'unknown', audit_target text NOT NULL DEFAULT 'unknown', audit_action text NOT NULL DEFAULT 'unknown', audit_school text NOT NULL DEFAULT '*', audit_group text NOT NULL DEFAULT '*', audit_time timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS storage.event_streams (
    subject text PRIMARY KEY,
    revision bigint NOT NULL CHECK (revision > 0)
);

CREATE TABLE IF NOT EXISTS storage.content_groups (
 id text PRIMARY KEY, fingerprint text NOT NULL, active boolean NOT NULL, data jsonb NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS content_group_active ON storage.content_groups(fingerprint) WHERE active;
CREATE INDEX IF NOT EXISTS content_group_cleanup ON storage.content_groups((data->>'cleanup_checked_at'),id) WHERE NOT active;
CREATE TABLE IF NOT EXISTS storage.content_handles (
 id text PRIMARY KEY, group_id text NOT NULL REFERENCES storage.content_groups(id),
 source_group_id text REFERENCES storage.content_groups(id), pending_group_id text REFERENCES storage.content_groups(id),
 active boolean NOT NULL, data jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS content_handle_expiry ON storage.content_handles((data->>'created_at'),id) WHERE active AND jsonb_array_length(data->'references')=0;
CREATE INDEX IF NOT EXISTS content_handle_group ON storage.content_handles(group_id) WHERE active;
CREATE INDEX IF NOT EXISTS content_handle_source ON storage.content_handles(source_group_id) WHERE active;
CREATE INDEX IF NOT EXISTS content_handle_pending ON storage.content_handles(pending_group_id) WHERE active;

REVOKE ALL ON SCHEMA storage FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA storage FROM PUBLIC;


CREATE TABLE IF NOT EXISTS storage.audit_retention(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton), revision bigint NOT NULL DEFAULT 0);
INSERT INTO storage.audit_retention(singleton) VALUES(true) ON CONFLICT DO NOTHING;
CREATE OR REPLACE FUNCTION storage.audit_project() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN NEW.audit_actor=CASE WHEN COALESCE(NEW.data->'actor'->>'issuer','')='' OR COALESCE(NEW.data->'actor'->>'subject','')='' THEN 'unknown' ELSE translate(rtrim(replace(encode(convert_to(NEW.data->'actor'->>'issuer','UTF8'),'base64'),E'\n',''),'='),'+/','-_')||':'||translate(rtrim(replace(encode(convert_to(NEW.data->'actor'->>'subject','UTF8'),'base64'),E'\n',''),'='),'+/','-_') END; NEW.audit_target=COALESCE(NULLIF(NEW.data->'event'->'data'->>'object_id',''),NULLIF(NEW.data->'event'->>'subject',''),'unknown'); NEW.audit_action=NEW.data->'event'->>'type'; NEW.audit_time=(NEW.data->'event'->>'time')::timestamptz; RETURN NEW; END $$;
CREATE OR REPLACE TRIGGER audit_project BEFORE INSERT OR UPDATE ON storage.audit FOR EACH ROW EXECUTE FUNCTION storage.audit_project();
CREATE OR REPLACE FUNCTION storage.audit_invalidate() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN UPDATE storage.audit_retention SET revision=revision+1 WHERE singleton; RETURN NULL; END $$;
REVOKE ALL ON FUNCTION storage.audit_invalidate() FROM PUBLIC;
CREATE OR REPLACE TRIGGER audit_invalidate AFTER UPDATE OR DELETE OR TRUNCATE ON storage.audit FOR EACH STATEMENT EXECUTE FUNCTION storage.audit_invalidate();
CREATE INDEX IF NOT EXISTS audit_query_order ON storage.audit(audit_time DESC,(id::text) COLLATE "C" DESC);

CREATE INDEX IF NOT EXISTS content_handles_prepared_group ON storage.content_handles ((data->>'prepared_group')) WHERE active AND data->>'prepared_group' IS NOT NULL;

CREATE TABLE IF NOT EXISTS storage.owner_closures(
    closure_id text PRIMARY KEY, owner_domain text NOT NULL, cancelled boolean NOT NULL,
    changed_at timestamptz NOT NULL DEFAULT statement_timestamp()
);
ALTER TABLE storage.owner_closures ADD COLUMN IF NOT EXISTS finalizing boolean NOT NULL DEFAULT false;
CREATE UNIQUE INDEX IF NOT EXISTS owner_closures_active ON storage.owner_closures(owner_domain) WHERE NOT cancelled;
ALTER TABLE storage.instances ADD COLUMN IF NOT EXISTS closure_draining boolean NOT NULL DEFAULT false;
CREATE INDEX IF NOT EXISTS instances_contributor_owner ON storage.instances((data->>'owner_domain'),id) WHERE data->>'ownership'='contributor';

-- Serialize enrollment/adoption with a change of the owner's write barrier.
CREATE OR REPLACE FUNCTION storage.set_instance_closure() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='UPDATE' AND NEW.data->>'ownership' IS NOT DISTINCT FROM OLD.data->>'ownership'
    AND NEW.data->>'owner_domain' IS NOT DISTINCT FROM OLD.data->>'owner_domain' THEN
    RETURN NEW;
 END IF;
 NEW.closure_draining=false;
 IF NEW.data->>'ownership'='contributor' THEN
    PERFORM pg_advisory_xact_lock(hashtextextended('stuhelper-storage:closure:' || (NEW.data->>'owner_domain'),0));
    IF EXISTS(SELECT 1 FROM storage.owner_closures WHERE owner_domain=NEW.data->>'owner_domain' AND finalizing AND NOT cancelled)
       AND NOT EXISTS(SELECT 1 FROM storage.instances i WHERE i.id=NEW.id AND i.data->>'owner_domain'=NEW.data->>'owner_domain') THEN
       RAISE EXCEPTION 'closing storage owner' USING ERRCODE='40001';
    END IF;
    SELECT EXISTS(SELECT 1 FROM storage.owner_closures WHERE owner_domain=NEW.data->>'owner_domain' AND NOT cancelled) INTO NEW.closure_draining;
 END IF;
 RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS instance_closure ON storage.instances;
CREATE TRIGGER instance_closure BEFORE INSERT OR UPDATE OF data ON storage.instances FOR EACH ROW EXECUTE FUNCTION storage.set_instance_closure();
ALTER TABLE storage.owner_closures ADD COLUMN IF NOT EXISTS instance_cursor text NOT NULL DEFAULT '';
ALTER TABLE storage.owner_closures ADD COLUMN IF NOT EXISTS binding_cursor text NOT NULL DEFAULT '';
ALTER TABLE storage.owner_closures ADD COLUMN IF NOT EXISTS instances_done boolean NOT NULL DEFAULT false;
ALTER TABLE storage.owner_closures ADD COLUMN IF NOT EXISTS bindings_done boolean NOT NULL DEFAULT false;

ALTER TABLE storage.owner_closures ADD COLUMN IF NOT EXISTS completed_at timestamptz;
CREATE INDEX IF NOT EXISTS owner_closure_completed ON storage.owner_closures(completed_at,closure_id) WHERE completed_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS owner_closure_cancelled ON storage.owner_closures(changed_at,closure_id) WHERE cancelled;
