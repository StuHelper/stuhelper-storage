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
    data jsonb NOT NULL
);

CREATE TABLE IF NOT EXISTS storage.instances (
    id text PRIMARY KEY,
    account_domain text NOT NULL UNIQUE,
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
    data jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS replicas_instance ON storage.replicas(instance_id);
CREATE INDEX IF NOT EXISTS jobs_claim ON storage.jobs(state,available_at,lease_until);
CREATE TABLE IF NOT EXISTS storage.idempotency (
    key text PRIMARY KEY,
    data jsonb NOT NULL
);
CREATE TABLE IF NOT EXISTS storage.outbox (
    id text PRIMARY KEY,
    data jsonb NOT NULL,
    delivered boolean NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS outbox_pending ON storage.outbox(id) WHERE NOT delivered;
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
