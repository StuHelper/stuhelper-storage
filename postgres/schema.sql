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
);
CREATE TABLE IF NOT EXISTS storage.event_streams (
    subject text PRIMARY KEY,
    revision bigint NOT NULL CHECK (revision > 0)
);

REVOKE ALL ON SCHEMA storage FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA storage FROM PUBLIC;
