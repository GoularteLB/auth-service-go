CREATE TABLE clients (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id   text        NOT NULL UNIQUE CHECK (length(client_id) <= 64),
    name        text        NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    secret_hash bytea       NOT NULL CHECK (length(secret_hash) = 32),
    scopes      text[]      NOT NULL DEFAULT '{}',
    created_at  timestamptz NOT NULL DEFAULT now(),
    revoked_at  timestamptz
);

ALTER TABLE audit_events ADD COLUMN client_id text CHECK (length(client_id) <= 64);

CREATE INDEX audit_events_client_id_idx ON audit_events (client_id, occurred_at DESC) WHERE client_id IS NOT NULL;
