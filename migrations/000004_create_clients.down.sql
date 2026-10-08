DROP INDEX IF EXISTS audit_events_client_id_idx;
ALTER TABLE audit_events DROP COLUMN IF EXISTS client_id;
DROP TABLE IF EXISTS clients;
