CREATE TABLE audit_events (
    id          bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    event_type  text        NOT NULL CHECK (length(event_type) <= 64),
    user_id     uuid,
    email       citext      CHECK (length(email) <= 254),
    ip          inet,
    user_agent  text        CHECK (length(user_agent) <= 512),
    request_id  text        CHECK (length(request_id) <= 64)
);

CREATE INDEX audit_events_user_id_idx ON audit_events (user_id, occurred_at DESC) WHERE user_id IS NOT NULL;
CREATE INDEX audit_events_email_idx ON audit_events (email, occurred_at DESC) WHERE email IS NOT NULL;
CREATE INDEX audit_events_ip_idx ON audit_events (ip, occurred_at DESC) WHERE ip IS NOT NULL;
