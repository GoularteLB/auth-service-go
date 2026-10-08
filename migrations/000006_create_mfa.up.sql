CREATE TABLE user_mfa (
    user_id           uuid        PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret_ciphertext bytea       NOT NULL CHECK (length(secret_ciphertext) <= 128),
    enabled_at        timestamptz,
    last_used_step    bigint      NOT NULL DEFAULT 0,
    created_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE mfa_recovery_codes (
    user_id   uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash bytea       NOT NULL CHECK (length(code_hash) = 32),
    used_at   timestamptz,
    PRIMARY KEY (user_id, code_hash)
);
