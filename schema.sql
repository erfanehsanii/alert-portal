
BEGIN;

CREATE TABLE IF NOT EXISTS users (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username VARCHAR(64) NOT NULL UNIQUE,
    -- LDAP identities are mapped to a stable AD objectGUID and never
    -- receive a local password hash. Local accounts retain their hashes.
    password_hash TEXT,
    auth_provider VARCHAR(16) NOT NULL DEFAULT 'local'
        CONSTRAINT users_auth_provider_check
        CHECK (auth_provider IN ('local', 'ldap')),
    ldap_object_guid UUID,
    role VARCHAR(16) NOT NULL
        CHECK (role IN ('admin', 'editor', 'viewer')),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ,
    CONSTRAINT users_auth_data_check CHECK (
        (
            auth_provider = 'local'
            AND password_hash IS NOT NULL
            AND ldap_object_guid IS NULL
        ) OR (
            auth_provider = 'ldap'
            AND password_hash IS NULL
            AND ldap_object_guid IS NOT NULL
        )
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_ldap_object_guid
    ON users (ldap_object_guid)
    WHERE ldap_object_guid IS NOT NULL;

CREATE TABLE IF NOT EXISTS user_sessions (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id BIGINT NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,
    token_hash CHAR(64) NOT NULL UNIQUE,
    csrf_token_hash CHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    CHECK (expires_at > created_at)
);
CREATE TABLE IF NOT EXISTS login_csrf_tokens (
    token_hash CHAR(64) PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_login_csrf_tokens_expires_at
    ON login_csrf_tokens(expires_at);

CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id
    ON user_sessions(user_id);

CREATE INDEX IF NOT EXISTS idx_user_sessions_expires_at
    ON user_sessions(expires_at);

CREATE TABLE IF NOT EXISTS audit_log (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_user_id BIGINT
        REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    target_type VARCHAR(100),
    target_id VARCHAR(100),
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_log_created_at
    ON audit_log(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_log_actor_user_id
    ON audit_log(actor_user_id);

CREATE TABLE IF NOT EXISTS mattermost_destinations (
    id UUID PRIMARY KEY,
    owner_user_id BIGINT NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(80) NOT NULL
        CHECK (length(btrim(name)) > 0),
    server_host VARCHAR(260) NOT NULL,
    webhook_url_encrypted TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_mm_dest_owner_name_ci
    ON mattermost_destinations (owner_user_id, lower(name));

CREATE INDEX IF NOT EXISTS idx_mm_dest_server_host
    ON mattermost_destinations (server_host);


-- Shared Mattermost bot channel destinations (v0.1.14).
CREATE TABLE IF NOT EXISTS mattermost_bot_destinations (
    id UUID PRIMARY KEY,
    owner_user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(80) NOT NULL CHECK (length(btrim(name)) > 0),
    server_host VARCHAR(260) NOT NULL,
    team_id VARCHAR(64) NOT NULL,
    team_name VARCHAR(128) NOT NULL,
    channel_id VARCHAR(64) NOT NULL,
    channel_name VARCHAR(128) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_mm_bot_dest_owner_name_ci
    ON mattermost_bot_destinations (owner_user_id, lower(name));
CREATE UNIQUE INDEX IF NOT EXISTS idx_mm_bot_dest_owner_channel
    ON mattermost_bot_destinations (owner_user_id, channel_id);
CREATE INDEX IF NOT EXISTS idx_mm_bot_dest_channel
    ON mattermost_bot_destinations (channel_id);

CREATE TABLE IF NOT EXISTS mattermost_bot_route_mappings (
    route_key VARCHAR(16) PRIMARY KEY
        CHECK (route_key IN ('cpu', 'disk', 'memory', 'uptime')),
    destination_id UUID NOT NULL
        REFERENCES mattermost_bot_destinations(id) ON DELETE RESTRICT,
    updated_by_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMIT;
