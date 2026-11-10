BEGIN;

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

COMMIT;
