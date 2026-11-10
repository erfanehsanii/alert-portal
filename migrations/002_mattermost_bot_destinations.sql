BEGIN;

-- Version 0.1.14 uses a shared Mattermost bot token and channel IDs. Keep the
-- 0.1.13 webhook table intact for a safe rollback; this migration is additive.
CREATE TABLE IF NOT EXISTS mattermost_bot_destinations (
    id UUID PRIMARY KEY,
    owner_user_id BIGINT NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(80) NOT NULL
        CHECK (length(btrim(name)) > 0),
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
    updated_by_user_id BIGINT
        REFERENCES users(id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMIT;
