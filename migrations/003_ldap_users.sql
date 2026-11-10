BEGIN;

-- Identify whether an account uses local or LDAP authentication.
-- Existing accounts automatically remain local accounts.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS auth_provider VARCHAR(16)
        NOT NULL DEFAULT 'local',
    ADD COLUMN IF NOT EXISTS ldap_object_guid UUID;


-- LDAP accounts must not store local password hashes.

ALTER TABLE users
    ALTER COLUMN password_hash DROP NOT NULL;


-- Only supported authentication providers are permitted.

ALTER TABLE users
    ADD CONSTRAINT users_auth_provider_check
    CHECK (auth_provider IN ('local', 'ldap'));


-- Enforce consistency between authentication providers
-- and their credential/identity fields.

ALTER TABLE users
    ADD CONSTRAINT users_auth_data_check
    CHECK (
        (
            auth_provider = 'local'
            AND password_hash IS NOT NULL
            AND ldap_object_guid IS NULL
        )
        OR
        (
            auth_provider = 'ldap'
            AND password_hash IS NULL
            AND ldap_object_guid IS NOT NULL
        )
    );


-- Every Active Directory identity maps to exactly
-- one Alert Portal account.

CREATE UNIQUE INDEX IF NOT EXISTS
    idx_users_ldap_object_guid
ON users (ldap_object_guid)
WHERE ldap_object_guid IS NOT NULL;

COMMIT;