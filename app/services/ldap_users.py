"""Provision and resolve LDAP users in the Alert Portal database."""

import json
import re
from dataclasses import dataclass

import psycopg

from app.auth.ldap_directory import LDAPIdentity
from app.services.database import get_database_connection


@dataclass(frozen=True)
class LDAPPortalUser:
    id: int
    username: str
    role: str


class LDAPAccountConflict(Exception):
    """An LDAP identity conflicts with an existing portal account."""


def _find_ldap_user(connection, object_guid):
    return connection.execute(
        """
        SELECT id, username, role, is_active
        FROM users
        WHERE auth_provider = 'ldap'
          AND ldap_object_guid = %s
        FOR UPDATE
        """,
        (object_guid,),
    ).fetchone()


def _audit_event(connection, action, user_id, details):
    connection.execute(
        """
        INSERT INTO audit_log (
            action,
            target_type,
            target_id,
            details
        )
        VALUES (%s, 'user', %s, %s::jsonb)
        """,
        (action, str(user_id), json.dumps(details)),
    )


def resolve_ldap_portal_user(
    identity: LDAPIdentity,
) -> LDAPPortalUser | None:
    """
    Resolve an authenticated AD identity to a portal account.

    The AD objectGUID is the stable identity.
    New users receive viewer permissions.
    Existing roles and active status are preserved.

    Returns None when the portal account is inactive.
    """

    username = identity.username.strip().lower()

    if not re.fullmatch(r"[a-z0-9._-]{1,64}", username):
        raise LDAPAccountConflict("Invalid LDAP username")

    try:
        with get_database_connection() as connection:
            user = _find_ldap_user(
                connection,
                identity.object_guid,
            )

            created = False

            if user is None:
                # Prevent case-insensitive username collisions,
                # including collisions with local accounts.
                conflict = connection.execute(
                    """
                    SELECT id
                    FROM users
                    WHERE LOWER(username) = %s
                    LIMIT 1
                    """,
                    (username,),
                ).fetchone()

                if conflict is None:
                    user = connection.execute(
                        """
                        INSERT INTO users (
                            username,
                            password_hash,
                            role,
                            is_active,
                            auth_provider,
                            ldap_object_guid
                        )
                        VALUES (
                            %s,
                            NULL,
                            'viewer',
                            TRUE,
                            'ldap',
                            %s
                        )
                        ON CONFLICT DO NOTHING
                        RETURNING
                            id, username, role, is_active
                        """,
                        (
                            username,
                            identity.object_guid,
                        ),
                    ).fetchone()

                    created = user is not None

                if user is None:
                    # Another login may have created this
                    # same LDAP identity concurrently.
                    user = _find_ldap_user(
                        connection,
                        identity.object_guid,
                    )

                    if user is None:
                        raise LDAPAccountConflict(
                            "LDAP username already exists"
                        )

            user_id, stored_username, role, is_active = user

            # A portal administrator may disable an LDAP
            # account independently of Active Directory.
            if not is_active:
                return None

            if stored_username != username:
                conflict = connection.execute(
                    """
                    SELECT id
                    FROM users
                    WHERE LOWER(username) = %s
                      AND id <> %s
                    LIMIT 1
                    """,
                    (username, user_id),
                ).fetchone()

                if conflict is not None:
                    raise LDAPAccountConflict(
                        "LDAP username already exists"
                    )

                connection.execute(
                    """
                    UPDATE users
                    SET username = %s,
                        updated_at = NOW()
                    WHERE id = %s
                    """,
                    (username, user_id),
                )

                _audit_event(
                    connection,
                    "ldap_username_updated",
                    user_id,
                    {
                        "old_username": stored_username,
                        "new_username": username,
                    },
                )

            elif created:
                _audit_event(
                    connection,
                    "ldap_user_created",
                    user_id,
                    {
                        "username": username,
                        "auth_provider": "ldap",
                        "role": "viewer",
                    },
                )

            return LDAPPortalUser(
                id=user_id,
                username=username,
                role=role,
            )

    except psycopg.errors.UniqueViolation as exc:
        raise LDAPAccountConflict(
            "LDAP username already exists"
        ) from exc