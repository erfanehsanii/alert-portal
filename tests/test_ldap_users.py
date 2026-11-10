"""Unit tests for LDAP user provisioning."""

from types import SimpleNamespace
from unittest.mock import MagicMock
from uuid import UUID

import psycopg
import pytest

from app.auth.ldap_directory import LDAPIdentity
from app.services import ldap_users
from app.services.ldap_users import (
    LDAPAccountConflict,
    LDAPPortalUser,
    resolve_ldap_portal_user,
)


GUID = UUID("12345678-1234-5678-90ab-cdef12345678")


def identity(username="test.user"):
    return LDAPIdentity(
        username=username,
        object_guid=GUID,
    )


def result(row):
    return SimpleNamespace(fetchone=lambda: row)


@pytest.fixture
def db(monkeypatch):
    """Replace PostgreSQL with a mocked connection."""
    connection = MagicMock()

    context = MagicMock()
    context.__enter__.return_value = connection
    context.__exit__.return_value = False

    factory = MagicMock(return_value=context)

    monkeypatch.setattr(
        ldap_users,
        "get_database_connection",
        factory,
    )

    return connection, factory


def test_new_ldap_user_created_as_viewer(db):
    connection, _ = db

    connection.execute.side_effect = [
        result(None),  # GUID not found
        result(None),  # Username available
        result((8, "test.user", "viewer", True)),
        result(None),  # Audit event
    ]

    user = resolve_ldap_portal_user(identity())

    assert user == LDAPPortalUser(
        id=8,
        username="test.user",
        role="viewer",
    )

    insert_sql, insert_params = (
        connection.execute.call_args_list[2].args
    )

    assert "password_hash" in insert_sql
    assert "NULL" in insert_sql
    assert "ON CONFLICT DO NOTHING" in insert_sql
    assert insert_params == ("test.user", GUID)

    audit_params = (
        connection.execute.call_args_list[3].args[1]
    )

    assert audit_params[0] == "ldap_user_created"
    assert '"role": "viewer"' in audit_params[2]


def test_existing_ldap_user_preserves_role_and_id(db):
    connection, _ = db

    connection.execute.return_value = result(
        (12, "test.user", "admin", True)
    )

    user = resolve_ldap_portal_user(identity())

    assert user.id == 12
    assert user.role == "admin"
    assert user.username == "test.user"

    # Existing account needs no INSERT or UPDATE.
    assert connection.execute.call_count == 1


def test_ldap_username_change_preserves_identity(db):
    connection, _ = db

    connection.execute.side_effect = [
        result((15, "old.user", "editor", True)),
        result(None),  # New username available
        result(None),  # UPDATE
        result(None),  # Audit
    ]

    user = resolve_ldap_portal_user(
        identity("new.user")
    )

    assert user.id == 15
    assert user.username == "new.user"
    assert user.role == "editor"

    update_params = (
        connection.execute.call_args_list[2].args[1]
    )

    assert update_params == ("new.user", 15)

    audit_params = (
        connection.execute.call_args_list[3].args[1]
    )

    assert audit_params[0] == "ldap_username_updated"


def test_inactive_ldap_user_is_rejected(db):
    connection, _ = db

    connection.execute.return_value = result(
        (19, "test.user", "viewer", False)
    )

    user = resolve_ldap_portal_user(identity())

    assert user is None
    assert connection.execute.call_count == 1


@pytest.mark.parametrize(
    "existing_username",
    ["test.user", "TEST.USER"],
)
def test_existing_username_collision_is_rejected(
    db,
    existing_username,
):
    connection, _ = db

    connection.execute.side_effect = [
        result(None),   # No matching GUID
        result((5,)),   # Existing username
        result(None),   # No matching LDAP identity
    ]

    with pytest.raises(LDAPAccountConflict):
        resolve_ldap_portal_user(
            identity(existing_username)
        )

    conflict_sql = (
        connection.execute.call_args_list[1].args[0]
    )

    assert "LOWER(username)" in conflict_sql


def test_ldap_rename_cannot_take_another_username(db):
    connection, _ = db

    connection.execute.side_effect = [
        result((21, "old.user", "editor", True)),
        result((5,)),  # Username owned by another account
    ]

    with pytest.raises(LDAPAccountConflict):
        resolve_ldap_portal_user(
            identity("occupied.user")
        )

    assert connection.execute.call_count == 2


def test_concurrent_login_reuses_same_guid(db):
    connection, _ = db

    connection.execute.side_effect = [
        result(None),
        result((30,)),  # Username appeared concurrently
        result((30, "test.user", "viewer", True)),
    ]

    user = resolve_ldap_portal_user(identity())

    assert user.id == 30
    assert user.role == "viewer"
    assert connection.execute.call_count == 3


@pytest.mark.parametrize(
    "username",
    [
        "",
        "bad*username",
        "user name",
        "x" * 65,
    ],
)
def test_invalid_username_rejected_before_database(
    db,
    username,
):
    _, factory = db

    with pytest.raises(LDAPAccountConflict):
        resolve_ldap_portal_user(
            identity(username)
        )

    factory.assert_not_called()


def test_database_failure_is_not_silently_ignored(db):
    connection, _ = db

    connection.execute.side_effect = (
        psycopg.OperationalError("Simulated database outage")
    )

    with pytest.raises(psycopg.OperationalError):
        resolve_ldap_portal_user(identity())