from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.auth.dependencies import AuthenticatedUser, get_current_user
from app.main import app
from app.routes.rules import require_valid_csrf


ADMIN = AuthenticatedUser(id=1, username="admin-user", role="admin")
EDITOR = AuthenticatedUser(id=2, username="editor-user", role="editor")
VIEWER = AuthenticatedUser(id=3, username="viewer-user", role="viewer")
LDAP_ADMIN = AuthenticatedUser(id=99, username="ad-admin", role="admin")

NOW = datetime(2026, 10, 23, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def client():
    app.dependency_overrides.clear()
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def user_row(
    user_id=10,
    username="test-user",
    role="editor",
    is_active=True,
    auth_provider="local",
):
    return (
        user_id,
        username,
        role,
        is_active,
        NOW,
        NOW,
        None,
        auth_provider,
    )


def cursor(one=None, many=None, rowcount=0):
    result = MagicMock()
    result.fetchone.return_value = one
    result.fetchall.return_value = many if many is not None else []
    result.rowcount = rowcount
    return result


def normalized_sql(sql):
    """Normalize multiline SQL so mock matching is whitespace-independent."""
    return " ".join(sql.split())


def selects_active_local_admins(sql):
    normalized = normalized_sql(sql)
    return (
        "WHERE auth_provider = 'local'"
        " AND role = 'admin'"
        " AND is_active = TRUE" in normalized
        and "FOR UPDATE" in normalized
    )


def authenticate_as(user, *, bypass_csrf=False):
    app.dependency_overrides[get_current_user] = lambda: user
    if bypass_csrf:
        # Isolate endpoint behavior in these tests.
        # CSRF rejection is tested separately.
        app.dependency_overrides[require_valid_csrf] = lambda: user


def mock_database(mock_db, connection):
    mock_db.return_value.__enter__.return_value = connection


def test_admin_can_list_users_without_exposing_password_hashes(client):
    authenticate_as(ADMIN)
    connection = MagicMock()
    connection.execute.return_value = cursor(
        many=[
            user_row(1, "admin-user", "admin"),
            user_row(10, "test-user", "editor", auth_provider="ldap"),
        ]
    )

    with patch("app.routes.users.get_database_connection") as mock_db:
        mock_database(mock_db, connection)
        response = client.get("/api/users")

    assert response.status_code == 200
    assert len(response.json()["items"]) == 2
    assert response.json()["items"][0]["username"] == "admin-user"
    assert response.json()["items"][0]["auth_provider"] == "local"
    assert response.json()["items"][1]["auth_provider"] == "ldap"
    assert "password_hash" not in response.text
    assert "ldap_object_guid" not in response.text


def test_non_admin_cannot_list_users(client):
    authenticate_as(EDITOR)

    with patch("app.routes.users.get_database_connection") as mock_db:
        response = client.get("/api/users")

    assert response.status_code == 403
    mock_db.assert_not_called()


def test_create_user_requires_csrf(client):
    authenticate_as(ADMIN)

    with patch("app.routes.users.get_database_connection") as mock_db:
        response = client.post(
            "/api/users",
            json={
                "username": "new-user",
                "password": "Strong-Test-Password-123",
                "role": "viewer",
            },
        )

    assert response.status_code == 403
    mock_db.assert_not_called()


def test_admin_can_create_user_and_audit_it(client):
    authenticate_as(ADMIN, bypass_csrf=True)
    connection = MagicMock()
    new_user = user_row(10, "new-user", "editor")

    def execute(sql, params=None):
        sql = normalized_sql(sql)

        if "SELECT id FROM users WHERE lower(username) = %s" in sql:
            return cursor(one=None)

        if "INSERT INTO users" in sql:
            return cursor(one=new_user)

        return cursor()

    connection.execute.side_effect = execute

    with (
        patch("app.routes.users.get_database_connection") as mock_db,
        patch(
            "app.routes.users.hash_password",
            return_value="fake-secure-password-hash",
        ) as hash_mock,
    ):
        mock_database(mock_db, connection)
        response = client.post(
            "/api/users",
            json={
                "username": "New-User",
                "password": "Strong-Test-Password-123",
                "role": "editor",
            },
        )

    assert response.status_code == 201
    assert response.json()["username"] == "new-user"
    assert response.json()["role"] == "editor"
    assert response.json()["is_active"] is True
    assert response.json()["auth_provider"] == "local"
    assert "password_hash" not in response.json()

    hash_mock.assert_called_once_with("Strong-Test-Password-123")
    connection.commit.assert_called_once()

    sql_calls = [
        normalized_sql(call.args[0])
        for call in connection.execute.call_args_list
    ]
    assert any("INSERT INTO audit_log" in sql for sql in sql_calls)

    inserted_user_call = next(
        call
        for call in connection.execute.call_args_list
        if "INSERT INTO users" in normalized_sql(call.args[0])
    )
    assert "'local'" in normalized_sql(inserted_user_call.args[0])
    assert inserted_user_call.args[1] == (
        "new-user",
        "fake-secure-password-hash",
        "editor",
    )


def test_duplicate_username_is_rejected(client):
    authenticate_as(ADMIN, bypass_csrf=True)
    connection = MagicMock()

    def execute(sql, params=None):
        sql = normalized_sql(sql)

        if "SELECT id FROM users WHERE lower(username) = %s" in sql:
            return cursor(one=(10,))

        return cursor()

    connection.execute.side_effect = execute

    with patch("app.routes.users.get_database_connection") as mock_db:
        mock_database(mock_db, connection)
        response = client.post(
            "/api/users",
            json={
                "username": "existing-user",
                "password": "Strong-Test-Password-123",
                "role": "viewer",
            },
        )

    assert response.status_code == 409
    assert "already exists" in response.json()["detail"]
    connection.commit.assert_not_called()

    assert not any(
        "INSERT INTO users" in normalized_sql(call.args[0])
        for call in connection.execute.call_args_list
    )


def test_invalid_role_is_rejected(client):
    authenticate_as(ADMIN, bypass_csrf=True)

    with patch("app.routes.users.get_database_connection") as mock_db:
        response = client.post(
            "/api/users",
            json={
                "username": "bad-role-user",
                "password": "Strong-Test-Password-123",
                "role": "superuser",
            },
        )

    assert response.status_code == 422
    mock_db.assert_not_called()


def test_admin_can_change_another_users_role(client):
    authenticate_as(ADMIN, bypass_csrf=True)
    connection = MagicMock()

    original = user_row(10, "test-user", "editor")
    updated = user_row(10, "test-user", "viewer")

    def execute(sql, params=None):
        sql = normalized_sql(sql)

        if selects_active_local_admins(sql):
            return cursor(many=[(1,), (2,)])

        if "FROM users WHERE id = %s FOR UPDATE" in sql:
            return cursor(one=original)

        if "UPDATE users SET role = %s" in sql:
            return cursor(one=updated)

        return cursor()

    connection.execute.side_effect = execute

    with patch("app.routes.users.get_database_connection") as mock_db:
        mock_database(mock_db, connection)
        response = client.patch(
            "/api/users/10",
            json={"role": "viewer"},
        )

    assert response.status_code == 200
    assert response.json()["role"] == "viewer"
    assert response.json()["is_active"] is True
    assert response.json()["auth_provider"] == "local"
    connection.commit.assert_called_once()

    audit_call = next(
        call
        for call in connection.execute.call_args_list
        if "INSERT INTO audit_log" in normalized_sql(call.args[0])
    )
    assert audit_call.args[1][1] == "user_updated"


def test_admin_cannot_change_own_role(client):
    authenticate_as(ADMIN, bypass_csrf=True)
    connection = MagicMock()

    def execute(sql, params=None):
        sql = normalized_sql(sql)

        if selects_active_local_admins(sql):
            return cursor(many=[(1,), (2,)])

        if "FROM users WHERE id = %s FOR UPDATE" in sql:
            return cursor(one=user_row(1, "admin-user", "admin"))

        return cursor()

    connection.execute.side_effect = execute

    with patch("app.routes.users.get_database_connection") as mock_db:
        mock_database(mock_db, connection)
        response = client.patch(
            "/api/users/1",
            json={"role": "viewer"},
        )

    assert response.status_code == 409
    assert "own role" in response.json()["detail"]
    connection.commit.assert_not_called()

    assert not any(
        "UPDATE users" in normalized_sql(call.args[0])
        for call in connection.execute.call_args_list
    )


def test_deactivating_user_revokes_sessions_and_audits(client):
    authenticate_as(ADMIN, bypass_csrf=True)
    connection = MagicMock()

    original = user_row(10, "test-user", "editor", True)
    deactivated = user_row(10, "test-user", "editor", False)

    def execute(sql, params=None):
        sql = normalized_sql(sql)

        if selects_active_local_admins(sql):
            return cursor(many=[(1,), (2,)])

        if "FROM users WHERE id = %s FOR UPDATE" in sql:
            return cursor(one=original)

        if "UPDATE users SET role = %s" in sql:
            return cursor(one=deactivated)

        if "UPDATE user_sessions SET revoked_at = NOW()" in sql:
            return cursor(rowcount=3)

        return cursor()

    connection.execute.side_effect = execute

    with patch("app.routes.users.get_database_connection") as mock_db:
        mock_database(mock_db, connection)
        response = client.patch(
            "/api/users/10",
            json={"is_active": False},
        )

    assert response.status_code == 200
    assert response.json()["is_active"] is False
    connection.commit.assert_called_once()

    session_call = next(
        call
        for call in connection.execute.call_args_list
        if "UPDATE user_sessions" in normalized_sql(call.args[0])
    )
    assert session_call.args[1] == (10,)

    audit_call = next(
        call
        for call in connection.execute.call_args_list
        if "INSERT INTO audit_log" in normalized_sql(call.args[0])
    )
    assert audit_call.args[1][1] == "user_updated"
    assert '"sessions_revoked": 3' in audit_call.args[1][4]


def test_password_reset_hashes_password_revokes_sessions_and_audits(client):
    authenticate_as(ADMIN, bypass_csrf=True)
    connection = MagicMock()

    def execute(sql, params=None):
        sql = normalized_sql(sql)

        if "SELECT id, username, auth_provider FROM users WHERE id = %s FOR UPDATE" in sql:
            return cursor(one=(10, "test-user", "local"))

        if "UPDATE user_sessions SET revoked_at = NOW()" in sql:
            return cursor(rowcount=2)

        return cursor()

    connection.execute.side_effect = execute

    with (
        patch("app.routes.users.get_database_connection") as mock_db,
        patch(
            "app.routes.users.hash_password",
            return_value="new-fake-password-hash",
        ) as hash_mock,
    ):
        mock_database(mock_db, connection)
        response = client.post(
            "/api/users/10/password",
            json={"password": "Replacement-Password-4567"},
        )

    assert response.status_code == 200
    assert response.json() == {
        "id": 10,
        "username": "test-user",
        "password_updated": True,
        "sessions_revoked": 2,
        "current_session_revoked": False,
    }

    hash_mock.assert_called_once_with("Replacement-Password-4567")
    connection.commit.assert_called_once()

    update_call = next(
        call
        for call in connection.execute.call_args_list
        if "UPDATE users SET password_hash = %s" in normalized_sql(
            call.args[0]
        )
    )
    assert update_call.args[1] == ("new-fake-password-hash", 10)

    audit_call = next(
        call
        for call in connection.execute.call_args_list
        if "INSERT INTO audit_log" in normalized_sql(call.args[0])
    )
    assert audit_call.args[1][1] == "user_password_reset"


def test_editor_cannot_reset_password(client):
    authenticate_as(EDITOR, bypass_csrf=True)

    with patch("app.routes.users.get_database_connection") as mock_db:
        response = client.post(
            "/api/users/10/password",
            json={"password": "Replacement-Password-4567"},
        )

    assert response.status_code == 403
    mock_db.assert_not_called()


def test_create_local_user_rejects_ldap_username_case_insensitively(client):
    """A local account cannot take the username of an existing LDAP account."""
    authenticate_as(ADMIN, bypass_csrf=True)
    connection = MagicMock()

    def execute(sql, params=None):
        if "SELECT id FROM users WHERE lower(username) = %s" in normalized_sql(sql):
            return cursor(one=(25,))
        return cursor()

    connection.execute.side_effect = execute

    with (
        patch("app.routes.users.get_database_connection") as mock_db,
        patch("app.routes.users.hash_password", return_value="test-hash"),
    ):
        mock_database(mock_db, connection)
        response = client.post(
            "/api/users",
            json={
                "username": "AD-User",
                "password": "Strong-Test-Password-123",
                "role": "viewer",
            },
        )

    assert response.status_code == 409
    lookup = next(
        call
        for call in connection.execute.call_args_list
        if "lower(username)" in normalized_sql(call.args[0])
    )
    assert lookup.args[1] == ("ad-user",)
    assert not any(
        "INSERT INTO users" in normalized_sql(call.args[0])
        for call in connection.execute.call_args_list
    )


@pytest.mark.parametrize(
    "endpoint,payload",
    [
        ("/api/users", {
            "username": "ad-user",
            "password": "Strong-Test-Password-123",
            "auth_provider": "ldap",
        }),
        ("/api/users/10", {"auth_provider": "local"}),
    ],
)
def test_api_does_not_allow_client_supplied_auth_provider(
    client, endpoint, payload
):
    authenticate_as(ADMIN, bypass_csrf=True)

    with patch("app.routes.users.get_database_connection") as mock_db:
        if endpoint == "/api/users":
            response = client.post(endpoint, json=payload)
        else:
            response = client.patch(endpoint, json=payload)

    assert response.status_code == 422
    mock_db.assert_not_called()


def test_admin_can_change_ldap_users_portal_role(client):
    """LDAP passwords stay in AD; portal roles remain admin-managed."""
    authenticate_as(ADMIN, bypass_csrf=True)
    connection = MagicMock()

    original = user_row(10, "ad-user", "viewer", auth_provider="ldap")
    updated = user_row(10, "ad-user", "admin", auth_provider="ldap")

    def execute(sql, params=None):
        normalized = normalized_sql(sql)
        if selects_active_local_admins(sql):
            return cursor(many=[(1,)])
        if "FROM users WHERE id = %s FOR UPDATE" in normalized:
            return cursor(one=original)
        if "UPDATE users SET role = %s" in normalized:
            return cursor(one=updated)
        return cursor()

    connection.execute.side_effect = execute

    with patch("app.routes.users.get_database_connection") as mock_db:
        mock_database(mock_db, connection)
        response = client.patch("/api/users/10", json={"role": "admin"})

    assert response.status_code == 200
    assert response.json()["role"] == "admin"
    assert response.json()["auth_provider"] == "ldap"
    connection.commit.assert_called_once()

    update_call = next(
        call
        for call in connection.execute.call_args_list
        if "UPDATE users SET role = %s" in normalized_sql(call.args[0])
    )
    assert update_call.args[1] == ("admin", True, 10)


def test_admin_can_deactivate_ldap_user_and_revoke_sessions(client):
    authenticate_as(ADMIN, bypass_csrf=True)
    connection = MagicMock()

    original = user_row(10, "ad-user", "viewer", auth_provider="ldap")
    disabled = user_row(10, "ad-user", "viewer", False, "ldap")

    def execute(sql, params=None):
        normalized = normalized_sql(sql)
        if selects_active_local_admins(sql):
            return cursor(many=[(1,)])
        if "FROM users WHERE id = %s FOR UPDATE" in normalized:
            return cursor(one=original)
        if "UPDATE users SET role = %s" in normalized:
            return cursor(one=disabled)
        if "UPDATE user_sessions SET revoked_at = NOW()" in normalized:
            return cursor(rowcount=4)
        return cursor()

    connection.execute.side_effect = execute

    with patch("app.routes.users.get_database_connection") as mock_db:
        mock_database(mock_db, connection)
        response = client.patch("/api/users/10", json={"is_active": False})

    assert response.status_code == 200
    assert response.json()["is_active"] is False
    assert response.json()["auth_provider"] == "ldap"
    connection.commit.assert_called_once()

    audit_call = next(
        call
        for call in connection.execute.call_args_list
        if "INSERT INTO audit_log" in normalized_sql(call.args[0])
    )
    assert '"sessions_revoked": 4' in audit_call.args[1][4]
    assert '"auth_provider": "ldap"' in audit_call.args[1][4]


@pytest.mark.parametrize(
    "update",
    [{"role": "viewer"}, {"is_active": False}],
)
def test_last_active_local_admin_is_protected_even_with_ldap_admin(
    client, update
):
    """An LDAP admin may operate the UI but cannot remove local recovery access."""
    authenticate_as(LDAP_ADMIN, bypass_csrf=True)
    connection = MagicMock()

    def execute(sql, params=None):
        normalized = normalized_sql(sql)
        if selects_active_local_admins(sql):
            return cursor(many=[(10,)])
        if "FROM users WHERE id = %s FOR UPDATE" in normalized:
            return cursor(one=user_row(10, "break-glass", "admin", True, "local"))
        return cursor()

    connection.execute.side_effect = execute

    with patch("app.routes.users.get_database_connection") as mock_db:
        mock_database(mock_db, connection)
        response = client.patch("/api/users/10", json=update)

    assert response.status_code == 409
    assert "last active local administrator" in response.json()["detail"]
    connection.commit.assert_not_called()
    assert any(
        selects_active_local_admins(call.args[0])
        for call in connection.execute.call_args_list
    )
    assert not any(
        "UPDATE users SET role = %s" in normalized_sql(call.args[0])
        for call in connection.execute.call_args_list
    )


def test_one_of_two_local_admins_may_be_demoted(client):
    authenticate_as(ADMIN, bypass_csrf=True)
    connection = MagicMock()

    original = user_row(10, "other-admin", "admin", True, "local")
    updated = user_row(10, "other-admin", "viewer", True, "local")

    def execute(sql, params=None):
        normalized = normalized_sql(sql)
        if selects_active_local_admins(sql):
            return cursor(many=[(1,), (10,)])
        if "FROM users WHERE id = %s FOR UPDATE" in normalized:
            return cursor(one=original)
        if "UPDATE users SET role = %s" in normalized:
            return cursor(one=updated)
        return cursor()

    connection.execute.side_effect = execute

    with patch("app.routes.users.get_database_connection") as mock_db:
        mock_database(mock_db, connection)
        response = client.patch("/api/users/10", json={"role": "viewer"})

    assert response.status_code == 200
    assert response.json()["role"] == "viewer"
    assert response.json()["auth_provider"] == "local"
    connection.commit.assert_called_once()


def test_ldap_password_reset_is_rejected_without_account_changes(client):
    authenticate_as(ADMIN, bypass_csrf=True)
    connection = MagicMock()

    def execute(sql, params=None):
        if (
            "SELECT id, username, auth_provider FROM users"
            in normalized_sql(sql)
        ):
            return cursor(one=(10, "ad-user", "ldap"))
        return cursor()

    connection.execute.side_effect = execute

    with (
        patch("app.routes.users.get_database_connection") as mock_db,
        patch("app.routes.users.hash_password", return_value="test-hash"),
    ):
        mock_database(mock_db, connection)
        response = client.post(
            "/api/users/10/password",
            json={"password": "Replacement-Password-4567"},
        )

    assert response.status_code == 409
    assert "Only local account passwords" in response.json()["detail"]
    connection.commit.assert_not_called()
    assert not any(
        "UPDATE users" in normalized_sql(call.args[0])
        or "UPDATE user_sessions" in normalized_sql(call.args[0])
        or "INSERT INTO audit_log" in normalized_sql(call.args[0])
        for call in connection.execute.call_args_list
    )
