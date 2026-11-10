from unittest.mock import MagicMock, patch

import psycopg
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.auth.dependencies import AuthenticatedUser
from app.main import app


ADMIN = AuthenticatedUser(id=1, username="admin-user", role="admin")
EDITOR = AuthenticatedUser(id=2, username="editor-user", role="editor")
CSRF_TOKEN = "test-csrf-token-for-user-dashboard-123456"


@pytest.fixture
def client():
    app.dependency_overrides.clear()
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def set_auth_cookies(client):
    client.cookies.set("alert_portal_session", "test-session-token")
    client.cookies.set("alert_portal_csrf", CSRF_TOKEN)


def mock_valid_session(mock_db):
    connection = MagicMock()
    connection.execute.return_value.fetchone.return_value = (1,)
    mock_db.return_value.__enter__.return_value = connection
    return connection


def test_unauthenticated_users_are_redirected(client):
    response = client.get("/users", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    assert response.headers["cache-control"] == "no-store"


def test_admin_can_open_user_management_page(client):
    set_auth_cookies(client)

    with (
        patch(
            "app.routes.user_dashboard.get_user_from_session_token",
            return_value=ADMIN,
        ),
        patch(
            "app.routes.user_dashboard.get_database_connection"
        ) as mock_db,
    ):
        mock_valid_session(mock_db)
        response = client.get("/users")

    assert response.status_code == 200
    assert "admin-user" in response.text
    assert 'id="create-user-form"' in response.text
    assert 'id="users-list"' in response.text
    assert "const currentUserId = 1;" in response.text
    assert "Create account" in response.text
    assert "Reset password" in response.text
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"


def test_user_management_ui_supports_ldap_accounts(client):
    set_auth_cookies(client)

    with (
        patch(
            "app.routes.user_dashboard.get_user_from_session_token",
            return_value=ADMIN,
        ),
        patch(
            "app.routes.user_dashboard.get_database_connection"
        ) as mock_db,
    ):
        mock_valid_session(mock_db)
        response = client.get("/users")

    assert response.status_code == 200
    assert ">All accounts</h2>" in response.text
    assert 'const isLdap = user.auth_provider === "ldap";' in response.text
    assert 'isLdap ? "Active Directory" : "Local"' in response.text
    assert "if (isLdap) {" in response.text
    assert "This account signs in with Active Directory." in response.text
    assert 'user.auth_provider === "ldap" ? "active directory" : "local"' in response.text


def test_non_admin_is_denied_user_management_page(client):
    set_auth_cookies(client)

    with (
        patch(
            "app.routes.user_dashboard.get_user_from_session_token",
            return_value=EDITOR,
        ),
        patch(
            "app.routes.user_dashboard.get_database_connection"
        ) as mock_db,
    ):
        response = client.get("/users")

    assert response.status_code == 403
    assert "restricted to administrators" in response.text
    mock_db.assert_not_called()


def test_invalid_session_redirects_to_login(client):
    set_auth_cookies(client)

    with patch(
        "app.routes.user_dashboard.get_user_from_session_token",
        side_effect=HTTPException(status_code=401, detail="Invalid session"),
    ):
        response = client.get("/users", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_database_outage_returns_503(client):
    set_auth_cookies(client)

    with (
        patch(
            "app.routes.user_dashboard.get_user_from_session_token",
            return_value=ADMIN,
        ),
        patch(
            "app.routes.user_dashboard.get_database_connection",
            side_effect=psycopg.OperationalError("database unavailable"),
        ),
    ):
        response = client.get("/users")

    assert response.status_code == 503
    assert response.json() == {
        "detail": "Authentication service temporarily unavailable."
    }


def test_dashboard_requires_session_bound_csrf_cookie(client):
    set_auth_cookies(client)

    connection = MagicMock()
    connection.execute.return_value.fetchone.return_value = None

    with (
        patch(
            "app.routes.user_dashboard.get_user_from_session_token",
            return_value=ADMIN,
        ),
        patch(
            "app.routes.user_dashboard.get_database_connection"
        ) as mock_db,
    ):
        mock_db.return_value.__enter__.return_value = connection
        response = client.get("/users", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"
