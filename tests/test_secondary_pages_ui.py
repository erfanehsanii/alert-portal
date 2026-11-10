from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.auth.dependencies import AuthenticatedUser
from app.main import app


ADMIN = AuthenticatedUser(id=1, username="admin-ui-test", role="admin")
EDITOR = AuthenticatedUser(id=2, username="editor-ui-test", role="editor")
VIEWER = AuthenticatedUser(id=3, username="viewer-ui-test", role="viewer")
SESSION = "ui-test-session-token"
CSRF = "ui-test-csrf-token-with-at-least-32-characters"


@pytest.fixture
def client():
    app.dependency_overrides.clear()
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def set_cookies(client):
    client.cookies.set("alert_portal_session", SESSION)
    client.cookies.set("alert_portal_csrf", CSRF)


def mock_valid_session(mock_db):
    connection = MagicMock()
    connection.execute.return_value.fetchone.return_value = (1,)
    mock_db.return_value.__enter__.return_value = connection
    return connection


def test_login_page_uses_consistent_styled_form(client):
    with patch("app.routes.auth.get_database_connection") as mock_db:
        mock_db.return_value.__enter__.return_value = MagicMock()
        response = client.get("/login")

    assert response.status_code == 200
    assert 'class="auth-card"' in response.text
    assert 'id="username" name="username"' in response.text
    assert 'id="password" name="password" type="password"' in response.text
    assert 'name="csrf_token"' in response.text
    assert 'action="/login"' in response.text
    assert response.headers["cache-control"] == "no-store"


def test_homepage_has_workspace_cards_and_username_only_identity(client):
    set_cookies(client)
    with (
        patch("app.main.get_user_from_session_token", return_value=ADMIN),
        patch("app.main.get_database_connection") as mock_db,
    ):
        mock_valid_session(mock_db)
        response = client.get("/")

    assert response.status_code == 200
    assert "Your monitoring workspace" in response.text
    assert 'href="/alerts">Open alert rules' in response.text
    assert 'href="/users">Manage users' in response.text
    assert '<span class="user-pill"><span class="user-dot" aria-hidden="true"></span>admin-ui-test</span>' in response.text
    assert "admin-ui-test · admin" not in response.text
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-frame-options"] == "DENY"


def test_homepage_does_not_expose_user_management_to_viewer(client):
    set_cookies(client)
    with (
        patch("app.main.get_user_from_session_token", return_value=VIEWER),
        patch("app.main.get_database_connection") as mock_db,
    ):
        mock_valid_session(mock_db)
        response = client.get("/")

    assert response.status_code == 200
    assert 'href="/users"' not in response.text
    assert "User management" not in response.text
    assert "Alert rules" in response.text


def test_user_management_has_search_summary_and_consistent_navigation(client):
    set_cookies(client)
    with (
        patch("app.routes.user_dashboard.get_user_from_session_token", return_value=ADMIN),
        patch("app.routes.user_dashboard.get_database_connection") as mock_db,
    ):
        mock_valid_session(mock_db)
        response = client.get("/users")

    assert response.status_code == 200
    for marker in (
        "User management",
        "Monitoring workspace",
        'id="create-user-form"',
        'id="new-username"',
        'id="new-password"',
        'id="new-role"',
        'id="user-search"',
        'id="metric-total-users"',
        'id="metric-active-users"',
        'id="metric-inactive-users"',
        'id="users-list"',
        'id="refresh-users"',
        'href="/alerts"',
        'class="user-pill"',
        'aria-current="page"',
    ):
        assert marker in response.text
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"


def test_user_management_remains_admin_only(client):
    set_cookies(client)
    with patch(
        "app.routes.user_dashboard.get_user_from_session_token",
        return_value=EDITOR,
    ):
        response = client.get("/users")

    assert response.status_code == 403
    assert "User management is restricted to administrators." in response.text
    assert 'href="/"' in response.text


def test_missing_homepage_session_still_redirects(client):
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"
