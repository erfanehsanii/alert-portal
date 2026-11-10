import re
from unittest.mock import MagicMock, patch

import psycopg
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.auth.dependencies import AuthenticatedUser
from app.main import app


ADMIN = AuthenticatedUser(
    id=1,
    username="admin-user",
    role="admin",
)

VIEWER = AuthenticatedUser(
    id=3,
    username="viewer-user",
    role="viewer",
)

SESSION_TOKEN = "test-session-token-for-dashboard"
CSRF_TOKEN = "test-csrf-token-for-dashboard-123456789"


@pytest.fixture
def client():
    app.dependency_overrides.clear()

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


def set_auth_cookies(client):
    """Set the cookies on the test client."""
    client.cookies.set("alert_portal_session", SESSION_TOKEN)
    client.cookies.set("alert_portal_csrf", CSRF_TOKEN)


def mock_valid_session_database(mock_db):
    """Simulate a session whose CSRF token is bound to its user."""
    fake_connection = MagicMock()
    fake_connection.execute.return_value.fetchone.return_value = (1,)
    mock_db.return_value.__enter__.return_value = fake_connection
    return fake_connection


def test_unauthenticated_dashboard_redirects_to_login(client):
    response = client.get("/alerts", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    assert response.headers["cache-control"] == "no-store"


def test_dashboard_renders_for_admin(client):
    set_auth_cookies(client)

    with (
        patch(
            "app.routes.dashboard.get_user_from_session_token",
            return_value=ADMIN,
        ),
        patch(
            "app.routes.dashboard.get_database_connection"
        ) as mock_db,
    ):
        mock_valid_session_database(mock_db)
        response = client.get("/alerts")

    assert response.status_code == 200
    assert "Alert Portal" in response.text
    assert "admin-user" in response.text
    assert "admin" in response.text
    assert 'id="editor-panel"' in response.text
    assert "const canEdit = true;" in response.text
    assert f'value="{CSRF_TOKEN}"' in response.text
    assert "const csrfToken =" in response.text
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"


def test_dashboard_is_read_only_for_viewer(client):
    set_auth_cookies(client)

    with (
        patch(
            "app.routes.dashboard.get_user_from_session_token",
            return_value=VIEWER,
        ),
        patch(
            "app.routes.dashboard.get_database_connection"
        ) as mock_db,
    ):
        mock_valid_session_database(mock_db)
        response = client.get("/alerts")

    assert response.status_code == 200
    assert "viewer-user" in response.text
    assert "const canEdit = false;" in response.text

    # Match the editor section independently of attribute order or CSS classes.
    editor_match = re.search(
        r"<section\b[^>]*\bid=\"editor-panel\"[^>]*>",
        response.text,
    )
    assert editor_match is not None, "Editor section must be present in the page."

    # Verify that the actual HTML element is hidden for viewers.
    assert re.search(
        r"\shidden(?:\s|=|>)",
        editor_match.group(0),
    ) is not None, "The editor section must have the hidden attribute for viewers."


def test_dashboard_redirects_when_session_is_invalid(client):
    set_auth_cookies(client)

    with patch(
        "app.routes.dashboard.get_user_from_session_token",
        side_effect=HTTPException(status_code=401, detail="Invalid session"),
    ):
        response = client.get("/alerts", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    assert any(
        cookie.startswith("alert_portal_session=")
        and "max-age=0" in cookie.lower()
        for cookie in response.headers.get_list("set-cookie")
    )


def test_dashboard_returns_503_when_database_is_unavailable(client):
    set_auth_cookies(client)

    with (
        patch(
            "app.routes.dashboard.get_user_from_session_token",
            return_value=ADMIN,
        ),
        patch(
            "app.routes.dashboard.get_database_connection",
            side_effect=psycopg.OperationalError("database unavailable"),
        ),
    ):
        response = client.get("/alerts")

    assert response.status_code == 503
    assert response.json() == {
        "detail": "Authentication service temporarily unavailable."
    }
    assert response.headers["cache-control"] == "no-store"


def test_dashboard_redirects_when_session_csrf_binding_is_invalid(client):
    set_auth_cookies(client)

    fake_connection = MagicMock()
    fake_connection.execute.return_value.fetchone.return_value = None

    with (
        patch(
            "app.routes.dashboard.get_user_from_session_token",
            return_value=ADMIN,
        ),
        patch(
            "app.routes.dashboard.get_database_connection"
        ) as mock_db,
    ):
        mock_db.return_value.__enter__.return_value = fake_connection
        response = client.get("/alerts", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"
