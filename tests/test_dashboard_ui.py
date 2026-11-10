from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from app.auth.dependencies import AuthenticatedUser
from app.main import app


ADMIN = AuthenticatedUser(id=1, username="admin-ui-test", role="admin")
EDITOR = AuthenticatedUser(id=3, username="editor-ui-test", role="editor")
VIEWER = AuthenticatedUser(id=2, username="viewer-ui-test", role="viewer")


def render_alerts_page(user=ADMIN):
    app.dependency_overrides.clear()
    client = TestClient(app)
    client.cookies.set("alert_portal_session", "session-for-dashboard-ui-test")
    client.cookies.set("alert_portal_csrf", "csrf-for-dashboard-ui-test")
    connection = MagicMock()
    connection.execute.return_value.fetchone.return_value = (1,)
    try:
        with (
            patch("app.routes.dashboard.get_user_from_session_token", return_value=user),
            patch("app.routes.dashboard.get_database_connection") as mock_db,
        ):
            mock_db.return_value.__enter__.return_value = connection
            return client.get("/alerts")
    finally:
        client.close()
        app.dependency_overrides.clear()


def test_dashboard_has_structured_workspace_and_rule_filters():
    response = render_alerts_page()
    assert response.status_code == 200
    for marker in (
        "Monitoring workspace",
        'class="metrics"',
        'id="metric-total"',
        'id="metric-critical"',
        'id="metric-warning"',
        'id="metric-info"',
        'id="rule-search"',
        'id="severity-filter"',
        'id="custom-labels"',
        'id="label-count"',
        'id="label-error"',
        'id="add-label-row"',
        "LABEL_NAME_MAX = 63",
        "LABEL_VALUE_MAX = 256",
        "status-success",
        "empty-state",
        "@media (max-width: 780px)",
    ):
        assert marker in response.text


def test_dashboard_shows_user_management_only_for_admin():
    admin_response = render_alerts_page(ADMIN)
    viewer_response = render_alerts_page(VIEWER)
    assert admin_response.status_code == 200
    assert 'href="/users">User management</a>' in admin_response.text
    assert viewer_response.status_code == 200
    assert 'href="/users">User management</a>' not in viewer_response.text


def test_dashboard_uses_api_permissions_per_rule():
    response = render_alerts_page(EDITOR)
    assert response.status_code == 200
    assert "const canEdit = true;" in response.text
    assert "rule.can_edit === true" in response.text
    assert "rule.can_delete === true" in response.text
    assert "if (mayEditRule || mayDeleteRule)" in response.text
    assert 'appendMeta(meta, "Access", "View only")' in response.text
    assert "only the rules they own" in response.text


def test_viewer_has_no_creation_form_or_mutation_controls():
    response = render_alerts_page(VIEWER)
    assert response.status_code == 200
    assert "const canEdit = false;" in response.text
    assert 'id="editor-panel" hidden' in response.text
    assert 'class="heading-actions" hidden' in response.text


def test_dashboard_preserves_security_headers():
    response = render_alerts_page()
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"

def test_dashboard_identity_pill_shows_username_only():
    response = render_alerts_page(ADMIN)
    assert response.status_code == 200
    assert (
        '<span class="user-pill"><span class="user-dot" aria-hidden="true"></span> admin-ui-test</span>'
        in response.text
    )
    assert "admin-ui-test · admin" not in response.text
