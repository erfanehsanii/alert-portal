from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.auth.dependencies import AuthenticatedUser, get_current_user
from app.main import app
from app.routes.rules import require_valid_csrf
from app.services.promql_templates import PrometheusTemplateOptionsUnavailable


ADMIN = AuthenticatedUser(id=21, username="template-admin", role="admin")
EDITOR = AuthenticatedUser(id=22, username="template-editor", role="editor")
VIEWER = AuthenticatedUser(id=23, username="template-viewer", role="viewer")


@pytest.fixture
def client():
    app.dependency_overrides.clear()
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def authenticate_as(user):
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[require_valid_csrf] = lambda: user


def sample_options():
    return {
        "targets": [
            {"job": "node-exporter", "instance": "192.0.2.10:9100"},
            {"job": "k8s-cluster-haproxy", "instance": "192.0.2.11:9100"},
        ],
        "filesystems": [
            {
                "job": "node-exporter", "instance": "192.0.2.10:9100",
                "mountpoint": "/", "device": "/dev/sda1", "fstype": "ext4",
            }
        ],
        "target_count": 2,
        "filesystem_count": 1,
        "result_limit": 1000,
    }


@pytest.mark.parametrize("user", [ADMIN, EDITOR])
def test_admin_and_editor_can_read_live_template_options(client, user):
    authenticate_as(user)
    expected = sample_options()
    with patch("app.routes.rules.get_promql_template_options", return_value=expected) as get_options:
        response = client.get("/api/rules/template-options")
    assert response.status_code == 200
    assert response.json() == expected
    get_options.assert_called_once_with()


def test_viewer_cannot_read_template_options(client):
    authenticate_as(VIEWER)
    with patch("app.routes.rules.get_promql_template_options") as get_options:
        response = client.get("/api/rules/template-options")
    assert response.status_code == 403
    get_options.assert_not_called()


def test_template_options_returns_safe_503_when_prometheus_unavailable(client):
    authenticate_as(ADMIN)
    with patch(
        "app.routes.rules.get_promql_template_options",
        side_effect=PrometheusTemplateOptionsUnavailable("sensitive internal error"),
    ) as get_options:
        response = client.get("/api/rules/template-options")
    assert response.status_code == 503
    assert "temporarily unavailable" in response.json()["detail"]
    assert "sensitive internal error" not in response.text
    get_options.assert_called_once_with()


def test_dashboard_renders_optional_promql_templates():
    user = ADMIN
    client = TestClient(app)
    client.cookies.set("alert_portal_session", "session-for-template-dashboard-test")
    client.cookies.set("alert_portal_csrf", "csrf-for-template-dashboard-test")
    connection = MagicMock()
    connection.execute.return_value.fetchone.return_value = (1,)
    try:
        with (
            patch("app.routes.dashboard.get_user_from_session_token", return_value=user),
            patch("app.routes.dashboard.get_database_connection") as mock_db,
        ):
            mock_db.return_value.__enter__.return_value = connection
            response = client.get("/alerts")
    finally:
        client.close()
        app.dependency_overrides.clear()
    assert response.status_code == 200
    for marker in (
        'id="promql-template"',
        'value="cpu">CPU usage above threshold',
        'value="memory">Memory usage above threshold',
        'value="disk">Disk usage above threshold',
        'id="template-job"',
        'id="template-instance"',
        'id="template-mountpoint"',
        'id="template-device"',
        'id="apply-promql-template"',
        '/api/rules/template-options',
        'Generate query',
        'Validate PromQL',
    ):
        assert marker in response.text