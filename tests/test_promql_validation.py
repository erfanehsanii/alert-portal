from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.auth.dependencies import AuthenticatedUser, get_current_user
from app.main import app
from app.routes.rules import require_valid_csrf
from app.services.promql_validation import (
    PrometheusValidationUnavailable,
    validate_promql_expression,
)


ADMIN = AuthenticatedUser(id=1, username="promql-admin", role="admin")
EDITOR = AuthenticatedUser(id=2, username="promql-editor", role="editor")
VIEWER = AuthenticatedUser(id=3, username="promql-viewer", role="viewer")


@pytest.fixture
def client():
    app.dependency_overrides.clear()
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def authenticate_as(user):
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[require_valid_csrf] = lambda: user


def test_valid_expression_with_series_is_reported_as_valid():
    payload = {
        "status": "success",
        "data": {"resultType": "vector", "result": [{"metric": {"job": "demo"}, "value": [1, "1"]}]},
    }
    with patch(
        "app.services.promql_validation._send_query",
        return_value=(200, payload),
    ):
        result = validate_promql_expression("up == 0")
    assert result["valid"] is True
    assert result["kind"] == "valid"
    assert result["result_count"] == 1
    assert result["has_results"] is True


def test_valid_expression_with_no_series_is_still_valid():
    payload = {"status": "success", "data": {"resultType": "vector", "result": []}}
    with patch("app.services.promql_validation._send_query", return_value=(200, payload)):
        result = validate_promql_expression("up{job=\"not-present\"} == 0")
    assert result["valid"] is True
    assert result["result_count"] == 0
    assert result["has_results"] is False


def test_prometheus_bad_data_error_is_reported_as_invalid_promql():
    payload = {
        "status": "error",
        "errorType": "bad_data",
        "error": "parse error: unexpected character in expression",
    }
    with patch("app.services.promql_validation._send_query", return_value=(400, payload)):
        result = validate_promql_expression("up === 0")
    assert result["valid"] is False
    assert result["kind"] == "invalid"
    assert "parse error" in result["message"]


def test_scalar_expression_is_not_accepted_as_an_alert_expression():
    payload = {"status": "success", "data": {"resultType": "scalar", "result": [1, "1"]}}
    with patch("app.services.promql_validation._send_query", return_value=(200, payload)):
        result = validate_promql_expression("1")
    assert result["valid"] is False
    assert result["kind"] == "invalid"
    assert "instant vector" in result["message"]


def test_query_timeout_or_connectivity_failure_is_not_marked_valid():
    with patch(
        "app.services.promql_validation._send_query",
        side_effect=PrometheusValidationUnavailable("query timed out"),
    ):
        with pytest.raises(PrometheusValidationUnavailable):
            validate_promql_expression("up == 0")


def test_validate_expression_endpoint_requires_csrf(client):
    app.dependency_overrides[get_current_user] = lambda: ADMIN
    with patch("app.routes.rules.validate_promql_expression") as validate:
        response = client.post("/api/rules/validate-expression", json={"expression": "up == 0"})
    assert response.status_code == 403
    validate.assert_not_called()


def test_viewer_cannot_validate_expression(client):
    authenticate_as(VIEWER)
    with patch("app.routes.rules.validate_promql_expression") as validate:
        response = client.post("/api/rules/validate-expression", json={"expression": "up == 0"})
    assert response.status_code == 403
    validate.assert_not_called()


@pytest.mark.parametrize("user", [ADMIN, EDITOR])
def test_editor_or_admin_can_validate_without_saving_a_rule(client, user):
    authenticate_as(user)
    result = {
        "valid": True,
        "kind": "valid",
        "message": "PromQL expression is valid.",
        "result_type": "vector",
        "result_count": 0,
        "has_results": False,
    }
    with patch("app.routes.rules.validate_promql_expression", return_value=result) as validate:
        response = client.post(
            "/api/rules/validate-expression",
            json={"expression": "  up == 0  "},
        )
    assert response.status_code == 200
    assert response.json() == result
    validate.assert_called_once_with("up == 0")


def test_endpoint_returns_503_when_prometheus_is_unavailable(client):
    authenticate_as(ADMIN)
    with patch(
        "app.routes.rules.validate_promql_expression",
        side_effect=PrometheusValidationUnavailable("internal detail"),
    ) as validate:
        response = client.post(
            "/api/rules/validate-expression",
            json={"expression": "up == 0"},
        )
    assert response.status_code == 503
    assert "Prometheus is unavailable" in response.json()["detail"]
    assert "internal detail" not in response.text
    validate.assert_called_once_with("up == 0")


def test_validate_expression_endpoint_rejects_oversized_input(client):
    authenticate_as(ADMIN)
    with patch("app.routes.rules.validate_promql_expression") as validate:
        response = client.post(
            "/api/rules/validate-expression",
            json={"expression": "x" * 4097},
        )
    assert response.status_code == 422
    validate.assert_not_called()


def test_dashboard_includes_the_promql_validation_controls():
    user = AuthenticatedUser(id=20, username="promql-dashboard", role="admin")
    client = TestClient(app)
    client.cookies.set("alert_portal_session", "session-for-promql-dashboard-test")
    client.cookies.set("alert_portal_csrf", "csrf-for-promql-dashboard-test")
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
    assert response.status_code == 200
    for marker in (
        'id="validate-expression-button"',
        'id="expression-validation-status"',
        "Validate PromQL",
        "/api/rules/validate-expression",
        "query currently returns no matching series",
        "PromQL validation unavailable",
    ):
        assert marker in response.text
