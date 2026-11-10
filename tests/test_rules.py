from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.auth.dependencies import AuthenticatedUser, get_current_user
from app.main import app
from app.routes.rules import require_valid_csrf
from app.services.prometheus_rules import (
    OWNER_USER_ID_ANNOTATION,
    RulePermissionError,
    RuleValidationError,
    _validated_rule_spec,
)


ADMIN = AuthenticatedUser(id=1, username="admin-user", role="admin")
EDITOR = AuthenticatedUser(id=2, username="editor-user", role="editor")
VIEWER = AuthenticatedUser(id=3, username="viewer-user", role="viewer")

CSRF_TOKEN = "test-csrf-token-for-alert-rules-123456789"


@pytest.fixture
def client():
    app.dependency_overrides.clear()

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


def sample_rule(owner_user_id=EDITOR.id, created_by="editor-user"):
    return {
        "apiVersion": "monitoring.coreos.com/v1",
        "kind": "PrometheusRule",
        "metadata": {
            "name": "alert-portal-test123456",
            "namespace": "alert-portal-rules",
            "creationTimestamp": "2026-10-23T12:00:00Z",
            "annotations": (
                {OWNER_USER_ID_ANNOTATION: str(owner_user_id)}
                if owner_user_id is not None else {}
            ),
            "labels": {
                "release": "prometheus-stack",
                "app.kubernetes.io/managed-by": "alert-portal",
            },
        },
        "spec": {
            "groups": [
                {
                    "name": "portal-alerts",
                    "rules": [
                        {
                            "alert": "TestAlert",
                            "expr": 'up{job="node-exporter"} == 0',
                            "for": "5m",
                            "labels": {"severity": "warning", "created_by": created_by},
                            "annotations": {
                                "summary": "A test target is down",
                                "description": "The target has been down for 5 minutes.",
                            },
                        }
                    ],
                }
            ]
        },
    }


def sample_payload():
    return {
        "alert_name": "TestAlert",
        "expression": 'up{job="node-exporter"} == 0',
        "duration": "5m",
        "severity": "warning",
        "summary": "A test target is down",
        "description": "The target has been down for 5 minutes.",
    }


def authenticate_as(user):
    app.dependency_overrides[get_current_user] = lambda: user


def bypass_csrf_for_authorization_test(user):
    # Authorization tests isolate role checks.
    # CSRF behavior is tested separately below.
    app.dependency_overrides[require_valid_csrf] = lambda: user


def test_list_rules_returns_portal_managed_rules(client):
    authenticate_as(ADMIN)

    with patch(
        "app.routes.rules.list_portal_rules",
        return_value=[sample_rule()],
    ):
        response = client.get("/api/rules")

    assert response.status_code == 200
    body = response.json()

    assert len(body["items"]) == 1
    assert body["items"][0]["name"] == "alert-portal-test123456"
    assert body["items"][0]["alert_name"] == "TestAlert"
    assert body["items"][0]["expression"] == (
        'up{job="node-exporter"} == 0'
    )
    assert body["items"][0]["duration"] == "5m"
    assert body["items"][0]["severity"] == "warning"
    assert body["items"][0]["can_edit"] is True
    assert body["items"][0]["can_delete"] is True


@pytest.mark.parametrize(
    ("user", "owner_user_id", "expected"),
    [
        (ADMIN, None, True),
        (ADMIN, 99, True),
        (EDITOR, EDITOR.id, True),
        (EDITOR, ADMIN.id, False),
        (EDITOR, None, False),
        (VIEWER, VIEWER.id, False),
        (VIEWER, EDITOR.id, False),
    ],
)
def test_list_rule_permissions_follow_immutable_user_id(
    client, user, owner_user_id, expected
):
    authenticate_as(user)
    # The visible username must not determine ownership.
    rule = sample_rule(owner_user_id=owner_user_id, created_by=user.username)
    with patch("app.routes.rules.list_portal_rules", return_value=[rule]):
        response = client.get("/api/rules")
    assert response.status_code == 200
    item = response.json()["items"][0]
    assert item["created_by"] == user.username
    assert item["can_edit"] is expected
    assert item["can_delete"] is expected


def test_viewer_can_read_rule_details_without_permission_to_modify(client):
    authenticate_as(VIEWER)
    with patch("app.routes.rules.get_portal_rule", return_value=sample_rule()):
        response = client.get("/api/rules/alert-portal-test123456")
    assert response.status_code == 200
    assert response.json()["can_edit"] is False
    assert response.json()["can_delete"] is False


def test_create_rule_requires_a_valid_csrf_token(client):
    authenticate_as(ADMIN)

    with patch("app.routes.rules.create_portal_rule") as create_rule:
        response = client.post(
            "/api/rules",
            json=sample_payload(),
            cookies={
                "alert_portal_session": "test-session",
                "alert_portal_csrf": CSRF_TOKEN,
            },
        )

    assert response.status_code == 403
    assert create_rule.called is False


def test_create_rule_requires_csrf_token_bound_to_session(client):
    authenticate_as(ADMIN)

    fake_connection = MagicMock()
    fake_connection.execute.return_value.fetchone.return_value = (1,)

    with (
        patch(
            "app.routes.rules.get_database_connection"
        ) as mock_db,
        patch(
            "app.routes.rules.create_portal_rule",
            return_value=sample_rule(),
        ) as create_rule,
        patch(
            "app.routes.rules.record_audit_event"
        ) as audit,
    ):
        mock_db.return_value.__enter__.return_value = fake_connection

        response = client.post(
            "/api/rules",
            json=sample_payload(),
            cookies={
                "alert_portal_session": "test-session",
                "alert_portal_csrf": CSRF_TOKEN,
            },
            headers={"X-CSRF-Token": CSRF_TOKEN},
        )

    assert response.status_code == 201
    assert response.json()["alert_name"] == "TestAlert"
    create_rule.assert_called_once()
    assert create_rule.call_args.kwargs["owner_user_id"] == ADMIN.id
    assert create_rule.call_args.kwargs["created_by"] == ADMIN.username
    audit.assert_called_once()

    assert audit.call_args.kwargs["action"] == "alert_rule_created"
    assert audit.call_args.kwargs["actor_user_id"] == ADMIN.id


def test_viewer_cannot_create_rules(client):
    authenticate_as(VIEWER)
    bypass_csrf_for_authorization_test(VIEWER)

    with patch("app.routes.rules.create_portal_rule") as create_rule:
        response = client.post(
            "/api/rules",
            json=sample_payload(),
        )

    assert response.status_code == 403
    create_rule.assert_not_called()


@pytest.mark.parametrize("method", ["put", "delete"])
def test_viewer_cannot_edit_or_delete_even_owned_rule(client, method):
    authenticate_as(VIEWER)
    bypass_csrf_for_authorization_test(VIEWER)
    with (
        patch("app.routes.rules.update_portal_rule") as update_rule,
        patch("app.routes.rules.delete_portal_rule") as delete_rule,
    ):
        response = getattr(client, method)(
            "/api/rules/alert-portal-test123456",
            **({"json": sample_payload()} if method == "put" else {}),
        )
    assert response.status_code == 403
    update_rule.assert_not_called()
    delete_rule.assert_not_called()



def test_create_rule_rejects_destination_owned_by_another_user(client):
    from app.services.mattermost_destinations import DestinationNotFoundError

    authenticate_as(EDITOR)
    bypass_csrf_for_authorization_test(EDITOR)
    payload = sample_payload()
    payload["notification_destination_id"] = "13c10bc8-f32d-4d32-8dcf-634798befb4a"

    with (
        patch(
            "app.routes.rules.get_user_destination",
            side_effect=DestinationNotFoundError("not owned"),
        ),
        patch("app.routes.rules.create_portal_rule") as create_rule,
    ):
        response = client.post("/api/rules", json=payload)

    assert response.status_code == 403
    create_rule.assert_not_called()

def test_editor_can_update_a_rule(client):
    authenticate_as(EDITOR)
    bypass_csrf_for_authorization_test(EDITOR)

    with (
        patch(
            "app.routes.rules.update_portal_rule",
            return_value=sample_rule(),
        ) as update_rule,
        patch(
            "app.routes.rules.record_audit_event"
        ) as audit,
    ):
        response = client.put(
            "/api/rules/alert-portal-test123456",
            json=sample_payload(),
        )

    assert response.status_code == 200
    assert response.json()["alert_name"] == "TestAlert"
    update_rule.assert_called_once()
    assert update_rule.call_args.kwargs["actor_user_id"] == EDITOR.id
    assert update_rule.call_args.kwargs["actor_role"] == "editor"
    audit.assert_called_once()

    assert audit.call_args.kwargs["action"] == "alert_rule_updated"
    assert audit.call_args.kwargs["actor_user_id"] == EDITOR.id


def test_editor_can_delete_a_portal_rule(client):
    authenticate_as(EDITOR)
    bypass_csrf_for_authorization_test(EDITOR)

    with (
        patch(
            "app.routes.rules.get_portal_rule",
            return_value=sample_rule(),
        ) as get_rule,
        patch(
            "app.routes.rules.delete_portal_rule",
            return_value={"status": "Success"},
        ) as delete_rule,
        patch(
            "app.routes.rules.record_audit_event"
        ) as audit,
    ):
        response = client.delete(
            "/api/rules/alert-portal-test123456",
        )

    assert response.status_code == 200
    assert response.json() == {
        "deleted": True,
        "name": "alert-portal-test123456",
    }

    get_rule.assert_called_once_with("alert-portal-test123456")
    delete_rule.assert_called_once_with(
        "alert-portal-test123456", actor_user_id=EDITOR.id, actor_role="editor"
    )
    audit.assert_called_once()

    assert audit.call_args.kwargs["action"] == "alert_rule_deleted"
    assert audit.call_args.kwargs["actor_user_id"] == EDITOR.id


@pytest.mark.parametrize("method", ["put", "delete"])
def test_api_maps_rule_ownership_denial_to_403_without_audit(client, method):
    authenticate_as(EDITOR)
    bypass_csrf_for_authorization_test(EDITOR)

    with (
        patch("app.routes.rules.get_portal_rule", return_value=sample_rule()),
        patch("app.routes.rules.update_portal_rule", side_effect=RulePermissionError("Forbidden")),
        patch("app.routes.rules.delete_portal_rule", side_effect=RulePermissionError("Forbidden")),
        patch("app.routes.rules.record_audit_event") as audit,
    ):
        response = getattr(client, method)(
            "/api/rules/alert-portal-test123456",
            **({"json": sample_payload()} if method == "put" else {}),
        )
    assert response.status_code == 403
    assert response.json()["detail"] == "Forbidden"
    audit.assert_not_called()


@pytest.mark.parametrize("duration", ["0s", "5m", "10s", "1h30m"])
def test_valid_rule_durations_are_accepted(duration):
    spec = _validated_rule_spec(
        "TestAlert",
        "up == 0",
        duration,
        "warning",
        "Test alert",
        "",
    )

    assert spec["groups"][0]["rules"][0]["alert"] == "TestAlert"


def test_invalid_duration_is_rejected():
    with pytest.raises(RuleValidationError):
        _validated_rule_spec(
            "TestAlert",
            "up == 0",
            "5minutes",
            "warning",
            "Test alert",
            "",
        )


def test_invalid_severity_is_rejected():
    with pytest.raises(RuleValidationError):
        _validated_rule_spec(
            "TestAlert",
            "up == 0",
            "5m",
            "emergency",
            "Test alert",
            "",
        )


def test_invalid_alert_name_is_rejected():
    with pytest.raises(RuleValidationError):
        _validated_rule_spec(
            "Test Alert!",
            "up == 0",
            "5m",
            "warning",
            "Test alert",
            "",
        )
