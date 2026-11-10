from copy import deepcopy
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.auth.dependencies import AuthenticatedUser, get_current_user
from app.main import app
from app.routes.rules import require_valid_csrf
from app.services.prometheus_rules import (
    OWNER_USER_ID_ANNOTATION,
    RuleValidationError,
    _validated_rule_spec,
    create_portal_rule,
    update_portal_rule,
)


ADMIN = AuthenticatedUser(
    id=1,
    username="admin-user",
    role="admin",
)


@pytest.fixture
def client():
    app.dependency_overrides.clear()
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def sample_rule(
    *,
    creator="admin-user",
    severity="warning",
    summary="Test target down",
    custom_label_name="team",
    custom_label_value="database",
):
    labels = {
        "severity": severity,
        "created_by": creator,
    }

    if custom_label_name and custom_label_value:
        labels[custom_label_name] = custom_label_value

    return {
        "apiVersion": "monitoring.coreos.com/v1",
        "kind": "PrometheusRule",
        "metadata": {
            "name": "alert-portal-labeltest",
            "uid": "labeltest-uid",
            "namespace": "alert-portal-rules",
            "resourceVersion": "42",
            "annotations": {OWNER_USER_ID_ANNOTATION: str(ADMIN.id)},
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
                            "alert": "LabelTestAlert",
                            "expr": "up == 0",
                            "for": "5m",
                            "labels": labels,
                            "annotations": {
                                "summary": summary,
                                "description": "Testing searchable labels.",
                            },
                        }
                    ],
                }
            ]
        },
    }


def valid_arguments():
    return {
        "alert_name": "LabelTestAlert",
        "expression": "up == 0",
        "duration": "5m",
        "severity": "warning",
        "summary": "Test target down",
        "description": "Testing searchable labels.",
        "created_by": "admin-user",
        "custom_label_name": "team",
        "custom_label_value": "database",
    }


def test_create_attaches_creator_and_custom_labels():
    api = MagicMock()
    api.create_namespaced_custom_object.side_effect = (
        lambda **kwargs: kwargs["body"]
    )

    result = create_portal_rule(**valid_arguments(), owner_user_id=ADMIN.id, api=api)

    body = api.create_namespaced_custom_object.call_args.kwargs["body"]
    alert = body["spec"]["groups"][0]["rules"][0]

    assert body["metadata"]["namespace"] == "alert-portal-rules"
    assert body["metadata"]["labels"]["release"] == "prometheus-stack"
    assert (
        body["metadata"]["labels"]["app.kubernetes.io/managed-by"]
        == "alert-portal"
    )
    assert body["metadata"]["annotations"][OWNER_USER_ID_ANNOTATION] == str(ADMIN.id)
    assert alert["labels"]["severity"] == "warning"
    assert alert["labels"]["created_by"] == "admin-user"
    assert alert["labels"]["team"] == "database"
    assert result == body


@pytest.mark.parametrize(
    "label_name",
    [
        "severity",
        "created_by",
        "alertname",
        "__internal",
        "team-name",
        "team name",
    ],
)
def test_reserved_or_invalid_custom_label_name_is_rejected(label_name):
    arguments = valid_arguments()
    arguments["custom_label_name"] = label_name

    with pytest.raises(RuleValidationError):
        _validated_rule_spec(
            alert_name=arguments["alert_name"],
            expression=arguments["expression"],
            duration=arguments["duration"],
            severity=arguments["severity"],
            summary=arguments["summary"],
            description=arguments["description"],
            created_by=arguments["created_by"],
            custom_label_name=arguments["custom_label_name"],
            custom_label_value=arguments["custom_label_value"],
        )


@pytest.mark.parametrize(
    ("label_name", "label_value"),
    [
        ("team", None),
        (None, "database"),
        ("", "database"),
        ("team", ""),
    ],
)
def test_custom_label_requires_both_name_and_value(label_name, label_value):
    arguments = valid_arguments()
    arguments["custom_label_name"] = label_name
    arguments["custom_label_value"] = label_value

    with pytest.raises(RuleValidationError):
        _validated_rule_spec(
            alert_name=arguments["alert_name"],
            expression=arguments["expression"],
            duration=arguments["duration"],
            severity=arguments["severity"],
            summary=arguments["summary"],
            description=arguments["description"],
            created_by=arguments["created_by"],
            custom_label_name=arguments["custom_label_name"],
            custom_label_value=arguments["custom_label_value"],
        )


def test_update_preserves_original_creator_and_updates_custom_label():
    api = MagicMock()
    existing = sample_rule(creator="original-owner")
    api.get_namespaced_custom_object.return_value = existing
    api.api_client.call_api.return_value = deepcopy(existing)

    update_portal_rule(
        name="alert-portal-labeltest",
        alert_name="LabelTestAlert",
        expression="up == 0",
        duration="5m",
        severity="critical",
        summary="Updated target alert",
        description="Updated description",
        custom_label_name="team",
        custom_label_value="platform",
        actor_user_id=ADMIN.id,
        actor_role=ADMIN.role,
        api=api,
    )

    call = api.api_client.call_api.call_args
    assert call.args[1] == "PATCH"
    assert call.args[4]["Content-Type"] == "application/json-patch+json"
    assert call.kwargs["auth_settings"] == ["BearerToken"]
    api.patch_namespaced_custom_object.assert_not_called()
    patch_body = call.kwargs["body"]
    assert patch_body[0] == {
        "op": "test", "path": "/metadata/uid", "value": "labeltest-uid",
    }
    assert patch_body[1] == {
        "op": "test", "path": "/metadata/resourceVersion", "value": "42",
    }
    assert patch_body[2]["op"] == "replace"
    assert patch_body[2]["path"] == "/spec"
    alert = patch_body[2]["value"]["groups"][0]["rules"][0]

    assert alert["labels"]["created_by"] == "original-owner"
    assert alert["labels"]["team"] == "platform"
    assert alert["labels"]["severity"] == "critical"
    assert alert["annotations"]["summary"] == "Updated target alert"


def test_create_api_uses_authenticated_username_as_creator(client):
    app.dependency_overrides[get_current_user] = lambda: ADMIN
    app.dependency_overrides[require_valid_csrf] = lambda: ADMIN

    rule = sample_rule()

    with (
        patch(
            "app.routes.rules.create_portal_rule",
            return_value=rule,
        ) as create_rule,
        patch("app.routes.rules.record_audit_event") as audit,
    ):
        response = client.post(
            "/api/rules",
            json={
                "alert_name": "LabelTestAlert",
                "expression": "up == 0",
                "duration": "5m",
                "severity": "warning",
                "summary": "Test target down",
                "description": "Testing searchable labels.",
                "custom_label_name": "team",
                "custom_label_value": "database",
            },
        )

    assert response.status_code == 201
    assert response.json()["created_by"] == "admin-user"
    assert response.json()["custom_labels"] == {"team": "database"}

    assert create_rule.call_args.kwargs["created_by"] == "admin-user"
    assert create_rule.call_args.kwargs["owner_user_id"] == ADMIN.id
    assert create_rule.call_args.kwargs["custom_label_name"] == "team"
    assert create_rule.call_args.kwargs["custom_label_value"] == "database"

    # record_audit_event receives labels inside its "details" argument.
    audit_details = audit.call_args.kwargs["details"]
    assert audit_details["labels"]["created_by"] == "admin-user"
    assert audit_details["labels"]["team"] == "database"


def test_create_api_accepts_multiple_custom_labels(client):
    app.dependency_overrides[get_current_user] = lambda: ADMIN
    app.dependency_overrides[require_valid_csrf] = lambda: ADMIN

    rule = sample_rule()
    alert = rule["spec"]["groups"][0]["rules"][0]
    alert["labels"].update({"environment": "production", "service": "postgresql"})

    custom_labels = {
        "team": "database",
        "environment": "production",
        "service": "postgresql",
    }

    with (
        patch(
            "app.routes.rules.create_portal_rule",
            return_value=rule,
        ) as create_rule,
        patch("app.routes.rules.record_audit_event") as audit,
    ):
        response = client.post(
            "/api/rules",
            json={
                "alert_name": "LabelTestAlert",
                "expression": "up == 0",
                "duration": "5m",
                "severity": "warning",
                "summary": "Test target down",
                "description": "Testing multiple labels.",
                "custom_labels": custom_labels,
            },
        )

    assert response.status_code == 201
    assert response.json()["custom_labels"] == custom_labels
    assert create_rule.call_args.kwargs["created_by"] == "admin-user"
    assert create_rule.call_args.kwargs["owner_user_id"] == ADMIN.id
    assert create_rule.call_args.kwargs["custom_labels"] == custom_labels
    audit_details = audit.call_args.kwargs["details"]
    assert audit_details["labels"]["created_by"] == "admin-user"
    assert audit_details["labels"]["team"] == "database"
    assert audit_details["labels"]["environment"] == "production"
    assert audit_details["labels"]["service"] == "postgresql"


def test_rule_dashboard_has_search_by_creator_and_label(client):
    session_token = "test-session-token-for-label-dashboard"
    csrf_token = "test-csrf-token-for-label-dashboard"

    client.cookies.set("alert_portal_session", session_token)
    client.cookies.set("alert_portal_csrf", csrf_token)

    connection = MagicMock()
    connection.execute.return_value.fetchone.return_value = (1,)

    with (
        patch(
            "app.routes.dashboard.get_user_from_session_token",
            return_value=ADMIN,
        ),
        patch(
            "app.routes.dashboard.get_database_connection"
        ) as mock_db,
    ):
        mock_db.return_value.__enter__.return_value = connection
        response = client.get("/alerts")

    assert response.status_code == 200
    assert 'id="rule-search"' in response.text
    assert "created_by" in response.text
    assert "rule.labels" in response.text
    assert "searchableText(rule)" in response.text
    # The multi-label editor uses a container and dynamically generated rows.
    assert 'id="custom-labels"' in response.text
    assert 'id="add-label-row"' in response.text
    assert 'LABEL_NAME_MAX = 63' in response.text
    assert 'LABEL_VALUE_MAX = 256' in response.text
    assert 'custom_labels: customLabels' in response.text
    assert 'Remove custom label row' in response.text

@pytest.mark.parametrize(
    ("custom_labels", "expected"),
    [
        ({"team": "database", "environment": "production", "service": "postgresql"},
         {"team": "database", "environment": "production", "service": "postgresql"}),
        ({"a" * 63: "x"}, {"a" * 63: "x"}),
        ({"team": "x" * 256}, {"team": "x" * 256}),
    ],
)
def test_multiple_custom_labels_and_boundary_lengths_are_accepted(custom_labels, expected):
    arguments = valid_arguments()
    arguments["custom_label_name"] = None
    arguments["custom_label_value"] = None

    spec = _validated_rule_spec(**arguments, custom_labels=custom_labels)
    labels = spec["groups"][0]["rules"][0]["labels"]

    for key, value in expected.items():
        assert labels[key] == value


@pytest.mark.parametrize(
    ("custom_labels", "message"),
    [
        ({"a" * 64: "x"}, "63 characters"),
        ({"team": "x" * 257}, "256 characters"),
        ({"team": "database", " team ": "platform"}, "Duplicate"),
        ({"severity": "critical"}, "reserved"),
        ({"created_by": "someone-else"}, "reserved"),
        ({"__internal": "value"}, "reserved"),
        ({"team": "bad\nvalue"}, "control characters"),
        ({"team": ""}, "cannot be empty"),
    ],
)
def test_custom_label_collection_validation(custom_labels, message):
    arguments = valid_arguments()
    arguments["custom_label_name"] = None
    arguments["custom_label_value"] = None

    with pytest.raises(RuleValidationError, match=message):
        _validated_rule_spec(**arguments, custom_labels=custom_labels)


def test_create_rule_service_passes_all_custom_labels_to_prometheus_rule():
    api = MagicMock()
    api.create_namespaced_custom_object.side_effect = (
        lambda **kwargs: kwargs["body"]
    )
    arguments = valid_arguments()
    arguments["custom_label_name"] = None
    arguments["custom_label_value"] = None
    arguments["custom_labels"] = {
        "team": "database",
        "environment": "production",
        "service": "postgresql",
    }

    result = create_portal_rule(**arguments, owner_user_id=ADMIN.id, api=api)
    labels = result["spec"]["groups"][0]["rules"][0]["labels"]

    assert labels["created_by"] == "admin-user"
    assert labels["team"] == "database"
    assert labels["environment"] == "production"
    assert labels["service"] == "postgresql"
