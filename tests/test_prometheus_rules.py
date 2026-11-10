from copy import deepcopy
from unittest.mock import MagicMock

import pytest
from kubernetes.client.rest import ApiException

from app.services.prometheus_rules import (
    OWNER_USER_ID_ANNOTATION,
    RuleConflictError,
    RuleNotFoundError,
    RulePermissionError,
    RuleValidationError,
    create_portal_rule,
    delete_portal_rule,
    list_portal_rules,
    update_portal_rule,
)


def make_rule(
    name="alert-portal-test123456",
    managed=True,
    resource_version="17",
    owner_user_id=2,
):
    labels = {
        "release": "prometheus-stack",
    }

    if managed:
        labels["app.kubernetes.io/managed-by"] = "alert-portal"

    return {
        "apiVersion": "monitoring.coreos.com/v1",
        "kind": "PrometheusRule",
        "metadata": {
            "name": name,
            "uid": "rule-uid-123456",
            "namespace": "alert-portal-rules",
            "resourceVersion": resource_version,
            "labels": labels,
            "annotations": (
                {OWNER_USER_ID_ANNOTATION: str(owner_user_id)}
                if owner_user_id is not None else {}
            ),
        },
        "spec": {
            "groups": [
                {
                    "name": "portal-alerts",
                    "rules": [
                        {
                            "alert": "TestAlert",
                            "expr": "up == 0",
                            "for": "5m",
                            "labels": {"severity": "warning"},
                            "annotations": {"summary": "Test target down"},
                        }
                    ],
                }
            ]
        },
    }


def valid_arguments():
    return {
        "alert_name": "TestAlert",
        "expression": "up == 0",
        "duration": "5m",
        "severity": "warning",
        "summary": "Test target down",
        "description": "The monitored target is down.",
    }


def test_list_returns_only_portal_managed_rules():
    api = MagicMock()
    managed_rule = make_rule()
    unmanaged_rule = make_rule(
        name="someone-elses-rule",
        managed=False,
    )
    api.list_namespaced_custom_object.return_value = {
        "items": [managed_rule, unmanaged_rule]
    }

    result = list_portal_rules(api=api)

    assert result == [managed_rule]
    call = api.list_namespaced_custom_object.call_args.kwargs
    assert call["namespace"] == "alert-portal-rules"
    assert call["plural"] == "prometheusrules"
    assert "release=prometheus-stack" in call["label_selector"]
    assert "app.kubernetes.io/managed-by=alert-portal" in call["label_selector"]


def test_create_adds_required_labels_and_dedicated_namespace():
    api = MagicMock()
    api.create_namespaced_custom_object.side_effect = (
        lambda **kwargs: kwargs["body"]
    )

    result = create_portal_rule(**valid_arguments(), owner_user_id=2, api=api)

    call = api.create_namespaced_custom_object.call_args.kwargs
    body = call["body"]

    assert call["namespace"] == "alert-portal-rules"
    assert call["plural"] == "prometheusrules"
    assert body["metadata"]["name"].startswith("alert-portal-")
    assert body["metadata"]["labels"]["release"] == "prometheus-stack"
    assert (
        body["metadata"]["labels"]["app.kubernetes.io/managed-by"]
        == "alert-portal"
    )
    assert body["metadata"]["annotations"][OWNER_USER_ID_ANNOTATION] == "2"
    assert body["spec"]["groups"][0]["rules"][0]["alert"] == "TestAlert"
    assert result == body


def test_create_rejects_invalid_duration_without_calling_kubernetes():
    api = MagicMock()
    arguments = valid_arguments()
    arguments["duration"] = "5minutes"

    with pytest.raises(RuleValidationError):
        create_portal_rule(**arguments, owner_user_id=2, api=api)

    api.create_namespaced_custom_object.assert_not_called()


def test_create_rejects_invalid_severity_without_calling_kubernetes():
    api = MagicMock()
    arguments = valid_arguments()
    arguments["severity"] = "emergency"

    with pytest.raises(RuleValidationError):
        create_portal_rule(**arguments, owner_user_id=2, api=api)

    api.create_namespaced_custom_object.assert_not_called()


@pytest.mark.parametrize("bad_id", [None, 0, -3, True, "2"])
def test_create_rejects_invalid_owner_user_id(bad_id):
    api = MagicMock()
    with pytest.raises(RuleValidationError, match="owner user ID"):
        create_portal_rule(**valid_arguments(), owner_user_id=bad_id, api=api)
    api.create_namespaced_custom_object.assert_not_called()


def test_update_refuses_a_rule_not_managed_by_portal():
    api = MagicMock()
    api.get_namespaced_custom_object.return_value = make_rule(
        managed=False
    )

    with pytest.raises(RuleNotFoundError):
        update_portal_rule(
            name="someone-elses-rule",
            **valid_arguments(),
            actor_user_id=2,
            actor_role="editor",
            api=api,
        )

    api.api_client.call_api.assert_not_called()


def test_delete_refuses_a_rule_not_managed_by_portal():
    api = MagicMock()
    api.get_namespaced_custom_object.return_value = make_rule(
        managed=False
    )

    with pytest.raises(RuleNotFoundError):
        delete_portal_rule(
            "someone-elses-rule", actor_user_id=2, actor_role="editor", api=api
        )

    api.delete_namespaced_custom_object.assert_not_called()


def test_update_preserves_resource_identity_and_patches_spec():
    api = MagicMock()
    existing = make_rule(resource_version="42")
    api.get_namespaced_custom_object.return_value = existing
    api.api_client.call_api.return_value = deepcopy(existing)

    update_portal_rule(
        name="alert-portal-test123456",
        **valid_arguments(),
        actor_user_id=2,
        actor_role="editor",
        api=api,
    )

    call = api.api_client.call_api.call_args
    assert call.args[0] == "/apis/{group}/{version}/namespaces/{namespace}/{plural}/{name}"
    assert call.args[1] == "PATCH"
    assert call.args[2]["name"] == "alert-portal-test123456"
    assert call.args[2]["namespace"] == "alert-portal-rules"
    assert call.args[4]["Content-Type"] == "application/json-patch+json"
    assert call.kwargs["auth_settings"] == ["BearerToken"]
    assert call.kwargs["_return_http_data_only"] is True
    assert call.kwargs["response_type"] == "object"
    api.patch_namespaced_custom_object.assert_not_called()
    patch_body = call.kwargs["body"]
    assert patch_body[:2] == [
        {"op": "test", "path": "/metadata/uid", "value": "rule-uid-123456"},
        {"op": "test", "path": "/metadata/resourceVersion", "value": "42"},
    ]
    assert patch_body[2]["op"] == "replace"
    assert patch_body[2]["path"] == "/spec"
    assert patch_body[2]["value"]["groups"][0]["rules"][0]["alert"] == "TestAlert"


def test_delete_checks_ownership_before_deleting():
    api = MagicMock()
    api.get_namespaced_custom_object.return_value = make_rule()
    api.delete_namespaced_custom_object.return_value = {
        "status": "Success"
    }

    result = delete_portal_rule(
        "alert-portal-test123456", actor_user_id=2, actor_role="editor", api=api
    )

    api.get_namespaced_custom_object.assert_called_once()
    api.delete_namespaced_custom_object.assert_called_once()
    assert api.delete_namespaced_custom_object.call_args.kwargs["namespace"] == (
        "alert-portal-rules"
    )
    assert api.delete_namespaced_custom_object.call_args.kwargs["body"] == {
        "apiVersion": "v1",
        "kind": "DeleteOptions",
        "preconditions": {
            "uid": "rule-uid-123456",
            "resourceVersion": "17",
        },
    }
    assert result == {"status": "Success"}


@pytest.mark.parametrize("operation", ["update", "delete"])
@pytest.mark.parametrize("owner", [None, 7])
def test_editor_cannot_change_unowned_or_other_users_rule(operation, owner):
    api = MagicMock()
    api.get_namespaced_custom_object.return_value = make_rule(owner_user_id=owner)

    with pytest.raises(RulePermissionError):
        if operation == "update":
            update_portal_rule(
                name="alert-portal-test123456", **valid_arguments(),
                actor_user_id=2, actor_role="editor", api=api,
            )
        else:
            delete_portal_rule(
                "alert-portal-test123456", actor_user_id=2,
                actor_role="editor", api=api,
            )

    api.api_client.call_api.assert_not_called()
    api.delete_namespaced_custom_object.assert_not_called()


@pytest.mark.parametrize("operation", ["update", "delete"])
def test_viewer_cannot_modify_even_owned_rule(operation):
    api = MagicMock()
    api.get_namespaced_custom_object.return_value = make_rule(owner_user_id=3)
    with pytest.raises(RulePermissionError):
        if operation == "update":
            update_portal_rule(
                name="alert-portal-test123456", **valid_arguments(),
                actor_user_id=3, actor_role="viewer", api=api,
            )
        else:
            delete_portal_rule(
                "alert-portal-test123456", actor_user_id=3,
                actor_role="viewer", api=api,
            )
    api.api_client.call_api.assert_not_called()
    api.delete_namespaced_custom_object.assert_not_called()


@pytest.mark.parametrize("operation", ["update", "delete"])
@pytest.mark.parametrize("owner", [None, 7])
def test_admin_can_modify_any_rule(operation, owner):
    api = MagicMock()
    api.get_namespaced_custom_object.return_value = make_rule(owner_user_id=owner)
    if operation == "update":
        update_portal_rule(
            name="alert-portal-test123456", **valid_arguments(),
            actor_user_id=1, actor_role="admin", api=api,
        )
        api.api_client.call_api.assert_called_once()
    else:
        delete_portal_rule(
            "alert-portal-test123456", actor_user_id=1,
            actor_role="admin", api=api,
        )
        api.delete_namespaced_custom_object.assert_called_once()


@pytest.mark.parametrize("operation", ["update", "delete"])
def test_concurrent_kubernetes_conflict_blocks_rule_change(operation):
    api = MagicMock()
    api.get_namespaced_custom_object.return_value = make_rule()
    if operation == "update":
        api.api_client.call_api.side_effect = ApiException(status=409)
    else:
        api.delete_namespaced_custom_object.side_effect = ApiException(status=409)

    with pytest.raises(RuleConflictError):
        if operation == "update":
            update_portal_rule(
                name="alert-portal-test123456", **valid_arguments(),
                actor_user_id=2, actor_role="editor", api=api,
            )
        else:
            delete_portal_rule(
                "alert-portal-test123456", actor_user_id=2,
                actor_role="editor", api=api,
            )


def test_update_keeps_original_mattermost_destination_and_owner_annotation():
    api = MagicMock()
    existing = make_rule()
    original = existing["spec"]["groups"][0]["rules"][0]
    original["labels"].update({
        "created_by": "original-username",
        "alert_route": "portal",
        "portal_destination": "ea431aa2-ea58-431e-8664-affc516f824b",
    })
    api.get_namespaced_custom_object.return_value = existing

    update_portal_rule(
        name="alert-portal-test123456", **valid_arguments(),
        actor_user_id=2, actor_role="editor", api=api,
    )
    patch = api.api_client.call_api.call_args.kwargs["body"]
    updated_labels = patch[2]["value"]["groups"][0]["rules"][0]["labels"]
    assert updated_labels["created_by"] == "original-username"
    assert updated_labels["alert_route"] == "portal"
    assert updated_labels["portal_destination"] == "ea431aa2-ea58-431e-8664-affc516f824b"
    assert all(part["path"] != "/metadata/annotations" for part in patch)


def test_create_adds_backend_managed_mattermost_routing_labels():
    import uuid

    api = MagicMock()
    api.create_namespaced_custom_object.side_effect = (
        lambda **kwargs: kwargs["body"]
    )
    destination_id = str(uuid.uuid4())

    result = create_portal_rule(
        **valid_arguments(),
        owner_user_id=2,
        notification_destination_id=destination_id,
        api=api,
    )

    labels = result["spec"]["groups"][0]["rules"][0]["labels"]
    assert labels["alert_route"] == "portal"
    assert labels["portal_destination"] == destination_id


@pytest.mark.parametrize(
    "reserved_label",
    ["alert_route", "portal_destination"],
)
def test_custom_labels_cannot_override_mattermost_routing(reserved_label):
    api = MagicMock()

    with pytest.raises(RuleValidationError, match="reserved"):
        create_portal_rule(
            **valid_arguments(),
            owner_user_id=2,
            custom_labels={reserved_label: "forged"},
            api=api,
        )

    api.create_namespaced_custom_object.assert_not_called()
