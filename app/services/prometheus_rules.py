import os
import re
import uuid
from typing import Any

from kubernetes import client, config
from kubernetes.client.exceptions import ApiException
from kubernetes.config.config_exception import ConfigException


GROUP = "monitoring.coreos.com"
VERSION = "v1"
PLURAL = "prometheusrules"

RULE_NAMESPACE = os.getenv(
    "PROMETHEUS_RULE_NAMESPACE",
    "alert-portal-rules",
)
RELEASE_LABEL_VALUE = os.getenv(
    "PROMETHEUS_RELEASE_LABEL_VALUE",
    "prometheus-stack",
)

MANAGED_LABEL_KEY = "app.kubernetes.io/managed-by"
MANAGED_LABEL_VALUE = "alert-portal"

ALLOWED_SEVERITIES = {"critical", "warning", "info"}
_RESERVED_CUSTOM_LABELS = {
    "severity", "created_by", "alertname", "alert_route", "portal_destination"
}

_ALERT_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_LABEL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")
_DURATION_RE = re.compile(
    r"^(?:0s|(?:[1-9][0-9]*(?:ms|s|m|h|d|w|y))+)$"
)
_DESTINATION_UNSET = object()
OWNER_USER_ID_ANNOTATION = "alert-portal.iraneit.app/owner-user-id"


class RuleValidationError(ValueError):
    """Raised when an alert rule contains invalid input."""


class RuleNotFoundError(LookupError):
    """Raised when a rule is missing or is not managed by the portal."""


class RulePermissionError(PermissionError):
    """Raised when a user cannot modify an alert rule."""


class RuleConflictError(RuntimeError):
    """Raised when Kubernetes reports a resource conflict."""


class KubernetesServiceError(RuntimeError):
    """Raised when the Kubernetes API is unavailable or rejects a request."""


def _get_api() -> client.CustomObjectsApi:
    """Create a Kubernetes API client using the Pod's service account."""
    try:
        config.load_incluster_config()
    except ConfigException as exc:
        raise KubernetesServiceError(
            "In-cluster Kubernetes authentication is unavailable."
        ) from exc

    return client.CustomObjectsApi()


def _call_api(operation, *args, **kwargs):
    """Translate Kubernetes API errors into safe application exceptions."""
    try:
        return operation(*args, **kwargs)

    except ApiException as exc:
        if exc.status == 404:
            raise RuleNotFoundError(
                "The requested alert rule was not found."
            ) from exc

        if exc.status == 409:
            raise RuleConflictError(
                "The alert rule conflicts with another change."
            ) from exc

        raise KubernetesServiceError(
            f"Kubernetes API request failed (HTTP {exc.status or 'unknown'})."
        ) from exc


def _is_portal_managed(rule: dict[str, Any]) -> bool:
    """Check that a resource has both required ownership labels."""
    metadata = rule.get("metadata", {})
    labels = metadata.get("labels", {})

    return (
        labels.get(MANAGED_LABEL_KEY) == MANAGED_LABEL_VALUE
        and labels.get("release") == RELEASE_LABEL_VALUE
    )


def _get_existing_rule(
    api: client.CustomObjectsApi,
    name: str,
) -> dict[str, Any]:
    """Retrieve a rule and reject resources not managed by this portal."""
    rule = _call_api(
        api.get_namespaced_custom_object,
        group=GROUP,
        version=VERSION,
        namespace=RULE_NAMESPACE,
        plural=PLURAL,
        name=name,
    )

    if not _is_portal_managed(rule):
        raise RuleNotFoundError(
            "The requested alert rule is not managed by the portal."
        )

    return rule


def _require_rule_write_permission(
    rule: dict[str, Any],
    *,
    actor_user_id: int,
    actor_role: str,
) -> None:
    """Allow admins to modify any rule and editors to modify their own."""

    if actor_role == "admin":
        return

    annotations = rule.get("metadata", {}).get("annotations") or {}
    owner_user_id = annotations.get(OWNER_USER_ID_ANNOTATION)

    if actor_role != "editor" or owner_user_id != str(actor_user_id):
        raise RulePermissionError(
            "You do not have permission to modify this alert rule."
        )


def _normalize_custom_labels(
    custom_labels: dict[str, str] | None,
    legacy_name: str | None,
    legacy_value: str | None,
) -> dict[str, str]:
    """Validate and normalize any number of user-supplied alert labels."""
    normalized: dict[str, str] = {}

    if custom_labels is None:
        custom_labels = {}
    if not isinstance(custom_labels, dict):
        raise RuleValidationError("Custom labels must be provided as a name/value object.")

    def add_label(raw_name: str, raw_value: str) -> None:
        if not isinstance(raw_name, str) or not isinstance(raw_value, str):
            raise RuleValidationError("Custom label names and values must be text.")

        name = raw_name.strip()
        value = raw_value.strip()
        if not name or not value:
            raise RuleValidationError("Custom label names and values cannot be empty.")
        if len(name) > 63:
            raise RuleValidationError("Custom label names must be 63 characters or fewer.")
        if len(value) > 256:
            raise RuleValidationError("Custom label values must be 256 characters or fewer.")
        if not _LABEL_NAME_RE.fullmatch(name):
            raise RuleValidationError(
                "Custom label names must start with a letter or underscore "
                "and contain only letters, numbers, or underscores."
            )
        if name.startswith("__"):
            raise RuleValidationError("Custom label names beginning with '__' are reserved.")
        if name in _RESERVED_CUSTOM_LABELS:
            raise RuleValidationError(f"'{name}' is a reserved label name.")
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise RuleValidationError("Custom label values cannot contain control characters.")
        if name in normalized:
            raise RuleValidationError(
                f"Duplicate custom label name '{name}'. Label names must be unique."
            )
        normalized[name] = value

    for name, value in custom_labels.items():
        add_label(name, value)

    # Accept the previous one-label API fields during the transition to multi-label UI.
    legacy_name = legacy_name.strip() if isinstance(legacy_name, str) else legacy_name
    legacy_value = legacy_value.strip() if isinstance(legacy_value, str) else legacy_value
    if not legacy_name and not legacy_value:
        return normalized
    if not legacy_name or not legacy_value:
        raise RuleValidationError(
            "Provide both a custom label name and value, or leave both empty."
        )
    add_label(legacy_name, legacy_value)
    return normalized


def _validated_rule_spec(
    alert_name: str,
    expression: str,
    duration: str,
    severity: str,
    summary: str,
    description: str,
    created_by: str | None = None,
    custom_label_name: str | None = None,
    custom_label_value: str | None = None,
    custom_labels: dict[str, str] | None = None,
    notification_destination_id: str | None = None,
) -> dict[str, Any]:
    """Validate input and construct a PrometheusRule spec."""
    if not isinstance(alert_name, str) or not _ALERT_NAME_RE.fullmatch(
        alert_name
    ):
        raise RuleValidationError(
            "Alert name must start with a letter or underscore and contain "
            "only letters, numbers, or underscores."
        )

    if not isinstance(expression, str):
        raise RuleValidationError("Expression must be text.")

    expression = expression.strip()
    if not expression:
        raise RuleValidationError("PromQL expression is required.")

    if len(expression) > 4096:
        raise RuleValidationError(
            "PromQL expression must be 4096 characters or fewer."
        )

    if not isinstance(duration, str):
        raise RuleValidationError("Duration must be text.")

    duration = duration.strip()
    if not _DURATION_RE.fullmatch(duration):
        raise RuleValidationError(
            "Duration must use Prometheus duration syntax, such as 0s, 5m, "
            "or 1h30m."
        )

    if severity not in ALLOWED_SEVERITIES:
        raise RuleValidationError(
            "Severity must be critical, warning, or info."
        )

    if not isinstance(summary, str) or not summary.strip():
        raise RuleValidationError("Summary is required.")

    summary = summary.strip()
    if len(summary) > 500:
        raise RuleValidationError(
            "Summary must be 500 characters or fewer."
        )

    if not isinstance(description, str):
        raise RuleValidationError("Description must be text.")

    description = description.strip()
    if len(description) > 2000:
        raise RuleValidationError(
            "Description must be 2000 characters or fewer."
        )

    if created_by is not None:
        if (
            not isinstance(created_by, str)
            or not _USERNAME_RE.fullmatch(created_by)
        ):
            raise RuleValidationError(
                "Creator username must contain 1–64 letters, numbers, "
                "periods, underscores, or hyphens."
            )

    normalized_custom_labels = _normalize_custom_labels(
        custom_labels=custom_labels,
        legacy_name=custom_label_name,
        legacy_value=custom_label_value,
    )

    labels = {"severity": severity}

    if created_by is not None:
        labels["created_by"] = created_by

    labels.update(normalized_custom_labels)

    if notification_destination_id is not None:
        try:
            destination_id = str(uuid.UUID(notification_destination_id))
        except (ValueError, TypeError, AttributeError) as exc:
            raise RuleValidationError("Mattermost destination ID is invalid.") from exc
        labels["alert_route"] = "portal"
        labels["portal_destination"] = destination_id

    alert = {
        "alert": alert_name,
        "expr": expression,
        "labels": labels,
        "annotations": {"summary": summary},
    }

    if duration != "0s":
        alert["for"] = duration

    if description:
        alert["annotations"]["description"] = description

    return {
        "groups": [
            {
                "name": "portal-alerts",
                "rules": [alert],
            }
        ]
    }


def list_portal_rules(
    api: client.CustomObjectsApi | None = None,
) -> list[dict[str, Any]]:
    """List only alert rules managed by this portal."""
    api = api or _get_api()

    response = _call_api(
        api.list_namespaced_custom_object,
        group=GROUP,
        version=VERSION,
        namespace=RULE_NAMESPACE,
        plural=PLURAL,
        label_selector=(
            f"{MANAGED_LABEL_KEY}={MANAGED_LABEL_VALUE},"
            f"release={RELEASE_LABEL_VALUE}"
        ),
    )

    return [
        rule
        for rule in response.get("items", [])
        if _is_portal_managed(rule)
    ]


def get_portal_rule(
    name: str,
    api: client.CustomObjectsApi | None = None,
) -> dict[str, Any]:
    """Retrieve one alert rule managed by this portal."""
    api = api or _get_api()
    return _get_existing_rule(api, name)


def create_portal_rule(
    alert_name: str,
    expression: str,
    duration: str,
    severity: str,
    summary: str,
    owner_user_id: int,
    description: str = "",
    created_by: str | None = None,
    custom_label_name: str | None = None,
    custom_label_value: str | None = None,
    custom_labels: dict[str, str] | None = None,
    notification_destination_id: str | None = None,
    api: client.CustomObjectsApi | None = None,
) -> dict[str, Any]:
    """Create an independently managed PrometheusRule resource."""
    if type(owner_user_id) is not int or owner_user_id <= 0:
        raise RuleValidationError("The alert owner user ID is invalid.")

    api = api or _get_api()

    spec = _validated_rule_spec(
        alert_name=alert_name,
        expression=expression,
        duration=duration,
        severity=severity,
        summary=summary,
        description=description,
        created_by=created_by,
        custom_label_name=custom_label_name,
        custom_label_value=custom_label_value,
        custom_labels=custom_labels,
        notification_destination_id=notification_destination_id,
    )

    resource_name = f"alert-portal-{uuid.uuid4().hex[:12]}"

    body = {
        "apiVersion": f"{GROUP}/{VERSION}",
        "kind": "PrometheusRule",
        "metadata": {
            "name": resource_name,
            "namespace": RULE_NAMESPACE,
            "labels": {
                "release": RELEASE_LABEL_VALUE,
                MANAGED_LABEL_KEY: MANAGED_LABEL_VALUE,
            },
            "annotations": {
                OWNER_USER_ID_ANNOTATION: str(owner_user_id),
            },
        },
        "spec": spec,
    }

    return _call_api(
        api.create_namespaced_custom_object,
        group=GROUP,
        version=VERSION,
        namespace=RULE_NAMESPACE,
        plural=PLURAL,
        body=body,
    )


def update_portal_rule(
    name: str,
    alert_name: str,
    expression: str,
    duration: str,
    severity: str,
    summary: str,
    actor_user_id: int,
    actor_role: str,
    description: str = "",
    custom_label_name: str | None = None,
    custom_label_value: str | None = None,
    custom_labels: dict[str, str] | None = None,
    notification_destination_id=_DESTINATION_UNSET,
    api: client.CustomObjectsApi | None = None,
) -> dict[str, Any]:
    """Update a rule while retaining its creator and omitted routing fields."""
    api = api or _get_api()
    existing = _get_existing_rule(api, name)

    _require_rule_write_permission(
        existing,
        actor_user_id=actor_user_id,
        actor_role=actor_role,
    )

    existing_groups = existing.get("spec", {}).get("groups", [])
    existing_rules = existing_groups[0].get("rules", []) if existing_groups else []
    existing_labels = existing_rules[0].get("labels", {}) if existing_rules else {}
    original_creator = existing_labels.get("created_by")
    if notification_destination_id is _DESTINATION_UNSET:
        # Keep notification routing for clients that predate the destination field.
        notification_destination_id = existing_labels.get("portal_destination")

    spec = _validated_rule_spec(
        alert_name=alert_name,
        expression=expression,
        duration=duration,
        severity=severity,
        summary=summary,
        description=description,
        created_by=original_creator,
        custom_label_name=custom_label_name,
        custom_label_value=custom_label_value,
        custom_labels=custom_labels,
        notification_destination_id=notification_destination_id,
    )

    # The JSON Patch tests make the update conditional on the resource we
    # authorized above. A concurrent ownership or spec change cannot silently
    # slip between the read and write operations.
    patch_body = [
        {
            "op": "test",
            "path": "/metadata/uid",
            "value": existing["metadata"]["uid"],
        },
        {
            "op": "test",
            "path": "/metadata/resourceVersion",
            "value": existing["metadata"]["resourceVersion"],
        },
        {"op": "replace", "path": "/spec", "value": spec},
    ]

    # Kubernetes Python client 35.0.0 hardcodes merge-patch for the generated
    # patch_namespaced_custom_object method and does not accept _content_type.
    # Use its configured, authenticated ApiClient directly so the RFC 6902
    # test operations retain their atomic conflict-protection semantics.
    return _call_api(
        api.api_client.call_api,
        "/apis/{group}/{version}/namespaces/{namespace}/{plural}/{name}",
        "PATCH",
        {
            "group": GROUP,
            "version": VERSION,
            "namespace": RULE_NAMESPACE,
            "plural": PLURAL,
            "name": name,
        },
        [],
        {
            "Accept": "application/json",
            "Content-Type": "application/json-patch+json",
        },
        body=patch_body,
        post_params=[],
        files={},
        response_type="object",
        auth_settings=["BearerToken"],
        _return_http_data_only=True,
        _preload_content=True,
        collection_formats={},
    )


def delete_portal_rule(
    name: str,
    actor_user_id: int,
    actor_role: str,
    api: client.CustomObjectsApi | None = None,
) -> dict[str, Any]:
    """Delete a portal-managed rule only when the user may modify it."""
    api = api or _get_api()

    existing = _get_existing_rule(api, name)
    _require_rule_write_permission(
        existing,
        actor_user_id=actor_user_id,
        actor_role=actor_role,
    )

    return _call_api(
        api.delete_namespaced_custom_object,
        group=GROUP,
        version=VERSION,
        namespace=RULE_NAMESPACE,
        plural=PLURAL,
        name=name,
        body={
            "apiVersion": "v1",
            "kind": "DeleteOptions",
            "preconditions": {
                "uid": existing["metadata"]["uid"],
                "resourceVersion": existing["metadata"]["resourceVersion"],
            },
        },
    )
