import secrets
from typing import Annotated, Literal

import psycopg
from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Request,
    status,
)
from pydantic import BaseModel, ConfigDict, Field

from app.auth.dependencies import (
    AuthenticatedUser,
    get_current_user,
    require_roles,
)
from app.auth.security import hash_csrf_token, hash_session_token
from app.services.audit import record_audit_event
from app.services.database import get_database_connection
from app.services.mattermost_destinations import (
    DestinationNotFoundError,
    DestinationValidationError,
    canonical_destination_id,
    get_user_destination,
)
from app.services.promql_validation import (
    PrometheusValidationUnavailable,
    validate_promql_expression,
)
from app.services.promql_templates import (
    PrometheusTemplateOptionsUnavailable,
    get_promql_template_options,
)
from app.services.prometheus_rules import (
    KubernetesServiceError,
    OWNER_USER_ID_ANNOTATION,
    RuleConflictError,
    RuleNotFoundError,
    RulePermissionError,
    RuleValidationError,
    create_portal_rule,
    delete_portal_rule,
    get_portal_rule,
    list_portal_rules,
    update_portal_rule,
)


router = APIRouter(prefix="/api/rules", tags=["alert-rules"])


class PromQLValidationPayload(BaseModel):
    """Input model for testing a PromQL expression without saving it."""

    model_config = ConfigDict(extra="forbid")

    expression: str = Field(min_length=1, max_length=4096)


class AlertRulePayload(BaseModel):
    """Input model for creating or updating a portal-managed alert."""

    model_config = ConfigDict(extra="forbid")

    alert_name: str = Field(min_length=1, max_length=128)
    expression: str = Field(min_length=1, max_length=4096)
    duration: str = Field(min_length=1, max_length=64)
    severity: Literal["critical", "warning", "info"]
    summary: str = Field(min_length=1, max_length=500)
    description: str = Field(default="", max_length=2000)
    # Multiple custom labels are the primary interface. The two legacy fields
    # remain accepted temporarily so older clients do not break during rollout.
    custom_labels: dict[str, str] = Field(default_factory=dict)
    custom_label_name: str | None = Field(default=None, max_length=63)
    custom_label_value: str | None = Field(default=None, max_length=256)
    notification_destination_id: str | None = Field(default=None, max_length=36)


def require_valid_csrf(
    request: Request,
    x_csrf_token: Annotated[
        str | None, Header(alias="X-CSRF-Token")
    ] = None,
    user: AuthenticatedUser = Depends(get_current_user),
) -> AuthenticatedUser:
    """Validate the request token against the cookie and active session."""
    session_token = request.cookies.get("alert_portal_session")
    csrf_cookie = request.cookies.get("alert_portal_csrf")

    if not session_token or not csrf_cookie or not x_csrf_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="A valid CSRF token is required.",
        )

    if not secrets.compare_digest(csrf_cookie, x_csrf_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid CSRF token.",
        )

    try:
        with get_database_connection() as connection:
            row = connection.execute(
                """
                SELECT 1
                FROM user_sessions
                WHERE token_hash = %s
                  AND csrf_token_hash = %s
                  AND user_id = %s
                  AND revoked_at IS NULL
                  AND expires_at > NOW()
                """,
                (
                    hash_session_token(session_token),
                    hash_csrf_token(csrf_cookie),
                    user.id,
                ),
            ).fetchone()
    except psycopg.Error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service temporarily unavailable.",
        ) from None

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The CSRF token is not valid for this session.",
        )

    return user


def _call_service(operation, *args, **kwargs):
    """Map service errors to safe, consistent HTTP responses."""
    try:
        return operation(*args, **kwargs)
    except RuleValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuleNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RulePermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except RuleConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except KubernetesServiceError:
        raise HTTPException(
            status_code=503,
            detail="The alert-rule service is temporarily unavailable.",
        ) from None


def _serialize_rule(
    rule: dict,
    *,
    user: AuthenticatedUser | None = None,
) -> dict:
    """Return the rule fields needed by the portal UI."""
    metadata = rule.get("metadata", {})
    owner_annotations = metadata.get("annotations") or {}
    owner_user_id = owner_annotations.get(OWNER_USER_ID_ANNOTATION)
    can_modify = bool(
        user is not None
        and (
            user.role == "admin"
            or (user.role == "editor" and owner_user_id == str(user.id))
        )
    )
    spec = rule.get("spec", {})
    groups = spec.get("groups", [])
    rules = groups[0].get("rules", []) if groups else []
    alert = rules[0] if rules else {}

    labels = alert.get("labels", {})
    annotations = alert.get("annotations", {})

    routing_labels = {"alert_route", "portal_destination"}
    custom_labels = {
        key: value
        for key, value in labels.items()
        if key not in {"severity", "created_by", "alertname", *routing_labels}
    }
    visible_labels = {
        key: value for key, value in labels.items() if key not in routing_labels
    }

    first_custom_label = (
        sorted(custom_labels.items())[0] if custom_labels else ("", "")
    )

    return {
        "name": metadata.get("name"),
        "namespace": metadata.get("namespace"),
        "created_at": metadata.get("creationTimestamp"),
        "alert_name": alert.get("alert", ""),
        "expression": alert.get("expr", ""),
        "duration": alert.get("for", "0s"),
        "severity": labels.get("severity", "warning"),
        "summary": annotations.get("summary", ""),
        "description": annotations.get("description", ""),
        "created_by": labels.get("created_by", ""),
        "can_edit": can_modify,
        "can_delete": can_modify,
        "labels": visible_labels,
        "custom_labels": custom_labels,
        "notification_destination_id": labels.get("portal_destination"),
        "custom_label_name": first_custom_label[0],
        "custom_label_value": first_custom_label[1],
    }


def _write_audit(
    *,
    user: AuthenticatedUser,
    action: str,
    rule_name: str,
    alert_name: str,
    severity: str | None = None,
    labels: dict | None = None,
    notification_destination_id: str | None = None,
) -> None:
    """Record a successful rule change without logging credentials."""
    try:
        record_audit_event(
            action=action,
            actor_user_id=user.id,
            target_type="prometheusrule",
            target_id=rule_name,
            details={
                "namespace": "alert-portal-rules",
                "alert_name": alert_name,
                "severity": severity,
                "labels": labels or {},
                "notification_destination_id": notification_destination_id,
            },
        )
    except psycopg.Error:
        raise HTTPException(
            status_code=503,
            detail=(
                "The Kubernetes change was applied, but its audit entry "
                "could not be saved. Check the rule list before retrying."
            ),
        ) from None


@router.get("")
def list_rules(
    user: AuthenticatedUser = Depends(get_current_user),
):
    """List portal-managed alert rules for any signed-in user."""
    rules = _call_service(list_portal_rules)
    return {"items": [_serialize_rule(rule, user=user) for rule in rules]}


@router.post("/validate-expression")
def validate_expression(
    payload: PromQLValidationPayload,
    user: AuthenticatedUser = Depends(require_roles("admin", "editor")),
    csrf_user: AuthenticatedUser = Depends(require_valid_csrf),
):
    """Evaluate PromQL against Prometheus without creating or changing a rule."""
    expression = payload.expression.strip()
    if not expression:
        return {
            "valid": False,
            "kind": "invalid",
            "message": "PromQL expression is required.",
            "result_type": None,
            "result_count": 0,
            "has_results": False,
        }

    try:
        return validate_promql_expression(expression)
    except PrometheusValidationUnavailable:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Prometheus is unavailable or the query timed out. "
                "Try validating the expression again shortly."
            ),
        ) from None


@router.get("/template-options")
def list_template_options(
    user: AuthenticatedUser = Depends(require_roles("admin", "editor")),
):
    """Return live Prometheus targets for built-in PromQL templates."""
    try:
        return get_promql_template_options()
    except PrometheusTemplateOptionsUnavailable:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Prometheus target choices are temporarily unavailable. "
                "You can still generate a template query without target filters."
            ),
        ) from None


@router.get("/{name}")
def read_rule(
    name: str,
    user: AuthenticatedUser = Depends(get_current_user),
):
    """Return one portal-managed rule."""
    rule = _call_service(get_portal_rule, name)
    return _serialize_rule(rule, user=user)


def _resolve_notification_destination(
    destination_id: str | None,
    user: AuthenticatedUser,
    *,
    existing_rule_name: str | None = None,
    existing_destination_id: str | None = None,
) -> str | None:
    """Accept only an owned destination, except preserving the rule's existing foreign destination."""
    if destination_id is None or not destination_id.strip():
        return None
    try:
        canonical_id = canonical_destination_id(destination_id)
        get_user_destination(canonical_id, user.id)
        return canonical_id
    except DestinationValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    except DestinationNotFoundError:
        # A shared rule may already use another user's channel. Fetch the current
        # rule only in this case and permit the exact same ID to remain selected.
        if existing_rule_name and not existing_destination_id:
            current = _call_service(get_portal_rule, existing_rule_name)
            existing_destination_id = _serialize_rule(current)["notification_destination_id"]
        if existing_destination_id:
            try:
                existing_id = canonical_destination_id(existing_destination_id)
            except DestinationValidationError:
                existing_id = None
            if existing_id is not None and secrets.compare_digest(canonical_id, existing_id):
                return existing_id
        raise HTTPException(
            status_code=403,
            detail="Choose a Mattermost destination registered to your account.",
        ) from None
    except psycopg.Error:
        raise HTTPException(
            status_code=503,
            detail="Mattermost destination service temporarily unavailable.",
        ) from None


@router.post("", status_code=status.HTTP_201_CREATED)
def create_rule(
    payload: AlertRulePayload,
    user: AuthenticatedUser = Depends(require_roles("admin", "editor")),
    csrf_user: AuthenticatedUser = Depends(require_valid_csrf),
):
    """Create a new rule and assign its creator from the authenticated user."""
    destination_id = _resolve_notification_destination(
        payload.notification_destination_id, user
    )
    rule = _call_service(
        create_portal_rule,
        alert_name=payload.alert_name,
        expression=payload.expression,
        duration=payload.duration,
        severity=payload.severity,
        summary=payload.summary,
        description=payload.description,
        created_by=user.username,
        owner_user_id=user.id,
        custom_labels=payload.custom_labels,
        custom_label_name=payload.custom_label_name,
        custom_label_value=payload.custom_label_value,
        notification_destination_id=destination_id,
    )

    result = _serialize_rule(rule, user=user)

    _write_audit(
        user=user,
        action="alert_rule_created",
        rule_name=result["name"],
        alert_name=result["alert_name"],
        severity=result["severity"],
        labels=result["labels"],
        notification_destination_id=result["notification_destination_id"],
    )

    return result


@router.put("/{name}")
def edit_rule(
    name: str,
    payload: AlertRulePayload,
    user: AuthenticatedUser = Depends(require_roles("admin", "editor")),
    csrf_user: AuthenticatedUser = Depends(require_valid_csrf),
):
    """Update a portal-managed rule while retaining its original creator."""
    update_arguments = {
        "name": name,
        "alert_name": payload.alert_name,
        "expression": payload.expression,
        "duration": payload.duration,
        "severity": payload.severity,
        "summary": payload.summary,
        "description": payload.description,
        "custom_labels": payload.custom_labels,
        "custom_label_name": payload.custom_label_name,
        "custom_label_value": payload.custom_label_value,
        "actor_user_id": user.id,
        "actor_role": user.role,
    }
    if "notification_destination_id" in payload.model_fields_set:
        update_arguments["notification_destination_id"] = _resolve_notification_destination(
            payload.notification_destination_id,
            user,
            existing_rule_name=name,
        )
    # Older clients omit this field; update_portal_rule preserves the existing
    # routing labels instead of inadvertently turning notifications off.
    rule = _call_service(update_portal_rule, **update_arguments)

    result = _serialize_rule(rule, user=user)

    _write_audit(
        user=user,
        action="alert_rule_updated",
        rule_name=result["name"],
        alert_name=result["alert_name"],
        severity=result["severity"],
        labels=result["labels"],
        notification_destination_id=result["notification_destination_id"],
    )

    return result


@router.delete("/{name}")
def remove_rule(
    name: str,
    user: AuthenticatedUser = Depends(require_roles("admin", "editor")),
    csrf_user: AuthenticatedUser = Depends(require_valid_csrf),
):
    """Delete a rule only if it is managed by the portal."""
    existing = _call_service(get_portal_rule, name)
    result = _serialize_rule(existing, user=user)

    _call_service(
        delete_portal_rule,
        name,
        actor_user_id=user.id,
        actor_role=user.role,
    )

    _write_audit(
        user=user,
        action="alert_rule_deleted",
        rule_name=name,
        alert_name=result["alert_name"],
        severity=result["severity"],
        labels=result["labels"],
    )

    return {"deleted": True, "name": name}