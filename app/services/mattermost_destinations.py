"""Mattermost bot destinations and authenticated Alertmanager forwarding.

All messages are posted through one dedicated Mattermost bot account with the
Mattermost REST API. User-owned destinations store channel metadata only; no
incoming-webhook URLs or bot tokens are stored in PostgreSQL.
"""

from __future__ import annotations

import json
import os
import re
import ssl
import uuid
from datetime import datetime
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPSHandler, HTTPRedirectHandler, Request, build_opener
from zoneinfo import ZoneInfo

import psycopg

from app.services.database import get_database_connection


_NAME_MAX = 80
_ALERT_COUNT_MAX = 2000
_ALERT_TEXT_MAX = 10_000
_API_BODY_MAX = 2_000_000
_LEGACY_ROUTE_KEYS = ("cpu", "disk", "memory", "uptime")
_CHANNEL_ID_RE = re.compile(r"^[A-Za-z0-9]{20,32}$")


class DestinationValidationError(ValueError):
    """Input or Alertmanager payload failed validation."""


class DestinationNotFoundError(LookupError):
    """The destination does not exist or is not owned by this user."""


class DestinationConflictError(RuntimeError):
    """A destination name/channel is duplicated or a destination is in use."""


class DestinationConfigurationError(RuntimeError):
    """Required Mattermost bot/API security configuration is missing or invalid."""


class MattermostDeliveryError(RuntimeError):
    """Mattermost could not accept the notification."""


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def canonical_destination_id(value: str) -> str:
    """Validate a destination UUID and return its canonical string form."""
    if not isinstance(value, str):
        raise DestinationValidationError("Destination ID must be text.")
    try:
        return str(uuid.UUID(value))
    except (ValueError, AttributeError, TypeError) as exc:
        raise DestinationValidationError("Destination ID is invalid.") from exc


def _canonical_hostname(hostname: str) -> str:
    try:
        canonical = hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except (UnicodeError, AttributeError) as exc:
        raise DestinationConfigurationError("Mattermost server hostname is invalid.") from exc
    if not canonical or any(char in canonical for char in " /\\\t\r\n") or ":" in canonical:
        raise DestinationConfigurationError("Mattermost server hostname is invalid.")
    return canonical


def _allowed_host_keys() -> set[str]:
    raw = os.getenv("MATTERMOST_ALLOWED_HOSTS", "")
    if not raw.strip():
        raise DestinationConfigurationError(
            "No Mattermost server hostnames have been approved by an administrator."
        )
    allowed: set[str] = set()
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        if "://" in entry or any(char in entry for char in "/\\@?#"):
            raise DestinationConfigurationError(
                "Mattermost host allowlist must contain exact hostnames, optionally with ports."
            )
        try:
            parsed = urlsplit("//" + entry)
            hostname = parsed.hostname
            port = parsed.port
        except ValueError as exc:
            raise DestinationConfigurationError(
                "Mattermost host allowlist contains an invalid entry."
            ) from exc
        if not hostname or parsed.path or parsed.query or parsed.fragment:
            raise DestinationConfigurationError("Mattermost host allowlist contains an invalid entry.")
        host = _canonical_hostname(hostname)
        allowed.add(host if port in (None, 443) else f"{host}:{port}")
    if not allowed:
        raise DestinationConfigurationError("No Mattermost server hostnames have been approved by an administrator.")
    return allowed


def _mattermost_base_url() -> tuple[str, str]:
    raw = os.getenv("MATTERMOST_BASE_URL", "").strip()
    if not raw or any(ord(char) < 32 or ord(char) == 127 for char in raw):
        raise DestinationConfigurationError("Mattermost API base URL is not configured.")
    try:
        parsed = urlsplit(raw)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise DestinationConfigurationError("Mattermost API base URL is invalid.") from exc
    if (
        parsed.scheme.lower() != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise DestinationConfigurationError(
            "Mattermost API base URL must be HTTPS and contain only the server origin."
        )
    host = _canonical_hostname(hostname)
    effective_port = 443 if port is None else port
    host_key = host if effective_port == 443 else f"{host}:{effective_port}"
    if host_key not in _allowed_host_keys():
        raise DestinationConfigurationError(
            "Mattermost API server is not present in the administrator-approved host allowlist."
        )
    authority = host if effective_port == 443 else f"{host}:{effective_port}"
    return f"https://{authority}", host_key


def _bot_token() -> str:
    token = os.getenv("MATTERMOST_BOT_TOKEN", "").strip()
    if not token or len(token) > 4096 or any(ord(char) < 33 or ord(char) == 127 for char in token):
        raise DestinationConfigurationError("Mattermost bot access token is not configured correctly.")
    return token


def _mattermost_api_request(
    method: str,
    path: str,
    *,
    payload: dict[str, Any] | None = None,
    delivery: bool = False,
) -> Any:
    """Call a fixed Mattermost API path without following redirects or logging secrets."""
    base_url, _ = _mattermost_base_url()
    token = _bot_token()
    if not path.startswith("/") or path.startswith("//") or ".." in path.split("/"):
        raise DestinationConfigurationError("Mattermost API path is invalid.")
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8") if payload is not None else None
    request = Request(
        f"{base_url}/api/v4{path}",
        data=body,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "Alert-Portal/0.1.20",
        },
        method=method,
    )
    opener = build_opener(
        _NoRedirectHandler(),
        HTTPSHandler(context=ssl.create_default_context()),
    )
    try:
        with opener.open(request, timeout=8) as response:
            raw = response.read(_API_BODY_MAX + 1)
            if len(raw) > _API_BODY_MAX:
                if delivery:
                    raise MattermostDeliveryError("Mattermost API response exceeded the size limit.")
                raise DestinationConfigurationError("Mattermost API response exceeded the size limit.")
            if not raw:
                return None
            try:
                return json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                if delivery:
                    raise MattermostDeliveryError("Mattermost API returned an invalid response.") from None
                raise DestinationConfigurationError("Mattermost API returned an invalid response.") from None
    except HTTPError as exc:
        if delivery:
            raise MattermostDeliveryError(f"Mattermost API returned HTTP {exc.code}.") from None
        raise DestinationConfigurationError(
            "Mattermost API rejected the bot credentials or the bot lacks required access."
        ) from None
    except (URLError, TimeoutError, OSError, ssl.SSLError) as exc:
        if delivery:
            raise MattermostDeliveryError(
                "Mattermost could not be reached or did not complete the notification request."
            ) from None
        raise DestinationConfigurationError(
            "Mattermost API could not be reached. Verify the server and bot configuration."
        ) from None


def _bot_identity() -> dict[str, str]:
    user = _mattermost_api_request("GET", "/users/me")
    if not isinstance(user, dict) or not user.get("id"):
        raise DestinationConfigurationError("Mattermost did not return a valid bot identity.")
    if user.get("is_bot") is not True:
        raise DestinationConfigurationError(
            "The configured Mattermost access token does not belong to a bot account."
        )
    return {
        "id": str(user["id"]),
        "username": str(user.get("username") or "Alert Portal Bot"),
        "display_name": str(user.get("display_name") or user.get("username") or "Alert Portal Bot"),
    }


def list_mattermost_channels() -> dict[str, Any]:
    """Return standard channels the configured bot belongs to, excluding DMs/group chats."""
    bot = _bot_identity()
    user_id = quote(bot["id"], safe="")
    teams: list[dict[str, Any]] = []
    page = 0
    per_page = 200
    while page < 20:
        params = urlencode({"page": page, "per_page": per_page})
        batch = _mattermost_api_request("GET", f"/users/{user_id}/teams?{params}")
        if not isinstance(batch, list):
            raise DestinationConfigurationError("Mattermost returned an invalid team list.")
        teams.extend(team for team in batch if isinstance(team, dict))
        if len(batch) < per_page:
            break
        page += 1
    if page >= 20:
        raise DestinationConfigurationError("Mattermost returned too many teams for the bot account.")

    items: list[dict[str, str]] = []
    for team in teams:
        team_id = str(team.get("id") or "")
        if not team_id:
            continue
        team_name = str(team.get("display_name") or team.get("name") or team_id)
        escaped_team_id = quote(team_id, safe="")
        channels = _mattermost_api_request(
            "GET", f"/users/{user_id}/teams/{escaped_team_id}/channels"
        )
        if not isinstance(channels, list):
            raise DestinationConfigurationError("Mattermost returned an invalid channel list.")
        for channel in channels:
            if not isinstance(channel, dict) or not channel.get("id"):
                continue
            if channel.get("delete_at") not in (None, 0, "0"):
                continue
            channel_type = channel.get("type")
            if channel_type not in ("O", "P"):
                continue
            channel_id = str(channel["id"])
            if not _CHANNEL_ID_RE.fullmatch(channel_id):
                continue
            items.append({
                "id": channel_id,
                "channel_id": channel_id,
                "team_id": team_id,
                "team_name": team_name,
                "channel_name": str(channel.get("name") or channel_id),
                "display_name": str(channel.get("display_name") or channel.get("name") or channel_id),
                "type": "public" if channel_type == "O" else "private",
            })

    # A channel should be returned once even if the API yields overlapping memberships.
    unique = {item["id"]: item for item in items}
    return {
        "bot": {"username": bot["username"], "display_name": bot["display_name"]},
        "items": sorted(
            unique.values(),
            key=lambda item: (item["team_name"].casefold(), item["display_name"].casefold()),
        ),
    }


def _normalize_name(name: str) -> str:
    if not isinstance(name, str):
        raise DestinationValidationError("Destination name must be text.")
    normalized = name.strip()
    if not normalized or len(normalized) > _NAME_MAX:
        raise DestinationValidationError("Destination name is required and must be at most 80 characters.")
    if any(ord(char) < 32 or ord(char) == 127 for char in normalized):
        raise DestinationValidationError("Destination name cannot contain control characters.")
    return normalized


def _destination_row(row) -> dict[str, Any]:
    if row is None:
        raise DestinationNotFoundError("Mattermost destination was not found.")
    return {
        "id": str(row[0]),
        "name": row[1],
        "server_host": row[2],
        "team_id": row[3],
        "team_name": row[4],
        "channel_id": row[5],
        "channel_name": row[6],
        "created_at": row[7].isoformat() if row[7] is not None else None,
    }


def _destination_select() -> str:
    return """
        SELECT id::text, name, server_host, team_id, team_name,
               channel_id, channel_name, created_at
        FROM mattermost_bot_destinations
    """


def create_user_destination(*, user_id: int, name: str, channel_id: str) -> dict[str, Any]:
    """Register a channel available to the shared bot; no token/channel URL is persisted."""
    normalized_name = _normalize_name(name)
    if not isinstance(channel_id, str) or not _CHANNEL_ID_RE.fullmatch(channel_id):
        raise DestinationValidationError("Select a valid Mattermost channel from the list.")

    channel_data = list_mattermost_channels()
    selected = next((item for item in channel_data["items"] if item["id"] == channel_id), None)
    if selected is None:
        raise DestinationValidationError(
            "The selected channel is not available to Alert Portal Bot. Add the bot to that channel and refresh."
        )
    _, server_host = _mattermost_base_url()
    destination_id = str(uuid.uuid4())
    try:
        with get_database_connection() as connection:
            row = connection.execute(
                """
                INSERT INTO mattermost_bot_destinations (
                    id, owner_user_id, name, server_host, team_id, team_name,
                    channel_id, channel_name
                )
                VALUES (%s::uuid, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id::text, name, server_host, team_id, team_name,
                          channel_id, channel_name, created_at
                """,
                (
                    destination_id, user_id, normalized_name, server_host,
                    selected["team_id"], selected["team_name"], selected["channel_id"],
                    selected["display_name"],
                ),
            ).fetchone()
    except psycopg.errors.UniqueViolation as exc:
        raise DestinationConflictError(
            "A destination with that name or channel already exists in your account."
        ) from exc
    return _destination_row(row)


def list_user_destinations(user_id: int) -> list[dict[str, Any]]:
    """List only the authenticated user's registered channels."""
    with get_database_connection() as connection:
        rows = connection.execute(
            _destination_select() + " WHERE owner_user_id = %s ORDER BY lower(name), created_at",
            (user_id,),
        ).fetchall()
    return [_destination_row(row) for row in rows]


def get_user_destination(destination_id: str, user_id: int) -> dict[str, Any]:
    """Read metadata only when the destination is owned by the requesting user."""
    canonical_id = canonical_destination_id(destination_id)
    with get_database_connection() as connection:
        row = connection.execute(
            _destination_select() + " WHERE id = %s::uuid AND owner_user_id = %s",
            (canonical_id, user_id),
        ).fetchone()
    return _destination_row(row)


def get_destination_for_delivery(
    *, destination_id: str | None = None, legacy_route: str | None = None
) -> dict[str, Any]:
    """Resolve a portal destination or a system-wide legacy-route mapping."""
    if destination_id:
        canonical_id = canonical_destination_id(destination_id)
        with get_database_connection() as connection:
            row = connection.execute(
                _destination_select() + " WHERE id = %s::uuid",
                (canonical_id,),
            ).fetchone()
        return _destination_row(row)

    if legacy_route not in _LEGACY_ROUTE_KEYS:
        raise DestinationValidationError("Alert route is not supported for legacy routing.")
    with get_database_connection() as connection:
        row = connection.execute(
            """
            SELECT d.id::text, d.name, d.server_host, d.team_id, d.team_name,
                   d.channel_id, d.channel_name, d.created_at
            FROM mattermost_bot_route_mappings AS m
            JOIN mattermost_bot_destinations AS d ON d.id = m.destination_id
            WHERE m.route_key = %s
            """,
            (legacy_route,),
        ).fetchone()
    if row is None:
        raise DestinationNotFoundError(
            f"The default Mattermost channel for the {legacy_route.upper()} route is not configured."
        )
    return _destination_row(row)


def delete_user_destination(destination_id: str, user_id: int) -> dict[str, Any]:
    """Delete an owned channel destination unless a global route mapping references it."""
    canonical_id = canonical_destination_id(destination_id)
    try:
        with get_database_connection() as connection:
            row = connection.execute(
                """
                DELETE FROM mattermost_bot_destinations
                WHERE id = %s::uuid AND owner_user_id = %s
                RETURNING id::text, name, server_host, team_id, team_name,
                          channel_id, channel_name, created_at
                """,
                (canonical_id, user_id),
            ).fetchone()
    except psycopg.errors.ForeignKeyViolation as exc:
        raise DestinationConflictError(
            "This destination is assigned to an existing Alertmanager route and cannot be deleted."
        ) from exc
    return _destination_row(row)


def is_destination_used_in_legacy_routes(destination_id: str) -> bool:
    canonical_id = canonical_destination_id(destination_id)
    with get_database_connection() as connection:
        row = connection.execute(
            "SELECT 1 FROM mattermost_bot_route_mappings WHERE destination_id = %s::uuid LIMIT 1",
            (canonical_id,),
        ).fetchone()
    return row is not None


def list_legacy_route_mappings() -> list[dict[str, Any]]:
    """Return current system-wide channel assignments for existing CPU/Disk/Memory/Uptime routes."""
    with get_database_connection() as connection:
        rows = connection.execute(
            """
            SELECT m.route_key, d.id::text, d.name, d.server_host, d.team_id,
                   d.team_name, d.channel_id, d.channel_name, d.created_at
            FROM mattermost_bot_route_mappings AS m
            JOIN mattermost_bot_destinations AS d ON d.id = m.destination_id
            ORDER BY m.route_key
            """
        ).fetchall()
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        dest = _destination_row(row[1:])
        result[row[0]] = dest
    return [{"route_key": key, **result[key]} for key in sorted(result)]


def update_legacy_route_mappings(*, admin_user_id: int, routes: dict[str, str]) -> list[dict[str, Any]]:
    """Atomically set all four legacy mappings using destinations owned by the admin."""
    if not isinstance(routes, dict) or set(routes.keys()) != set(_LEGACY_ROUTE_KEYS):
        raise DestinationValidationError(
            "Specify destinations for all four existing routes: cpu, disk, memory, and uptime."
        )
    normalized = {key: canonical_destination_id(value) for key, value in routes.items()}
    with get_database_connection() as connection:
        for key in _LEGACY_ROUTE_KEYS:
            row = connection.execute(
                "SELECT id FROM mattermost_bot_destinations WHERE id = %s::uuid AND owner_user_id = %s",
                (normalized[key], admin_user_id),
            ).fetchone()
            if row is None:
                raise DestinationNotFoundError(
                    "Each default route must use a Mattermost destination registered by the administrator."
                )
        for key in _LEGACY_ROUTE_KEYS:
            connection.execute(
                """
                INSERT INTO mattermost_bot_route_mappings (route_key, destination_id, updated_by_user_id)
                VALUES (%s, %s::uuid, %s)
                ON CONFLICT (route_key) DO UPDATE SET
                    destination_id = EXCLUDED.destination_id,
                    updated_by_user_id = EXCLUDED.updated_by_user_id,
                    updated_at = NOW()
                """,
                (key, normalized[key], admin_user_id),
            )
        connection.commit()
    return list_legacy_route_mappings()


def _safe_text(value: Any, maximum: int = 1000) -> str:
    if value is None:
        return ""
    text = str(value)
    text = "".join(char if char in "\n\t" or ord(char) >= 32 else " " for char in text)
    # Prevent alert annotations from invoking Mattermost @here/@channel mentions.
    text = text.replace("@", "@\u200b")
    return text[:maximum]


def _format_tehran_time(value: Any) -> str:
    raw = _safe_text(value, 64)
    if not raw or raw.startswith("0001-"):
        return ""
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=ZoneInfo("UTC"))
        return parsed.astimezone(ZoneInfo("Asia/Tehran")).strftime("%a, %d %b %Y %H:%M:%S %Z")
    except (ValueError, TypeError):
        return raw


def parse_alertmanager_notification(
    payload: dict[str, Any]
) -> tuple[str, str | None, str]:
    """Validate the route labels and create a safe Mattermost Markdown message."""
    if not isinstance(payload, dict):
        raise DestinationValidationError("Alertmanager payload must be a JSON object.")
    alerts = payload.get("alerts")
    if not isinstance(alerts, list) or not alerts or len(alerts) > _ALERT_COUNT_MAX:
        raise DestinationValidationError("Alertmanager payload contains an invalid alert list.")

    route_keys: set[str] = set()
    destination_ids: set[str] = set()
    alert_items: list[tuple[dict[str, Any], dict[str, Any], dict[str, Any]]] = []
    for alert in alerts:
        if not isinstance(alert, dict):
            raise DestinationValidationError("Alertmanager alert entry is invalid.")
        labels = alert.get("labels")
        annotations = alert.get("annotations")
        if not isinstance(labels, dict) or not isinstance(annotations, dict):
            raise DestinationValidationError("Alertmanager alert labels or annotations are invalid.")
        route_key = labels.get("alert_route")
        if route_key not in ("portal", *_LEGACY_ROUTE_KEYS):
            raise DestinationValidationError("Alert is not marked for a supported notification route.")
        route_keys.add(route_key)
        if route_key == "portal":
            destination_ids.add(canonical_destination_id(labels.get("portal_destination")))
        alert_items.append((alert, labels, annotations))

    if len(route_keys) != 1:
        raise DestinationValidationError("A notification group must contain only one alert route.")
    route_key = next(iter(route_keys))
    destination_id: str | None = None
    if route_key == "portal":
        if len(destination_ids) != 1:
            raise DestinationValidationError(
                "A portal notification group must contain exactly one Mattermost destination."
            )
        destination_id = next(iter(destination_ids))

    overall_status = _safe_text(payload.get("status", "firing"), 16).upper()
    if overall_status not in {"FIRING", "RESOLVED"}:
        raise DestinationValidationError("Alertmanager status is invalid.")

    label = "Alert Portal" if route_key == "portal" else f"{route_key.upper()} alert route"
    lines = [f"**{label} — {overall_status}**"]
    for alert, labels, annotations in alert_items:
        name = _safe_text(labels.get("alertname", "UnnamedAlert"), 160) or "UnnamedAlert"
        severity = _safe_text(labels.get("severity", "unknown"), 40) or "unknown"
        item_status = _safe_text(alert.get("status", overall_status.lower()), 16).upper()
        lines.append(f"\n**{name}** — {item_status} · severity: {severity}")
        summary = _safe_text(annotations.get("summary", ""), 700)
        description = _safe_text(annotations.get("description", ""), 1000)
        if summary:
            lines.append(summary)
        if description and description != summary:
            lines.append(description)

        owner = _safe_text(labels.get("owner"), 160)
        if owner:
            lines.append(f"Owner: {owner}")
        context = []
        for key in ("cluster", "namespace", "job", "instance", "hostname", "mountpoint", "volume"):
            value = _safe_text(labels.get(key), 160)
            if value:
                context.append(f"{key}={value}")
        if context:
            lines.append("`" + " · ".join(context) + "`")

        starts_at = _format_tehran_time(alert.get("startsAt"))
        ends_at = _format_tehran_time(alert.get("endsAt"))
        if starts_at:
            lines.append(f"Started at: {starts_at}")
        if item_status == "RESOLVED" and ends_at:
            lines.append(f"Ended at: {ends_at}")

    message = "\n".join(lines)
    if len(message) > _ALERT_TEXT_MAX:
        message = message[: _ALERT_TEXT_MAX - 20] + "\n… message truncated"
    return route_key, destination_id, message


def _post_to_mattermost(channel_id: str, message: str) -> None:
    """Post as the configured bot account using Mattermost's Create Post API."""
    if not isinstance(channel_id, str) or not _CHANNEL_ID_RE.fullmatch(channel_id):
        raise DestinationConfigurationError("Configured Mattermost channel ID is invalid.")
    # Fail closed if an administrator accidentally configures a human user's token.
    _bot_identity()
    _mattermost_api_request(
        "POST",
        "/posts",
        payload={"channel_id": channel_id, "message": message},
        delivery=True,
    )


def forward_alertmanager_notification(payload: dict[str, Any]) -> dict[str, str]:
    """Resolve a selected portal destination or legacy route and post as one bot."""
    route_key, destination_id, message = parse_alertmanager_notification(payload)
    if route_key == "portal":
        destination = get_destination_for_delivery(destination_id=destination_id)
    else:
        destination = get_destination_for_delivery(legacy_route=route_key)
    _post_to_mattermost(destination["channel_id"], message)
    result = {"status": "delivered", "destination_id": destination["id"]}
    if route_key != "portal":
        result["legacy_route"] = route_key
    return result


def legacy_route_keys() -> tuple[str, ...]:
    """Export a stable tuple for route/UI tests and consumers."""
    return _LEGACY_ROUTE_KEYS
