from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
import uuid

import pytest

from app.services.mattermost_destinations import (
    DestinationConfigurationError,
    DestinationConflictError,
    DestinationNotFoundError,
    DestinationValidationError,
    create_user_destination,
    forward_alertmanager_notification,
    list_mattermost_channels,
    parse_alertmanager_notification,
    update_legacy_route_mappings,
    _bot_identity,
    _mattermost_base_url,
    _post_to_mattermost,
)


DESTINATION_ID = "13c10bc8-f32d-4d32-8dcf-634798befb4a"
CHANNEL_ID = "abcdefghij1234567890123456"
CHANNEL_META = {
    "id": CHANNEL_ID,
    "channel_id": CHANNEL_ID,
    "team_id": "team12345678901234567890",
    "team_name": "Alerts",
    "channel_name": "Uptime",
    "display_name": "Uptime",
    "type": "public",
}


def configure_bot(monkeypatch):
    monkeypatch.setenv("MATTERMOST_BASE_URL", "https://mattermost.example.com")
    monkeypatch.setenv("MATTERMOST_ALLOWED_HOSTS", "mattermost.example.com")
    monkeypatch.setenv("MATTERMOST_BOT_TOKEN", "opaque-bot-token-for-tests")


def _alert(route="portal", destination_id=DESTINATION_ID, name="DiskAlmostFull"):
    labels = {
        "alertname": name,
        "alert_route": route,
        "severity": "critical",
        "instance": "node-1:9100",
        "owner": "platform-team",
        "namespace": "monitoring" if route != "portal" else "alert-portal-rules",
    }
    if destination_id:
        labels["portal_destination"] = destination_id
    return {
        "status": "firing",
        "labels": labels,
        "annotations": {
            "summary": "Disk use is high @channel",
            "description": "Check available disk space.",
        },
        "startsAt": "2026-10-25T07:00:00Z",
        "endsAt": "0001-01-01T00:00:00Z",
    }


def test_mattermost_base_url_requires_exact_approved_https_host(monkeypatch):
    configure_bot(monkeypatch)
    assert _mattermost_base_url() == ("https://mattermost.example.com", "mattermost.example.com")

    monkeypatch.setenv("MATTERMOST_BASE_URL", "http://mattermost.example.com")
    with pytest.raises(DestinationConfigurationError):
        _mattermost_base_url()

    monkeypatch.setenv("MATTERMOST_BASE_URL", "https://127.0.0.1")
    with pytest.raises(DestinationConfigurationError):
        _mattermost_base_url()


def test_mattermost_base_url_requires_allowlist(monkeypatch):
    monkeypatch.setenv("MATTERMOST_BASE_URL", "https://mattermost.example.com")
    monkeypatch.delenv("MATTERMOST_ALLOWED_HOSTS", raising=False)
    with pytest.raises(DestinationConfigurationError):
        _mattermost_base_url()


def test_bot_token_must_identify_bot_account(monkeypatch):
    configure_bot(monkeypatch)
    with patch(
        "app.services.mattermost_destinations._mattermost_api_request",
        return_value={"id": "human12345678901234567890", "username": "human", "is_bot": False},
    ):
        with pytest.raises(DestinationConfigurationError, match="does not belong to a bot"):
            _bot_identity()


def test_list_mattermost_channels_returns_only_bot_accessible_standard_channels(monkeypatch):
    configure_bot(monkeypatch)
    team = {"id": "team12345678901234567890", "name": "alerts", "display_name": "Alerts"}
    channels = [
        {"id": CHANNEL_ID, "name": "uptime", "display_name": "Uptime", "type": "O", "delete_at": 0},
        {"id": "bcdefghij1234567890123456", "name": "private", "display_name": "Private channel", "type": "P", "delete_at": 0},
        {"id": "cdefghij1234567890123456", "name": "dm", "display_name": "DM", "type": "D", "delete_at": 0},
        {"id": "defghij1234567890123456", "name": "archived", "display_name": "Archived", "type": "O", "delete_at": 9},
    ]
    with patch(
        "app.services.mattermost_destinations._mattermost_api_request",
        side_effect=[
            {"id": "bot12345678901234567890", "username": "alertportalbot", "display_name": "Alert Portal Bot", "is_bot": True},
            [team],
            channels,
        ],
    ) as request:
        result = list_mattermost_channels()

    assert result["bot"]["username"] == "alertportalbot"
    assert [item["display_name"] for item in result["items"]] == ["Private channel", "Uptime"]
    assert all(item["type"] in {"public", "private"} for item in result["items"])
    assert request.call_count == 3


def test_create_destination_persists_channel_metadata_without_any_token(monkeypatch):
    configure_bot(monkeypatch)
    connection = MagicMock()
    connection.execute.return_value.fetchone.return_value = (
        DESTINATION_ID,
        "Uptime notifications",
        "mattermost.example.com",
        CHANNEL_META["team_id"],
        CHANNEL_META["team_name"],
        CHANNEL_ID,
        "Uptime",
        datetime(2026, 10, 25, tzinfo=timezone.utc),
    )
    context = MagicMock()
    context.__enter__.return_value = connection

    with (
        patch("app.services.mattermost_destinations.list_mattermost_channels", return_value={"items": [CHANNEL_META], "bot": {"username": "alertportalbot"}}),
        patch("app.services.mattermost_destinations._mattermost_base_url", return_value=("https://mattermost.example.com", "mattermost.example.com")),
        patch("app.services.mattermost_destinations.get_database_connection", return_value=context),
    ):
        result = create_user_destination(user_id=12, name="Uptime notifications", channel_id=CHANNEL_ID)

    query, parameters = connection.execute.call_args.args
    assert "mattermost_bot_destinations" in query
    assert "channel_id" in query
    assert CHANNEL_ID in parameters
    assert "token" not in parameters
    assert result == {
        "id": DESTINATION_ID,
        "name": "Uptime notifications",
        "server_host": "mattermost.example.com",
        "team_id": CHANNEL_META["team_id"],
        "team_name": "Alerts",
        "channel_id": CHANNEL_ID,
        "channel_name": "Uptime",
        "created_at": "2026-10-25T00:00:00+00:00",
    }


def test_create_destination_rejects_channel_not_available_to_bot(monkeypatch):
    configure_bot(monkeypatch)
    with patch(
        "app.services.mattermost_destinations.list_mattermost_channels",
        return_value={"items": [], "bot": {"username": "alertportalbot"}},
    ):
        with pytest.raises(DestinationValidationError, match="not available to Alert Portal Bot"):
            create_user_destination(user_id=1, name="Uptime", channel_id=CHANNEL_ID)


def test_parse_portal_alert_formats_message_and_suppresses_mentions():
    payload = {"receiver": "alert-portal-forwarder", "status": "firing", "alerts": [_alert()]}
    route_key, destination_id, message = parse_alertmanager_notification(payload)
    assert route_key == "portal"
    assert destination_id == DESTINATION_ID
    assert "DiskAlmostFull" in message
    assert "Check available disk space." in message
    assert "Owner: platform-team" in message
    assert "@\u200bchannel" in message
    assert "Started at:" in message


def test_parse_legacy_route_without_destination_label():
    payload = {"receiver": "monitoring/mattermost-cpu/cpu", "status": "firing", "alerts": [_alert(route="cpu", destination_id=None, name="CpuSaturation") ]}
    route_key, destination_id, message = parse_alertmanager_notification(payload)
    assert route_key == "cpu"
    assert destination_id is None
    assert "CPU alert route" in message
    assert "CpuSaturation" in message


def test_parse_alertmanager_rejects_mixed_routes_or_destinations():
    other_id = str(uuid.uuid4())
    mixed_routes = {"status": "firing", "alerts": [_alert(route="cpu", destination_id=None), _alert(route="memory", destination_id=None)]}
    with pytest.raises(DestinationValidationError, match="only one alert route"):
        parse_alertmanager_notification(mixed_routes)
    mixed_destinations = {"status": "firing", "alerts": [_alert(), _alert(destination_id=other_id)]}
    with pytest.raises(DestinationValidationError, match="exactly one Mattermost destination"):
        parse_alertmanager_notification(mixed_destinations)


def test_parse_alertmanager_rejects_unknown_route():
    with pytest.raises(DestinationValidationError, match="supported notification route"):
        parse_alertmanager_notification({"alerts": [_alert(route="unknown", destination_id=None)]})


def test_forward_portal_notification_posts_to_destination_channel(monkeypatch):
    import app.services.mattermost_destinations as service
    destination = {
        "id": DESTINATION_ID,
        "name": "Uptime notifications",
        "server_host": "mattermost.example.com",
        "team_id": CHANNEL_META["team_id"],
        "team_name": "Alerts",
        "channel_id": CHANNEL_ID,
        "channel_name": "Uptime",
        "created_at": "2026-10-25T00:00:00+00:00",
    }
    payload = {"status": "firing", "alerts": [_alert()]}
    with (
        patch.object(service, "get_destination_for_delivery", return_value=destination) as resolve,
        patch.object(service, "_post_to_mattermost") as post,
    ):
        result = forward_alertmanager_notification(payload)

    assert result == {"status": "delivered", "destination_id": DESTINATION_ID}
    resolve.assert_called_once_with(destination_id=DESTINATION_ID)
    assert post.call_args.args[0] == CHANNEL_ID
    assert "DiskAlmostFull" in post.call_args.args[1]


def test_forward_legacy_notification_uses_admin_route_mapping():
    import app.services.mattermost_destinations as service
    destination = {
        "id": DESTINATION_ID,
        "name": "CPU channel",
        "server_host": "mattermost.example.com",
        "team_id": CHANNEL_META["team_id"],
        "team_name": "Alerts",
        "channel_id": CHANNEL_ID,
        "channel_name": "CPU",
        "created_at": "2026-10-25T00:00:00+00:00",
    }
    payload = {"receiver": "monitoring/mattermost-cpu/cpu", "status": "firing", "alerts": [_alert(route="cpu", destination_id=None)]}
    with (
        patch.object(service, "get_destination_for_delivery", return_value=destination) as resolve,
        patch.object(service, "_post_to_mattermost") as post,
    ):
        result = forward_alertmanager_notification(payload)
    assert result == {"status": "delivered", "destination_id": DESTINATION_ID, "legacy_route": "cpu"}
    resolve.assert_called_once_with(legacy_route="cpu")
    post.assert_called_once_with(CHANNEL_ID, post.call_args.args[1])


def test_update_legacy_route_mappings_requires_owned_destinations():
    connection = MagicMock()
    connection.execute.return_value.fetchone.return_value = (1,)
    context = MagicMock()
    context.__enter__.return_value = connection
    routes = {key: DESTINATION_ID for key in ("cpu", "disk", "memory", "uptime")}
    with (
        patch("app.services.mattermost_destinations.get_database_connection", return_value=context),
        patch("app.services.mattermost_destinations.list_legacy_route_mappings", return_value=[]),
    ):
        result = update_legacy_route_mappings(admin_user_id=10, routes=routes)
    assert result == []
    assert connection.execute.call_count == 8
    connection.commit.assert_called_once()


def test_update_legacy_route_mappings_requires_all_four_routes():
    with pytest.raises(DestinationValidationError, match="all four existing routes"):
        update_legacy_route_mappings(admin_user_id=1, routes={"cpu": DESTINATION_ID})


def test_post_to_mattermost_uses_bot_identity_and_create_post_api(monkeypatch):
    configure_bot(monkeypatch)
    with patch(
        "app.services.mattermost_destinations._mattermost_api_request",
        side_effect=[
            {"id": "bot12345678901234567890", "username": "alertportalbot", "is_bot": True},
            {"id": "post12345678901234567890"},
        ],
    ) as request:
        _post_to_mattermost(CHANNEL_ID, "**Alert**")

    assert request.call_count == 2
    request.assert_any_call("GET", "/users/me")
    request.assert_any_call(
        "POST",
        "/posts",
        payload={"channel_id": CHANNEL_ID, "message": "**Alert**"},
        delivery=True,
    )


def test_rule_spec_adds_backend_managed_destination_labels_and_reserves_custom_route_labels():
    from app.services.prometheus_rules import RuleValidationError, _validated_rule_spec

    spec = _validated_rule_spec(
        alert_name="DestinationSelected",
        expression="vector(1)",
        duration="0s",
        severity="warning",
        summary="A test alert",
        description="",
        created_by="editor-user",
        notification_destination_id=DESTINATION_ID,
    )
    labels = spec["groups"][0]["rules"][0]["labels"]
    assert labels["alert_route"] == "portal"
    assert labels["portal_destination"] == DESTINATION_ID

    for reserved in ("alert_route", "portal_destination"):
        with pytest.raises(RuleValidationError, match="reserved label"):
            _validated_rule_spec(
                alert_name="DestinationSelected",
                expression="vector(1)",
                duration="0s",
                severity="warning",
                summary="A test alert",
                description="",
                custom_labels={reserved: "forged"},
            )
