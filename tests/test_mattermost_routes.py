import os
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.auth.dependencies import AuthenticatedUser, get_current_user
from app.main import app
from app.routes.rules import require_valid_csrf


ADMIN = AuthenticatedUser(id=1, username="admin-user", role="admin")
VIEWER = AuthenticatedUser(id=3, username="viewer-user", role="viewer")


def setup_client(user=ADMIN):
    app.dependency_overrides.clear()
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[require_valid_csrf] = lambda: user
    return TestClient(app)


def teardown_client(client):
    client.close()
    app.dependency_overrides.clear()


def test_alertmanager_forward_endpoint_rejects_missing_or_wrong_bearer(monkeypatch):
    monkeypatch.setenv("ALERTMANAGER_WEBHOOK_TOKEN", "token-for-test")
    client = setup_client()
    try:
        with patch("app.routes.mattermost.forward_alertmanager_notification") as forward:
            no_auth = client.post("/api/alertmanager/notify", json={})
            wrong_auth = client.post(
                "/api/alertmanager/notify",
                json={},
                headers={"Authorization": "Bearer wrong-token"},
            )
        assert no_auth.status_code == 401
        assert wrong_auth.status_code == 401
        forward.assert_not_called()
    finally:
        teardown_client(client)


def test_alertmanager_forward_endpoint_requires_configured_token(monkeypatch):
    monkeypatch.delenv("ALERTMANAGER_WEBHOOK_TOKEN", raising=False)
    client = setup_client()
    try:
        response = client.post("/api/alertmanager/notify", json={})
        assert response.status_code == 503
    finally:
        teardown_client(client)


def test_alertmanager_forward_endpoint_forwards_authenticated_payload(monkeypatch):
    monkeypatch.setenv("ALERTMANAGER_WEBHOOK_TOKEN", "token-for-test")
    client = setup_client()
    payload = {"receiver": "monitoring/mattermost-uptime/uptime", "alerts": []}
    try:
        with patch(
            "app.routes.mattermost.forward_alertmanager_notification",
            return_value={"status": "delivered", "destination_id": "abc"},
        ) as forward:
            response = client.post(
                "/api/alertmanager/notify",
                json=payload,
                headers={"Authorization": "Bearer token-for-test"},
            )
        assert response.status_code == 200
        assert response.json()["status"] == "delivered"
        forward.assert_called_once_with(payload)
    finally:
        teardown_client(client)


def test_destination_list_exposes_channel_metadata_but_no_token_or_webhook_url():
    client = setup_client()
    safe_item = {
        "id": "13c10bc8-f32d-4d32-8dcf-634798befb4a",
        "name": "Uptime alerts",
        "server_host": "chat.example.com",
        "team_id": "team12345678901234567890",
        "team_name": "Alerts",
        "channel_id": "abcdefghij1234567890123456",
        "channel_name": "Uptime",
        "created_at": "2026-10-25T00:00:00+00:00",
    }
    try:
        with patch("app.routes.mattermost.list_user_destinations", return_value=[safe_item]):
            response = client.get("/api/destinations")
        assert response.status_code == 200
        assert response.json()["items"] == [safe_item]
        assert "token-for-test" not in response.text
        assert "hooks/" not in response.text
    finally:
        teardown_client(client)


def test_channel_listing_requires_login(monkeypatch):
    app.dependency_overrides.clear()
    client = TestClient(app)
    try:
        # No session overrides: the API must return an authentication error.
        with patch("app.routes.mattermost.list_mattermost_channels") as channels:
            response = client.get("/api/mattermost/channels")
        assert response.status_code == 401
        channels.assert_not_called()
    finally:
        client.close()
        app.dependency_overrides.clear()


def test_viewer_cannot_configure_legacy_routes():
    client = setup_client(VIEWER)
    try:
        with patch("app.routes.mattermost.update_legacy_route_mappings") as update:
            response = client.put(
                "/api/mattermost/legacy-routes",
                json={"routes": {"cpu": "x", "disk": "x", "memory": "x", "uptime": "x"}},
            )
        assert response.status_code == 403
        update.assert_not_called()
    finally:
        teardown_client(client)


def test_alertmanager_forward_endpoint_rejects_oversized_request(monkeypatch):
    monkeypatch.setenv("ALERTMANAGER_WEBHOOK_TOKEN", "token-for-test")
    client = setup_client()
    try:
        with patch("app.routes.mattermost.forward_alertmanager_notification") as forward:
            response = client.post(
                "/api/alertmanager/notify",
                content=b"x" * (4_194_304 + 1),
                headers={"Authorization": "Bearer token-for-test"},
            )
        assert response.status_code == 413
        forward.assert_not_called()
    finally:
        teardown_client(client)