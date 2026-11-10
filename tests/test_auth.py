"""Authentication, session, and LDAP login regression tests."""

from unittest.mock import MagicMock, patch
from uuid import UUID

import psycopg
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.auth.dependencies import (
    AuthenticatedUser,
    get_user_from_session_token,
    require_roles,
)
from app.auth.ldap_directory import LDAPIdentity, LDAPUnavailable
from app.auth.security import (
    generate_csrf_token,
    generate_session_token,
    hash_csrf_token,
    hash_password,
    hash_session_token,
    verify_password,
)
from app.main import app
from app.services.ldap_users import (
    LDAPAccountConflict,
    LDAPPortalUser,
)


LDAP_GUID = UUID("12345678-1234-5678-90ab-cdef12345678")


@pytest.fixture
def client():
    return TestClient(app)


def _login_connection(account):
    """Fake the consumed login-CSRF row and the account lookup."""
    fake_connection = MagicMock()
    fake_connection.execute.return_value.fetchone.side_effect = [
        ("csrf-token-hash",),
        account,
    ]
    return fake_connection


def _post_login(client, username="test-user", password="Test-Password-8472"):
    return client.post(
        "/login",
        data={
            "csrf_token": generate_csrf_token(),
            "username": username,
            "password": password,
        },
        follow_redirects=False,
    )


def test_liveness_endpoint(client):
    response = client.get("/health/live")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_login_form_renders_with_csrf_and_no_cache(client):
    csrf_token = "known-csrf-token-value-1234567890-abcd"
    fake_connection = MagicMock()

    with (
        patch("app.routes.auth.get_database_connection") as mock_db,
        patch(
            "app.routes.auth.generate_csrf_token",
            return_value=csrf_token,
        ),
    ):
        mock_db.return_value.__enter__.return_value = fake_connection
        response = client.get("/login")

    assert response.status_code == 200
    assert 'name="csrf_token"' in response.text
    assert f'value="{csrf_token}"' in response.text
    assert response.headers.get("cache-control") == "no-store"

    # The login form uses a hidden field, not a CSRF cookie.
    assert response.headers.get_list("set-cookie") == []

    executed_sql = [
        call.args[0]
        for call in fake_connection.execute.call_args_list
    ]
    assert any(
        "DELETE FROM login_csrf_tokens" in sql
        for sql in executed_sql
    )
    assert any(
        "INSERT INTO login_csrf_tokens" in sql
        for sql in executed_sql
    )
    fake_connection.commit.assert_called_once()


def test_unauthenticated_home_redirects_to_login(client):
    response = client.get("/", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers.get("location") == "/login"
    assert response.headers.get("cache-control") == "no-store"


def test_invalid_login_csrf_token_is_rejected(client):
    fake_connection = MagicMock()
    fake_connection.execute.return_value.fetchone.return_value = None

    with patch("app.routes.auth.get_database_connection") as mock_db:
        mock_db.return_value.__enter__.return_value = fake_connection

        response = client.post(
            "/login",
            data={
                "csrf_token": "invalid-csrf-token-value-long-enough-123456",
                "username": "test-user",
                "password": "Correct-Test-Password-8472",
            },
            follow_redirects=False,
        )

    assert response.status_code == 403
    assert "expired or invalid" in response.text
    assert response.headers.get("cache-control") == "no-store"
    fake_connection.commit.assert_called_once()


def test_incorrect_password_is_rejected(client):
    fake_connection = _login_connection(
        (12345, "test-user", "fake-password-hash", "admin", "local", True)
    )

    with (
        patch("app.routes.auth.get_database_connection") as mock_db,
        patch("app.routes.auth.verify_password", return_value=False),
        patch("app.routes.auth.record_audit_event") as audit,
        patch("app.routes.auth.load_ldap_settings") as ldap_settings,
        patch("app.routes.auth.authenticate_ldap") as ldap_auth,
    ):
        mock_db.return_value.__enter__.return_value = fake_connection

        response = _post_login(
            client,
            username="test-user",
            password="Wrong-Test-Password-8472",
        )

    assert response.status_code == 401
    assert "Invalid username or password" in response.text
    assert response.headers.get("cache-control") == "no-store"
    audit.assert_called_once()
    assert audit.call_args.kwargs["action"] == "login_failed"

    # Never try Active Directory after a local-account password failure.
    ldap_settings.assert_not_called()
    ldap_auth.assert_not_called()


def test_successful_login_sets_secure_cookie_attributes(client):
    fake_connection = _login_connection(
        (12345, "test-user", "fake-password-hash", "admin", "local", True)
    )

    with (
        patch("app.routes.auth.get_database_connection") as mock_db,
        patch("app.routes.auth.verify_password", return_value=True),
    ):
        mock_db.return_value.__enter__.return_value = fake_connection

        response = _post_login(
            client,
            username="test-user",
            password="Correct-Test-Password-8472",
        )

    assert response.status_code == 303
    assert response.headers.get("location") == "/"
    assert response.headers.get("cache-control") == "no-store"

    cookies = response.headers.get_list("set-cookie")
    session_cookie = next(
        cookie
        for cookie in cookies
        if cookie.startswith("alert_portal_session=")
    )
    csrf_cookie = next(
        cookie
        for cookie in cookies
        if cookie.startswith("alert_portal_csrf=")
    )

    for cookie in (session_cookie, csrf_cookie):
        assert "httponly" in cookie.lower()
        assert "samesite=lax" in cookie.lower()
        assert "max-age=28800" in cookie.lower()

    # The local test configuration uses HTTP.
    # COOKIE_SECURE must be true for HTTPS production deployment.
    assert "secure" not in session_cookie.lower()

    executed_sql = [
        call.args[0]
        for call in fake_connection.execute.call_args_list
    ]

    assert any("INSERT INTO user_sessions" in sql for sql in executed_sql)
    assert any("UPDATE users" in sql for sql in executed_sql)
    assert any("INSERT INTO audit_log" in sql for sql in executed_sql)

    # The successful-login transaction must be committed.
    assert fake_connection.commit.call_count >= 1


def test_logout_rejects_mismatched_csrf_token(client):
    csrf_cookie = "cookie-csrf-token-value-long-enough-12345"
    submitted_token = "different-form-token-value-long-enough-12345"

    response = client.post(
        "/logout",
        cookies={
            "alert_portal_session": "fake-session-token",
            "alert_portal_csrf": csrf_cookie,
        },
        data={"csrf_token": submitted_token},
        follow_redirects=False,
    )

    assert response.status_code == 403
    assert "Invalid logout request" in response.text
    assert response.headers.get("cache-control") == "no-store"


def test_successful_logout_revokes_session_and_clears_cookies(client):
    session_token = "fake-session-token-for-logout-test"
    csrf_token = "valid-csrf-cookie-token-for-logout-test"

    fake_connection = MagicMock()
    fake_connection.execute.return_value.fetchone.return_value = (12345,)

    with patch("app.routes.auth.get_database_connection") as mock_db:
        mock_db.return_value.__enter__.return_value = fake_connection

        response = client.post(
            "/logout",
            cookies={
                "alert_portal_session": session_token,
                "alert_portal_csrf": csrf_token,
            },
            data={"csrf_token": csrf_token},
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert response.headers.get("location") == "/login"
    assert response.headers.get("cache-control") == "no-store"

    executed_sql = [
        call.args[0]
        for call in fake_connection.execute.call_args_list
    ]

    assert any("UPDATE user_sessions" in sql for sql in executed_sql)
    assert any("INSERT INTO audit_log" in sql for sql in executed_sql)

    # Session revocation and the audit record are committed together.
    assert fake_connection.commit.call_count == 1

    cookies = response.headers.get_list("set-cookie")
    assert any(
        cookie.startswith("alert_portal_session=")
        and "max-age=0" in cookie.lower()
        for cookie in cookies
    )
    assert any(
        cookie.startswith("alert_portal_csrf=")
        and "max-age=0" in cookie.lower()
        for cookie in cookies
    )


def test_missing_session_is_rejected():
    with pytest.raises(HTTPException) as exc_info:
        get_user_from_session_token(None)

    assert exc_info.value.status_code == 401


def test_invalid_session_is_rejected():
    fake_connection = MagicMock()
    fake_connection.execute.return_value.fetchone.return_value = None

    with patch("app.auth.dependencies.get_database_connection") as mock_db:
        mock_db.return_value.__enter__.return_value = fake_connection

        with pytest.raises(HTTPException) as exc_info:
            get_user_from_session_token("invalid-session-token")

    assert exc_info.value.status_code == 401


def test_session_lookup_database_outage_returns_503():
    with patch(
        "app.auth.dependencies.get_database_connection",
        side_effect=psycopg.OperationalError("database unavailable"),
    ):
        with pytest.raises(HTTPException) as exc_info:
            get_user_from_session_token("test-session-token")

    assert exc_info.value.status_code == 503


def test_admin_role_is_accepted():
    user = AuthenticatedUser(id=1, username="admin-user", role="admin")
    checker = require_roles("admin")

    assert checker(user) == user


def test_viewer_is_rejected_by_admin_only_checker():
    user = AuthenticatedUser(id=2, username="viewer-user", role="viewer")
    checker = require_roles("admin")

    with pytest.raises(HTTPException) as exc_info:
        checker(user)

    assert exc_info.value.status_code == 403


def test_password_hashing_and_verification():
    password = "Correct-Test-Password-8472"
    stored_hash = hash_password(password)

    assert stored_hash != password
    assert verify_password(password, stored_hash)
    assert not verify_password("Wrong-Test-Password-8472", stored_hash)


def test_password_hashing_rejects_short_password():
    with pytest.raises(ValueError):
        hash_password("short")


def test_session_and_csrf_tokens_are_generated():
    session_token = generate_session_token()
    csrf_token = generate_csrf_token()

    assert session_token
    assert csrf_token
    assert session_token != csrf_token
    assert hash_session_token(session_token) != session_token
    assert hash_csrf_token(csrf_token) != csrf_token


def test_homepage_session_validation_database_outage_returns_503(client):
    session_token = "test-session-token"
    csrf_token = "test-csrf-token"

    user = AuthenticatedUser(id=12345, username="test-user", role="admin")

    with (
        patch("app.main.get_user_from_session_token", return_value=user),
        patch(
            "app.main.get_database_connection",
            side_effect=psycopg.OperationalError("database unavailable"),
        ),
    ):
        response = client.get(
            "/",
            cookies={
                "alert_portal_session": session_token,
                "alert_portal_csrf": csrf_token,
            },
            follow_redirects=False,
        )

    assert response.status_code == 503
    assert response.json() == {
        "status": "authentication service temporarily unavailable"
    }
    assert response.headers.get("cache-control") == "no-store"


def test_readiness_database_outage_returns_503(client):
    with patch(
        "app.main.get_database_connection",
        side_effect=psycopg.OperationalError("database unavailable"),
    ):
        response = client.get("/health/ready")

    assert response.status_code == 503
    assert response.json() == {"status": "not ready"}


def test_first_ldap_login_creates_session_with_portal_identity(client):
    fake_connection = _login_connection(None)
    ldap_identity = LDAPIdentity(username="ad.user", object_guid=LDAP_GUID)
    portal_user = LDAPPortalUser(id=81, username="ad.user", role="viewer")

    with (
        patch("app.routes.auth.get_database_connection") as mock_db,
        patch("app.routes.auth.load_ldap_settings", return_value=object()),
        patch(
            "app.routes.auth.authenticate_ldap",
            return_value=ldap_identity,
        ) as ldap_auth,
        patch(
            "app.routes.auth.resolve_ldap_portal_user",
            return_value=portal_user,
        ) as provision,
    ):
        mock_db.return_value.__enter__.return_value = fake_connection
        response = _post_login(client, username="ad.user")

    assert response.status_code == 303
    assert response.headers.get("location") == "/"
    ldap_auth.assert_called_once()
    provision.assert_called_once_with(ldap_identity)
    assert any(
        "INSERT INTO user_sessions" in call.args[0]
        and call.args[1][0] == 81
        for call in fake_connection.execute.call_args_list
    )


def test_existing_ldap_user_retains_role_and_portal_id(client):
    fake_connection = _login_connection(
        (22, "ad.user", None, "editor", "ldap", True)
    )
    ldap_identity = LDAPIdentity(username="ad.user", object_guid=LDAP_GUID)

    with (
        patch("app.routes.auth.get_database_connection") as mock_db,
        patch("app.routes.auth.load_ldap_settings", return_value=object()),
        patch("app.routes.auth.authenticate_ldap", return_value=ldap_identity),
        patch(
            "app.routes.auth.resolve_ldap_portal_user",
            return_value=LDAPPortalUser(
                id=22, username="ad.user", role="editor"
            ),
        ),
    ):
        mock_db.return_value.__enter__.return_value = fake_connection
        response = _post_login(client, username="ad.user")

    assert response.status_code == 303
    assert any(
        "INSERT INTO user_sessions" in call.args[0]
        and call.args[1][0] == 22
        for call in fake_connection.execute.call_args_list
    )


def test_failed_ldap_password_does_not_provision_user(client):
    fake_connection = _login_connection(None)

    with (
        patch("app.routes.auth.get_database_connection") as mock_db,
        patch("app.routes.auth.load_ldap_settings", return_value=object()),
        patch("app.routes.auth.authenticate_ldap", return_value=None),
        patch("app.routes.auth.resolve_ldap_portal_user") as provision,
        patch("app.routes.auth.record_audit_event") as audit,
    ):
        mock_db.return_value.__enter__.return_value = fake_connection
        response = _post_login(client, username="ad.user")

    assert response.status_code == 401
    provision.assert_not_called()
    audit.assert_called_once()


def test_missing_ldap_configuration_does_not_break_local_login(client):
    fake_connection = _login_connection(None)

    with (
        patch("app.routes.auth.get_database_connection") as mock_db,
        patch("app.routes.auth.load_ldap_settings", return_value=None),
        patch("app.routes.auth.authenticate_ldap") as ldap_auth,
        patch("app.routes.auth.record_audit_event"),
    ):
        mock_db.return_value.__enter__.return_value = fake_connection
        response = _post_login(client, username="ad.user")

    assert response.status_code == 401
    ldap_auth.assert_not_called()


def test_ldap_outage_returns_503_without_creating_session(client):
    fake_connection = _login_connection(None)

    with (
        patch("app.routes.auth.get_database_connection") as mock_db,
        patch("app.routes.auth.load_ldap_settings", return_value=object()),
        patch(
            "app.routes.auth.authenticate_ldap",
            side_effect=LDAPUnavailable("simulated outage"),
        ),
    ):
        mock_db.return_value.__enter__.return_value = fake_connection
        response = _post_login(client, username="ad.user")

    assert response.status_code == 503
    assert not any(
        "INSERT INTO user_sessions" in call.args[0]
        for call in fake_connection.execute.call_args_list
    )


def test_inactive_ldap_account_cannot_attempt_ad_login(client):
    fake_connection = _login_connection(
        (36, "ad.user", None, "viewer", "ldap", False)
    )

    with (
        patch("app.routes.auth.get_database_connection") as mock_db,
        patch("app.routes.auth.load_ldap_settings") as ldap_settings,
        patch("app.routes.auth.authenticate_ldap") as ldap_auth,
        patch("app.routes.auth.record_audit_event"),
    ):
        mock_db.return_value.__enter__.return_value = fake_connection
        response = _post_login(client, username="ad.user")

    assert response.status_code == 401
    ldap_settings.assert_not_called()
    ldap_auth.assert_not_called()


def test_ldap_account_collision_is_rejected_without_session(client):
    fake_connection = _login_connection(None)
    ldap_identity = LDAPIdentity(username="ad.user", object_guid=LDAP_GUID)

    with (
        patch("app.routes.auth.get_database_connection") as mock_db,
        patch("app.routes.auth.load_ldap_settings", return_value=object()),
        patch("app.routes.auth.authenticate_ldap", return_value=ldap_identity),
        patch(
            "app.routes.auth.resolve_ldap_portal_user",
            side_effect=LDAPAccountConflict("username taken"),
        ),
        patch("app.routes.auth.record_audit_event") as audit,
    ):
        mock_db.return_value.__enter__.return_value = fake_connection
        response = _post_login(client, username="ad.user")

    assert response.status_code == 401
    audit.assert_called_once()
    assert not any(
        "INSERT INTO user_sessions" in call.args[0]
        for call in fake_connection.execute.call_args_list
    )


def test_ldap_result_cannot_replace_different_existing_user(client):
    fake_connection = _login_connection(
        (41, "ad.user", None, "viewer", "ldap", True)
    )
    ldap_identity = LDAPIdentity(username="ad.user", object_guid=LDAP_GUID)

    with (
        patch("app.routes.auth.get_database_connection") as mock_db,
        patch("app.routes.auth.load_ldap_settings", return_value=object()),
        patch("app.routes.auth.authenticate_ldap", return_value=ldap_identity),
        patch(
            "app.routes.auth.resolve_ldap_portal_user",
            return_value=LDAPPortalUser(
                id=99, username="ad.user", role="admin"
            ),
        ),
        patch("app.routes.auth.record_audit_event"),
    ):
        mock_db.return_value.__enter__.return_value = fake_connection
        response = _post_login(client, username="ad.user")

    assert response.status_code == 401
    assert not any(
        "INSERT INTO user_sessions" in call.args[0]
        for call in fake_connection.execute.call_args_list
    )
