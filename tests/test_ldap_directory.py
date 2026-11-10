"""Unit and security tests for Active Directory authentication."""

import ssl
from dataclasses import replace
from types import SimpleNamespace
from uuid import UUID

import pytest
from ldap3 import SIMPLE, SUBTREE
from ldap3.core.exceptions import LDAPSocketOpenError

from app.auth import ldap_directory
from app.auth.ldap_config import LDAPSettings
from app.auth.ldap_directory import (
    LDAPIdentity,
    LDAPUnavailable,
    authenticate_ldap,
)


TEST_GUID = UUID("12345678-1234-5678-90ab-cdef12345678")

GROUP_DN = (
    "CN=AlertPortal-Users,"
    "OU=Monitoring,OU=Engineering,"
    "OU=Example,DC=example,DC=com"
)

SETTINGS = LDAPSettings(
    host="ad.example.com",
    port=636,
    base_dn="DC=example,DC=com",
    group_dn=GROUP_DN,
    netbios_domain="EXAMPLE",
    timeout=10,
    ca_cert_file=None,
)


class FakeEntry:
    """Simulated Active Directory user entry."""

    def __init__(
        self,
        username="test.user",
        guid=TEST_GUID.bytes_le,
    ):
        self.username = username
        self.guid = guid

    def __getitem__(self, name):
        if name == "objectGUID":
            return SimpleNamespace(
                raw_values=[self.guid]
            )

        if name == "sAMAccountName":
            return SimpleNamespace(
                value=self.username
            )

        raise KeyError(name)


@pytest.fixture
def directory_stub(monkeypatch):
    """Mock LDAP connections without contacting Active Directory."""

    state = {
        "bind_ok": True,
        "bind_result": 49,
        "whoami": "u:EXAMPLE\\test.user",
        "whoami_error": False,
        "search_ok": True,
        "search_error": False,
        "network_error": False,
        "entries": [FakeEntry()],
        "connections": [],
        "closed": [],
        "search_kwargs": None,
    }

    class FakeConnection:
        def __init__(self, user, password, **kwargs):
            self.user = user
            self.password = password
            self.options = kwargs

            self.result = {"result": 0}
            self.entries = []

            self.extend = SimpleNamespace(
                standard=SimpleNamespace(
                    who_am_i=self.who_am_i
                )
            )

            state["connections"].append(self)

        def bind(self):
            if state["network_error"]:
                raise LDAPSocketOpenError(
                    "Simulated AD connection failure"
                )

            if not state["bind_ok"]:
                self.result = {
                    "result": state["bind_result"]
                }
                return False

            return True

        def who_am_i(self):
            if state["whoami_error"]:
                raise LDAPSocketOpenError(
                    "Simulated WhoAmI failure"
                )

            return state["whoami"]

        def search(self, **kwargs):
            state["search_kwargs"] = kwargs

            if state["search_error"]:
                raise LDAPSocketOpenError(
                    "Simulated LDAP search failure"
                )

            if not state["search_ok"]:
                return False

            self.entries = list(state["entries"])

            return True

        def unbind(self):
            state["closed"].append(self.user)
            return True

    def fake_connection(_server, **kwargs):
        return FakeConnection(**kwargs)

    monkeypatch.setattr(
        ldap_directory,
        "Connection",
        fake_connection,
    )

    return state


def test_valid_ad_user_authenticates(directory_stub):
    identity = authenticate_ldap(
        "test.user",
        "fake-test-password",
        SETTINGS,
    )

    assert isinstance(identity, LDAPIdentity)
    assert identity.username == "test.user"
    assert identity.object_guid == TEST_GUID

    # User-first authentication must use exactly one connection.
    assert len(directory_stub["connections"]) == 1
    assert len(directory_stub["closed"]) == 1

    connection = directory_stub["connections"][0]

    assert connection.user == "EXAMPLE\\test.user"
    assert connection.password == "fake-test-password"


def test_connection_uses_secure_options(directory_stub):
    authenticate_ldap(
        "test.user",
        "fake-password",
        SETTINGS,
    )

    connection = directory_stub["connections"][0]

    assert connection.options["authentication"] == SIMPLE
    assert connection.options["auto_bind"] is False
    assert connection.options["auto_referrals"] is False
    assert connection.options["receive_timeout"] == 10


def test_search_uses_verified_identity(directory_stub):
    authenticate_ldap(
        "TEST.USER",
        "fake-password",
        SETTINGS,
    )

    search_filter = directory_stub[
        "search_kwargs"
    ]["search_filter"]

    assert "(sAMAccountName=test.user)" in search_filter


def test_search_requires_correct_ad_group(directory_stub):
    authenticate_ldap(
        "test.user",
        "fake-password",
        SETTINGS,
    )

    search_filter = directory_stub[
        "search_kwargs"
    ]["search_filter"]

    assert (
        f"(memberOf:1.2.840.113556.1.4.1941:={GROUP_DN})"
        in search_filter
    )


def test_search_excludes_disabled_ad_accounts(directory_stub):
    authenticate_ldap(
        "test.user",
        "fake-password",
        SETTINGS,
    )

    search_filter = directory_stub[
        "search_kwargs"
    ]["search_filter"]

    assert (
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
        in search_filter
    )


def test_search_is_scoped_and_limited(directory_stub):
    authenticate_ldap(
        "test.user",
        "fake-password",
        SETTINGS,
    )

    options = directory_stub["search_kwargs"]

    assert options["search_base"] == SETTINGS.base_dn
    assert options["search_scope"] == SUBTREE
    assert options["size_limit"] == 2

    assert "objectGUID" in options["attributes"]
    assert "sAMAccountName" in options["attributes"]


def test_user_outside_allowed_group_is_rejected(directory_stub):
    directory_stub["entries"] = []

    identity = authenticate_ldap(
        "test.user",
        "fake-password",
        SETTINGS,
    )

    assert identity is None

    # Even rejected users must have their connections closed.
    assert len(directory_stub["closed"]) == 1


def test_invalid_ad_password_is_rejected(directory_stub):
    directory_stub["bind_ok"] = False
    directory_stub["bind_result"] = 49

    identity = authenticate_ldap(
        "test.user",
        "wrong-password",
        SETTINGS,
    )

    assert identity is None
    assert directory_stub["search_kwargs"] is None
    assert len(directory_stub["closed"]) == 1


@pytest.mark.parametrize(
    "result_code",
    [1, 52, 81],
)
def test_unexpected_bind_failure_fails_closed(
    directory_stub,
    result_code,
):
    directory_stub["bind_ok"] = False
    directory_stub["bind_result"] = result_code

    with pytest.raises(LDAPUnavailable):
        authenticate_ldap(
            "test.user",
            "fake-password",
            SETTINGS,
        )

    assert len(directory_stub["closed"]) == 1


@pytest.mark.parametrize(
    "username,password",
    [
        ("test.user", ""),
        ("test*user", "fake-password"),
        ("test(user)", "fake-password"),
        ("test/user", "fake-password"),
        ("test@example.com", "fake-password"),
        ("", "fake-password"),
    ],
)
def test_invalid_input_rejected_before_connection(
    directory_stub,
    username,
    password,
):
    identity = authenticate_ldap(
        username,
        password,
        SETTINGS,
    )

    assert identity is None
    assert directory_stub["connections"] == []


@pytest.mark.parametrize(
    "invalid_identity",
    [
        None,
        "",
        "dn:CN=Test User,DC=example,DC=com",
        "u:EXAMPLE\\test.user\\unexpected",
    ],
)
def test_invalid_whoami_response_fails_closed(
    directory_stub,
    invalid_identity,
):
    directory_stub["whoami"] = invalid_identity

    with pytest.raises(LDAPUnavailable):
        authenticate_ldap(
            "test.user",
            "fake-password",
            SETTINGS,
        )

    assert directory_stub["search_kwargs"] is None
    assert len(directory_stub["closed"]) == 1


def test_whoami_username_mismatch_fails_closed(directory_stub):
    directory_stub["whoami"] = "u:EXAMPLE\\other.user"

    with pytest.raises(LDAPUnavailable):
        authenticate_ldap(
            "test.user",
            "fake-password",
            SETTINGS,
        )

    assert directory_stub["search_kwargs"] is None


def test_whoami_domain_mismatch_fails_closed(directory_stub):
    directory_stub["whoami"] = "u:OTHER\\test.user"

    with pytest.raises(LDAPUnavailable):
        authenticate_ldap(
            "test.user",
            "fake-password",
            SETTINGS,
        )

    assert directory_stub["search_kwargs"] is None


def test_whoami_failure_fails_closed(directory_stub):
    directory_stub["whoami_error"] = True

    with pytest.raises(LDAPUnavailable):
        authenticate_ldap(
            "test.user",
            "fake-password",
            SETTINGS,
        )

    assert len(directory_stub["closed"]) == 1


def test_directory_search_failure_fails_closed(directory_stub):
    directory_stub["search_ok"] = False

    with pytest.raises(LDAPUnavailable):
        authenticate_ldap(
            "test.user",
            "fake-password",
            SETTINGS,
        )

    assert len(directory_stub["closed"]) == 1


def test_directory_search_exception_fails_closed(directory_stub):
    directory_stub["search_error"] = True

    with pytest.raises(LDAPUnavailable):
        authenticate_ldap(
            "test.user",
            "fake-password",
            SETTINGS,
        )

    assert len(directory_stub["closed"]) == 1


def test_ad_network_outage_fails_closed(directory_stub):
    directory_stub["network_error"] = True

    with pytest.raises(LDAPUnavailable):
        authenticate_ldap(
            "test.user",
            "fake-password",
            SETTINGS,
        )

    assert len(directory_stub["closed"]) == 1


def test_ambiguous_directory_results_fail_closed(directory_stub):
    directory_stub["entries"] = [
        FakeEntry(),
        FakeEntry(),
    ]

    with pytest.raises(LDAPUnavailable):
        authenticate_ldap(
            "test.user",
            "fake-password",
            SETTINGS,
        )


def test_directory_identity_mismatch_fails_closed(directory_stub):
    directory_stub["entries"] = [
        FakeEntry(username="other.user"),
    ]

    with pytest.raises(LDAPUnavailable):
        authenticate_ldap(
            "test.user",
            "fake-password",
            SETTINGS,
        )


@pytest.mark.parametrize(
    "invalid_guid",
    [
        b"",
        b"\x01" * 15,
        None,
    ],
)
def test_invalid_object_guid_fails_closed(
    directory_stub,
    invalid_guid,
):
    directory_stub["entries"] = [
        FakeEntry(guid=invalid_guid),
    ]

    with pytest.raises(LDAPUnavailable):
        authenticate_ldap(
            "test.user",
            "fake-password",
            SETTINGS,
        )


def test_ldaps_requires_certificate_verification(
    directory_stub,
    monkeypatch,
):
    captured = {}
    original_tls = ldap_directory.Tls

    def capture_tls(**kwargs):
        captured.update(kwargs)
        return original_tls(**kwargs)

    monkeypatch.setattr(
        ldap_directory,
        "Tls",
        capture_tls,
    )

    identity = authenticate_ldap(
        "test.user",
        "fake-password",
        SETTINGS,
    )

    assert identity is not None
    assert captured["validate"] == ssl.CERT_REQUIRED
    assert captured["ca_certs_file"] == SETTINGS.ca_cert_file
    assert captured["sni"] == SETTINGS.host


@pytest.mark.parametrize(
    "legacy_enabled,expected_ciphers",
    [
        (False, None),
        (True, "DEFAULT:@SECLEVEL=1"),
    ],
)
def test_ldaps_modes_preserve_certificate_verification(
    directory_stub,
    monkeypatch,
    legacy_enabled,
    expected_ciphers,
):
    captured = {}
    original_tls = ldap_directory.Tls

    def capture_tls(**kwargs):
        captured.update(kwargs)
        return original_tls(**kwargs)

    monkeypatch.setattr(
        ldap_directory,
        "Tls",
        capture_tls,
    )

    settings = replace(
        SETTINGS,
        legacy_tls_compat=legacy_enabled,
    )

    identity = authenticate_ldap(
        "test.user",
        "fake-password",
        settings,
    )

    assert identity is not None
    assert captured["validate"] == ssl.CERT_REQUIRED
    assert captured["ca_certs_file"] == settings.ca_cert_file
    assert captured["ciphers"] == expected_ciphers
    assert captured["sni"] == settings.host