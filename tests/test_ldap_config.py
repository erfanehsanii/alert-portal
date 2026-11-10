"""Security tests for LDAP configuration."""

import pytest

from app.auth.ldap_config import load_ldap_settings


@pytest.fixture
def enabled_ldap_env(monkeypatch):
    """Configure LDAP using test-only settings."""

    settings = {
        "LDAP_ENABLED": "true",
        "LDAP_HOST": "ad.example.com",
        "LDAP_PORT": "636",
        "LDAP_BASE_DN": "DC=example,DC=com",
        "LDAP_GROUP_DN": "CN=TestGroup,DC=example,DC=com",
        "LDAP_NETBIOS_DOMAIN": "EXAMPLE",
        "LDAP_TIMEOUT": "10",
        "LDAP_CA_CERT_FILE": "/etc/ssl/certs/test-internal-ca.crt",
    }

    for name, value in settings.items():
        monkeypatch.setenv(name, value)

    for name in (
        "LDAP_LEGACY_TLS_COMPAT",
        "LDAP_TLS_VERIFY",
        "LDAP_BIND_DN",
        "LDAP_BIND_PASSWORD",
    ):
        monkeypatch.delenv(name, raising=False)


def test_ldap_disabled_by_default(monkeypatch):
    monkeypatch.delenv("LDAP_ENABLED", raising=False)

    assert load_ldap_settings() is None


def test_ldap_requires_ca_certificate(
    enabled_ldap_env,
    monkeypatch,
):
    monkeypatch.delenv("LDAP_CA_CERT_FILE")

    with pytest.raises(ValueError, match="LDAP_CA_CERT_FILE"):
        load_ldap_settings()


def test_ldap_accepts_configured_ca_path(enabled_ldap_env):
    settings = load_ldap_settings()

    assert settings is not None
    assert settings.host == "ad.example.com"
    assert settings.port == 636
    assert settings.netbios_domain == "EXAMPLE"

    assert (
        settings.ca_cert_file
        == "/etc/ssl/certs/test-internal-ca.crt"
    )


def test_service_account_is_not_required(enabled_ldap_env):
    settings = load_ldap_settings()

    assert settings is not None
    assert not hasattr(settings, "bind_dn")
    assert not hasattr(settings, "bind_password")


def test_netbios_domain_is_required(
    enabled_ldap_env,
    monkeypatch,
):
    monkeypatch.delenv("LDAP_NETBIOS_DOMAIN")

    with pytest.raises(
        ValueError,
        match="LDAP_NETBIOS_DOMAIN",
    ):
        load_ldap_settings()


@pytest.mark.parametrize(
    "invalid_domain",
    [
        "EXAMPLE\\OTHER",
        "EXAMPLE/OTHER",
        "EXAMPLE LOCAL",
        "DOMAIN-NAME-TOO-LONG",
        "@INVALID",
    ],
)
def test_invalid_netbios_domain_is_rejected(
    enabled_ldap_env,
    monkeypatch,
    invalid_domain,
):
    monkeypatch.setenv(
        "LDAP_NETBIOS_DOMAIN",
        invalid_domain,
    )

    with pytest.raises(
        ValueError,
        match="Invalid LDAP_NETBIOS_DOMAIN",
    ):
        load_ldap_settings()


def test_legacy_tls_disable_setting_is_ignored(
    enabled_ldap_env,
    monkeypatch,
):
    monkeypatch.setenv("LDAP_TLS_VERIFY", "false")

    settings = load_ldap_settings()

    assert settings is not None
    assert not hasattr(settings, "tls_verify")


def test_legacy_tls_compat_disabled_by_default(
    enabled_ldap_env,
):
    settings = load_ldap_settings()

    assert settings is not None
    assert settings.legacy_tls_compat is False


def test_legacy_tls_compat_requires_explicit_opt_in(
    enabled_ldap_env,
    monkeypatch,
):
    monkeypatch.setenv(
        "LDAP_LEGACY_TLS_COMPAT",
        "true",
    )

    settings = load_ldap_settings()

    assert settings is not None
    assert settings.legacy_tls_compat is True


def test_invalid_legacy_tls_compat_configuration_fails(
    enabled_ldap_env,
    monkeypatch,
):
    monkeypatch.setenv(
        "LDAP_LEGACY_TLS_COMPAT",
        "invalid",
    )

    with pytest.raises(
        ValueError,
        match="LDAP_LEGACY_TLS_COMPAT",
    ):
        load_ldap_settings()


@pytest.mark.parametrize(
    "variable,value",
    [
        ("LDAP_PORT", "0"),
        ("LDAP_PORT", "65536"),
        ("LDAP_PORT", "invalid"),
        ("LDAP_TIMEOUT", "0"),
        ("LDAP_TIMEOUT", "31"),
        ("LDAP_TIMEOUT", "invalid"),
    ],
)
def test_invalid_port_or_timeout_fails(
    enabled_ldap_env,
    monkeypatch,
    variable,
    value,
):
    monkeypatch.setenv(variable, value)

    with pytest.raises(ValueError):
        load_ldap_settings()