"""Configuration for Microsoft Active Directory authentication."""

import os
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class LDAPSettings:
    host: str
    port: int
    base_dn: str
    group_dn: str
    netbios_domain: str
    timeout: int = 10
    ca_cert_file: str | None = None
    legacy_tls_compat: bool = False


def _read_bool(name: str, default: bool) -> bool:
    value = os.getenv(
        name,
        "true" if default else "false",
    ).strip().lower()

    if value in ("true", "1", "yes"):
        return True

    if value in ("false", "0", "no"):
        return False

    raise ValueError(f"Invalid boolean configuration: {name}")


def load_ldap_settings() -> LDAPSettings | None:
    """Return LDAP settings, or None when LDAP is disabled."""

    if not _read_bool("LDAP_ENABLED", False):
        return None

    required = (
        "LDAP_HOST",
        "LDAP_BASE_DN",
        "LDAP_GROUP_DN",
        "LDAP_NETBIOS_DOMAIN",
        "LDAP_CA_CERT_FILE",
    )

    missing = [
        name
        for name in required
        if not os.getenv(name, "").strip()
    ]

    if missing:
        raise ValueError(
            "Missing LDAP configuration: " + ", ".join(missing)
        )

    try:
        port = int(os.getenv("LDAP_PORT", "636"))
        timeout = int(os.getenv("LDAP_TIMEOUT", "10"))
    except ValueError as exc:
        raise ValueError(
            "LDAP_PORT and LDAP_TIMEOUT must be integers"
        ) from exc

    if not 1 <= port <= 65535:
        raise ValueError("Invalid LDAP_PORT")

    if not 1 <= timeout <= 30:
        raise ValueError(
            "LDAP_TIMEOUT must be between 1 and 30"
        )

    netbios_domain = os.environ[
        "LDAP_NETBIOS_DOMAIN"
    ].strip()

    if not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9-]{0,14}",
        netbios_domain,
    ):
        raise ValueError(
            "Invalid LDAP_NETBIOS_DOMAIN"
        )

    return LDAPSettings(
        host=os.environ["LDAP_HOST"].strip(),
        port=port,
        base_dn=os.environ["LDAP_BASE_DN"].strip(),
        group_dn=os.environ["LDAP_GROUP_DN"].strip(),
        netbios_domain=netbios_domain,
        timeout=timeout,
        ca_cert_file=os.environ[
            "LDAP_CA_CERT_FILE"
        ].strip(),
        legacy_tls_compat=_read_bool(
            "LDAP_LEGACY_TLS_COMPAT",
            False,
        ),
    )