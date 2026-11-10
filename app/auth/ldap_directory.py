"""Microsoft Active Directory authentication for Alert Portal."""

import re
import ssl
from dataclasses import dataclass
from uuid import UUID

from ldap3 import (
    NONE,
    SIMPLE,
    SUBTREE,
    Connection,
    Server,
    Tls,
)
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars

from app.auth.ldap_config import LDAPSettings


@dataclass(frozen=True)
class LDAPIdentity:
    """An authenticated Active Directory identity."""

    username: str
    object_guid: UUID


class LDAPUnavailable(RuntimeError):
    """Active Directory could not complete authentication."""


def _close_connection(connection: Connection | None) -> None:
    """Close LDAP connections without exposing cleanup errors."""

    if connection is not None:
        try:
            connection.unbind()
        except (LDAPException, OSError):
            pass


def authenticate_ldap(
    username: str,
    password: str,
    settings: LDAPSettings,
) -> LDAPIdentity | None:
    """
    Authenticate and authorize an AD user without a service account.

    Returns:
        LDAPIdentity: Authentication and authorization succeeded.
        None: Invalid credentials or unauthorized user.

    Raises:
        LDAPUnavailable: LDAP communication or validation failure.
    """

    normalized_username = username.strip()

    # Reject empty passwords and malformed usernames before binding.
    if not password:
        return None

    if not re.fullmatch(
        r"[A-Za-z0-9._-]{1,64}",
        normalized_username,
    ):
        return None

    connection = None

    try:
        # Always verify the AD server certificate.
        tls = Tls(
            validate=ssl.CERT_REQUIRED,
            ca_certs_file=settings.ca_cert_file,
            ciphers=(
                "DEFAULT:@SECLEVEL=1"
                if settings.legacy_tls_compat
                else None
            ),
            sni=settings.host,
        )

        server = Server(
            settings.host,
            port=settings.port,
            use_ssl=True,
            tls=tls,
            connect_timeout=settings.timeout,
            get_info=NONE,
        )

        # Authenticate directly as the user.
        # No service account or stored LDAP password is needed.
        login_name = (
            f"{settings.netbios_domain}\\{normalized_username}"
        )

        connection = Connection(
            server,
            user=login_name,
            password=password,
            authentication=SIMPLE,
            auto_bind=False,
            auto_referrals=False,
            receive_timeout=settings.timeout,
        )

        if not connection.bind():
            result_code = (
                connection.result or {}
            ).get("result")

            # LDAP result 49: invalid credentials.
            if result_code == 49:
                return None

            raise LDAPUnavailable(
                "Active Directory authentication failed"
            )

        # Verify which AD identity was actually authenticated.
        whoami = connection.extend.standard.who_am_i()

        identity_match = re.fullmatch(
            r"u:([A-Za-z0-9][A-Za-z0-9-]{0,14})"
            r"\\([A-Za-z0-9._-]{1,64})",
            whoami or "",
            flags=re.IGNORECASE,
        )

        if identity_match is None:
            raise LDAPUnavailable(
                "Active Directory identity verification failed"
            )

        bound_domain, bound_username = (
            identity_match.groups()
        )

        # Prevent authentication as an unexpected identity.
        if (
            bound_domain.casefold()
            != settings.netbios_domain.casefold()
            or bound_username.casefold()
            != normalized_username.casefold()
        ):
            raise LDAPUnavailable(
                "Active Directory identity mismatch"
            )

        # Search only for the verified, authenticated identity.
        safe_username = escape_filter_chars(
            bound_username
        )

        safe_group_dn = escape_filter_chars(
            settings.group_dn
        )

        # Enforce nested group membership and reject disabled users.
        search_filter = (
            "(&(objectCategory=person)"
            "(objectClass=user)"
            f"(sAMAccountName={safe_username})"
            f"(memberOf:1.2.840.113556.1.4.1941:={safe_group_dn})"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        )

        search_success = connection.search(
            search_base=settings.base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=[
                "objectGUID",
                "sAMAccountName",
            ],
            size_limit=2,
        )

        if not search_success:
            raise LDAPUnavailable(
                "Active Directory search failed"
            )

        entries = connection.entries

        # No match means missing, disabled, or unauthorized user.
        if len(entries) == 0:
            return None

        # Refuse ambiguous directory results.
        if len(entries) != 1:
            raise LDAPUnavailable(
                "Active Directory returned ambiguous results"
            )

        entry = entries[0]

        ad_username = entry[
            "sAMAccountName"
        ].value

        # Confirm that the search result is the bound identity.
        if (
            not isinstance(ad_username, str)
            or ad_username.casefold()
            != bound_username.casefold()
        ):
            raise LDAPUnavailable(
                "Active Directory account identity mismatch"
            )

        # AD objectGUID uses little-endian byte ordering.
        raw_guid = entry[
            "objectGUID"
        ].raw_values[0]

        if len(raw_guid) != 16:
            raise LDAPUnavailable(
                "Invalid Active Directory objectGUID"
            )

        object_guid = UUID(
            bytes_le=bytes(raw_guid)
        )

        return LDAPIdentity(
            username=ad_username.lower(),
            object_guid=object_guid,
        )

    except LDAPUnavailable:
        raise

    except (LDAPException, OSError) as exc:
        raise LDAPUnavailable(
            "Active Directory authentication unavailable"
        ) from exc

    except (
        AttributeError,
        IndexError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise LDAPUnavailable(
            "Invalid Active Directory response"
        ) from exc

    finally:
        _close_connection(connection)