
from dataclasses import dataclass
from typing import Annotated

import psycopg
from fastapi import Cookie, Depends, HTTPException, status

from app.auth.security import hash_session_token
from app.services.database import get_database_connection


@dataclass(frozen=True)
class AuthenticatedUser:
    id: int
    username: str
    role: str


def get_user_from_session_token(
    session_token: str | None,
) -> AuthenticatedUser:
    """Resolve a user from a session token and validate its database state."""
    if not session_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    token_hash = hash_session_token(session_token)

    try:
        with get_database_connection() as connection:
            row = connection.execute(
                """
                SELECT u.id, u.username, u.role
                FROM user_sessions AS s
                JOIN users AS u ON u.id = s.user_id
                WHERE s.token_hash = %s
                  AND s.revoked_at IS NULL
                  AND s.expires_at > NOW()
                  AND u.is_active = TRUE
                """,
                (token_hash,),
            ).fetchone()
    except psycopg.Error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service temporarily unavailable",
        ) from None

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
        )

    return AuthenticatedUser(id=row[0], username=row[1], role=row[2])


def get_current_user(
    alert_portal_session: Annotated[str | None, Cookie()] = None,
) -> AuthenticatedUser:
    """FastAPI dependency for routes protected by the session cookie."""
    return get_user_from_session_token(alert_portal_session)


def require_roles(*allowed_roles: str):
    """Create a dependency that restricts access to specified roles."""

    def role_checker(
        user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    ) -> AuthenticatedUser:
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return user

    return role_checker
