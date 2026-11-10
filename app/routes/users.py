import json
from typing import Literal

import psycopg
from fastapi import APIRouter, Depends, HTTPException, Path, status
from pydantic import BaseModel, ConfigDict, Field

from app.auth.dependencies import AuthenticatedUser, require_roles
from app.auth.security import hash_password
from app.routes.rules import require_valid_csrf
from app.services.database import get_database_connection


router = APIRouter(tags=["user-management"])

Role = Literal["admin", "editor", "viewer"]

USER_COLUMNS = """
    id, username, role, is_active, created_at, updated_at, last_login_at, auth_provider
"""


class UserCreate(BaseModel):
    """Fields for creating a local account."""

    model_config = ConfigDict(extra="forbid")

    username: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9._-]+$",
    )
    password: str = Field(min_length=12, max_length=1024)
    role: Role = "viewer"


class UserUpdate(BaseModel):
    """Fields for changing a user's role or active status."""

    model_config = ConfigDict(extra="forbid")

    role: Role | None = None
    is_active: bool | None = None


class UserPasswordReset(BaseModel):
    """Fields for resetting a local user's password."""

    model_config = ConfigDict(extra="forbid")

    password: str = Field(min_length=12, max_length=1024)


def _serialize_user(row) -> dict:
    """Return public account details; never return password hashes."""
    return {
        "id": row[0],
        "username": row[1],
        "role": row[2],
        "is_active": row[3],
        "created_at": row[4],
        "updated_at": row[5],
        "last_login_at": row[6],
        "auth_provider": row[7],
    }


def _insert_audit_event(
    connection,
    *,
    actor_user_id: int,
    action: str,
    target_id: int,
    details: dict,
) -> None:
    """Write the audit entry in the same transaction as the account change."""
    connection.execute(
        """
        INSERT INTO audit_log (
            actor_user_id,
            action,
            target_type,
            target_id,
            details
        )
        VALUES (%s, %s, %s, %s, %s::jsonb)
        """,
        (
            actor_user_id,
            action,
            "user",
            str(target_id),
            json.dumps(details),
        ),
    )


def _database_unavailable() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="User-management service temporarily unavailable.",
    )


def _unique_username_conflict() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="That username already exists.",
    )


@router.get("/api/users")
def list_users(
    actor: AuthenticatedUser = Depends(require_roles("admin")),
):
    """List accounts for administrators only."""
    try:
        with get_database_connection() as connection:
            rows = connection.execute(
                f"SELECT {USER_COLUMNS} FROM users ORDER BY username"
            ).fetchall()

        return {"items": [_serialize_user(row) for row in rows]}

    except psycopg.Error:
        raise _database_unavailable() from None


@router.post("/api/users", status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreate,
    actor: AuthenticatedUser = Depends(require_roles("admin")),
    csrf_actor: AuthenticatedUser = Depends(require_valid_csrf),
):
    """Create a local account with a hashed password."""
    username = payload.username.lower()

    try:
        password_hash = hash_password(payload.password)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    try:
        with get_database_connection() as connection:
            existing = connection.execute(
                "SELECT id FROM users WHERE lower(username) = %s",
                (username,),
            ).fetchone()

            if existing is not None:
                raise _unique_username_conflict()

            row = connection.execute(
                """
                INSERT INTO users (
                    username,
                    password_hash,
                    role,
                    auth_provider,
                    is_active
                )
                VALUES (%s, %s, %s, 'local', TRUE)
                RETURNING id, username, role, is_active,
                          created_at, updated_at, last_login_at,
                          auth_provider
                """,
                (username, password_hash, payload.role),
            ).fetchone()

            _insert_audit_event(
                connection,
                actor_user_id=actor.id,
                action="user_created",
                target_id=row[0],
                details={
                    "username": username,
                    "auth_provider": "local",
                    "role": payload.role,
                    "is_active": True,
                },
            )

            connection.commit()

        return _serialize_user(row)

    except psycopg.errors.UniqueViolation:
        raise _unique_username_conflict() from None
    except psycopg.Error:
        raise _database_unavailable() from None


@router.patch("/api/users/{user_id}")
def update_user(
    user_id: int = Path(ge=1),
    payload: UserUpdate = ...,
    actor: AuthenticatedUser = Depends(require_roles("admin")),
    csrf_actor: AuthenticatedUser = Depends(require_valid_csrf),
):
    """Change a user's role or active status, protecting administrator access."""
    fields = payload.model_fields_set

    if not fields:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Specify a role and/or is_active value.",
        )

    if any(getattr(payload, field) is None for field in fields):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Update fields cannot be null.",
        )

    try:
        with get_database_connection() as connection:
            # Lock active local administrators in a consistent order so
            # concurrent updates cannot remove the last local administrator.
            # LDAP administrators must not be counted as recovery accounts.
            active_local_admins = connection.execute(
                """
                SELECT id
                FROM users
                WHERE auth_provider = 'local'
                  AND role = 'admin'
                  AND is_active = TRUE
                ORDER BY id
                FOR UPDATE
                """
            ).fetchall()

            current = connection.execute(
                f"""
                SELECT {USER_COLUMNS}
                FROM users
                WHERE id = %s
                FOR UPDATE
                """,
                (user_id,),
            ).fetchone()

            if current is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found.",
                )

            old = _serialize_user(current)
            new_role = payload.role if payload.role is not None else old["role"]
            new_active = (
                payload.is_active
                if payload.is_active is not None
                else old["is_active"]
            )

            if user_id == actor.id and (
                new_role != old["role"] or new_active != old["is_active"]
            ):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="You cannot change your own role or active status.",
                )

            removing_active_local_admin = (
                old["auth_provider"] == "local"
                and old["role"] == "admin"
                and old["is_active"]
                and (new_role != "admin" or not new_active)
            )

            if removing_active_local_admin and len(active_local_admins) <= 1:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="The last active local administrator cannot be demoted or deactivated.",
                )

            if new_role == old["role"] and new_active == old["is_active"]:
                return old

            row = connection.execute(
                """
                UPDATE users
                SET role = %s,
                    is_active = %s,
                    updated_at = NOW()
                WHERE id = %s
                RETURNING id, username, role, is_active,
                          created_at, updated_at, last_login_at,
                          auth_provider
                """,
                (new_role, new_active, user_id),
            ).fetchone()

            revoked_sessions = 0

            if old["is_active"] and not new_active:
                cursor = connection.execute(
                    """
                    UPDATE user_sessions
                    SET revoked_at = NOW()
                    WHERE user_id = %s AND revoked_at IS NULL
                    """,
                    (user_id,),
                )
                revoked_sessions = cursor.rowcount

            updated = _serialize_user(row)

            _insert_audit_event(
                connection,
                actor_user_id=actor.id,
                action="user_updated",
                target_id=user_id,
                details={
                    "username": updated["username"],
                    "auth_provider": updated["auth_provider"],
                    "before": {
                        "role": old["role"],
                        "is_active": old["is_active"],
                    },
                    "after": {
                        "role": updated["role"],
                        "is_active": updated["is_active"],
                    },
                    "sessions_revoked": revoked_sessions,
                },
            )

            connection.commit()

        return updated

    except HTTPException:
        raise
    except psycopg.Error:
        raise _database_unavailable() from None


@router.post("/api/users/{user_id}/password")
def reset_user_password(
    user_id: int = Path(ge=1),
    payload: UserPasswordReset = ...,
    actor: AuthenticatedUser = Depends(require_roles("admin")),
    csrf_actor: AuthenticatedUser = Depends(require_valid_csrf),
):
    """Reset a local user's password and revoke their existing sessions."""
    try:
        password_hash = hash_password(payload.password)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    try:
        with get_database_connection() as connection:
            current = connection.execute(
                """
                SELECT id, username, auth_provider
                FROM users
                WHERE id = %s
                FOR UPDATE
                """,
                (user_id,),
            ).fetchone()

            if current is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found.",
                )

            if current[2] != "local":
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Only local account passwords can be reset here.",
                )

            connection.execute(
                """
                UPDATE users
                SET password_hash = %s,
                    updated_at = NOW()
                WHERE id = %s
                """,
                (password_hash, user_id),
            )

            cursor = connection.execute(
                """
                UPDATE user_sessions
                SET revoked_at = NOW()
                WHERE user_id = %s AND revoked_at IS NULL
                """,
                (user_id,),
            )
            revoked_sessions = cursor.rowcount

            _insert_audit_event(
                connection,
                actor_user_id=actor.id,
                action="user_password_reset",
                target_id=user_id,
                details={
                    "username": current[1],
                    "sessions_revoked": revoked_sessions,
                },
            )

            connection.commit()

        return {
            "id": user_id,
            "username": current[1],
            "password_updated": True,
            "sessions_revoked": revoked_sessions,
            "current_session_revoked": user_id == actor.id,
        }

    except HTTPException:
        raise
    except psycopg.Error:
        raise _database_unavailable() from None