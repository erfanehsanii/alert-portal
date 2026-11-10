
import json
from typing import Any

from app.services.database import get_database_connection


def record_audit_event(
    action: str,
    actor_user_id: int | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Record an audit event without storing credentials or session tokens."""
    safe_details = details or {}

    with get_database_connection() as connection:
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
                target_type,
                target_id,
                json.dumps(safe_details),
            ),
        )
        connection.commit()
