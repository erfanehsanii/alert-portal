import json
import os
import secrets
from html import escape
from datetime import datetime, timedelta, timezone

import psycopg
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from app.auth.security import (
    generate_csrf_token,
    generate_session_token,
    hash_csrf_token,
    hash_session_token,
    verify_password,
)
from app.services.audit import record_audit_event
from app.services.database import get_database_connection
from starlette.concurrency import run_in_threadpool

from app.auth.ldap_config import load_ldap_settings
from app.auth.ldap_directory import LDAPUnavailable, authenticate_ldap
from app.services.ldap_users import (
    LDAPAccountConflict,
    resolve_ldap_portal_user,
)

router = APIRouter()

SESSION_HOURS = int(os.getenv("SESSION_HOURS", "8"))
LOGIN_CSRF_MINUTES = 10
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"


def login_error(message: str, status_code: int = 403) -> HTMLResponse:
    """Return a non-cacheable authentication error page using the portal theme."""
    safe_message = escape(message)
    return HTMLResponse(
        f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light">
  <title>Sign-in unavailable — Alert Portal</title>
  <style>
    :root {{ color-scheme: light; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: #172033; background: #f4f6fb; --surface:#fff; --muted:#667085; --line:#e1e7f0; --primary:#3159d9; --primary-soft:#edf2ff; --danger:#b42318; --danger-soft:#fff0ef; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; min-height:100vh; display:grid; place-items:center; padding:24px; }}
    .auth-shell {{ width:min(100%, 440px); }}
    .brand {{ display:flex; align-items:center; gap:12px; margin:0 0 22px 4px; }}
    .brand-mark {{ display:grid; place-items:center; width:44px; height:44px; border-radius:14px; color:#fff; background:linear-gradient(145deg,#4268ee,#2545b4); font-weight:850; box-shadow:0 5px 12px rgba(49,89,217,.22); }}
    .brand-name {{ margin:0; font-size:1.08rem; font-weight:780; letter-spacing:-.03em; }}
    .brand-subtitle {{ margin:3px 0 0; font-size:.82rem; color:var(--muted); }}
    .auth-card {{ padding:clamp(24px,5vw,36px); border:1px solid var(--line); border-radius:18px; background:var(--surface); box-shadow:0 12px 40px rgba(28,43,74,.08); }}
    .eyebrow {{ margin:0 0 8px; color:var(--primary); font-size:.75rem; font-weight:800; letter-spacing:.11em; text-transform:uppercase; }}
    h1 {{ margin:0 0 10px; font-size:1.7rem; line-height:1.2; letter-spacing:-.04em; }}
    .message {{ margin:0 0 22px; padding:12px 14px; border:1px solid #f2b8b5; border-radius:10px; color:var(--danger); background:var(--danger-soft); line-height:1.5; }}
    .button {{ display:inline-flex; justify-content:center; width:100%; min-height:44px; align-items:center; padding:10px 15px; border:1px solid var(--primary); border-radius:10px; color:#fff; background:var(--primary); font:inherit; font-weight:700; text-decoration:none; }}
    .button:hover {{ background:#2448bb; }}
    :focus-visible {{ outline:3px solid #9cb6ff; outline-offset:3px; }}
  </style>
</head>
<body>
  <main class="auth-shell">
    <div class="brand"><div class="brand-mark" aria-hidden="true">AP</div><div><p class="brand-name">Alert Portal</p><p class="brand-subtitle">Monitoring workspace</p></div></div>
    <section class="auth-card" aria-labelledby="error-title">
      <p class="eyebrow">Sign-in</p>
      <h1 id="error-title">We couldn't continue</h1>
      <p class="message" role="alert">{safe_message}</p>
      <a class="button" href="/login">Return to sign in</a>
    </section>
  </main>
</body>
</html>""",
        status_code=status_code,
        headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"},
    )

def insert_audit_event(
    connection,
    action: str,
    actor_user_id: int | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    details: dict | None = None,
) -> None:
    """Insert an audit event into the caller's current transaction."""
    import json

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
            json.dumps(details or {}),
        ),
    )


@router.get("/login", response_class=HTMLResponse)
async def login_page():
    """Issue a short-lived, single-use CSRF token for the login form."""
    csrf_token = generate_csrf_token()
    csrf_token_hash = hash_csrf_token(csrf_token)
    expires_at = datetime.now(timezone.utc) + timedelta(
        minutes=LOGIN_CSRF_MINUTES
    )

    try:
        with get_database_connection() as connection:
            connection.execute(
                "DELETE FROM login_csrf_tokens WHERE expires_at <= NOW()"
            )
            connection.execute(
                """
                INSERT INTO login_csrf_tokens (token_hash, expires_at)
                VALUES (%s, %s)
                """,
                (csrf_token_hash, expires_at),
            )
            connection.commit()
    except psycopg.Error:
        return login_error(
            "Sign-in is temporarily unavailable. Please try again.",
            status_code=503,
        )

    html = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light">
  <title>Sign in — Alert Portal</title>
  <style>
    :root { color-scheme: light; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: #172033; background: #f4f6fb; --surface:#fff; --muted:#667085; --line:#e1e7f0; --line-strong:#cbd5e1; --primary:#3159d9; --primary-hover:#2448bb; }
    * { box-sizing:border-box; }
    body { margin:0; min-height:100vh; display:grid; place-items:center; padding:24px; }
    .auth-shell { width:min(100%, 440px); }
    .brand { display:flex; align-items:center; gap:12px; margin:0 0 22px 4px; }
    .brand-mark { display:grid; place-items:center; width:44px; height:44px; border-radius:14px; color:#fff; background:linear-gradient(145deg,#4268ee,#2545b4); font-weight:850; letter-spacing:-.04em; box-shadow:0 5px 12px rgba(49,89,217,.22); }
    .brand-name { margin:0; font-size:1.08rem; font-weight:780; letter-spacing:-.03em; }
    .brand-subtitle { margin:3px 0 0; color:var(--muted); font-size:.82rem; }
    .auth-card { padding:clamp(24px,5vw,36px); border:1px solid var(--line); border-radius:18px; background:var(--surface); box-shadow:0 12px 40px rgba(28,43,74,.08); }
    .eyebrow { margin:0 0 8px; color:var(--primary); font-size:.75rem; font-weight:800; letter-spacing:.11em; text-transform:uppercase; }
    h1 { margin:0 0 8px; font-size:1.85rem; line-height:1.2; letter-spacing:-.045em; }
    .intro { margin:0 0 25px; color:var(--muted); font-size:.94rem; line-height:1.55; }
    .field { margin-top:16px; }
    label { display:block; margin-bottom:7px; color:#344054; font-size:.86rem; font-weight:700; }
    input { display:block; width:100%; min-height:45px; padding:11px 12px; border:1px solid var(--line-strong); border-radius:10px; outline:none; background:#fff; color:#172033; font:inherit; }
    input:focus { border-color:#7695fa; box-shadow:0 0 0 3px rgba(65,103,232,.12); }
    input::placeholder { color:#98a2b3; }
    .button { display:inline-flex; justify-content:center; width:100%; min-height:46px; align-items:center; margin-top:24px; padding:11px 16px; border:1px solid var(--primary); border-radius:10px; color:white; background:var(--primary); font:inherit; font-weight:730; cursor:pointer; box-shadow:0 2px 4px rgba(49,89,217,.16); }
    .button:hover { border-color:var(--primary-hover); background:var(--primary-hover); }
    .footnote { margin:20px 0 0; color:var(--muted); text-align:center; font-size:.78rem; }
    :focus-visible { outline:3px solid #9cb6ff; outline-offset:3px; }
    @media (prefers-reduced-motion:reduce) { *,*::before,*::after { transition:none !important; scroll-behavior:auto !important; } }
  </style>
</head>
<body>
  <main class="auth-shell">
    <div class="brand"><div class="brand-mark" aria-hidden="true">AP</div><div><p class="brand-name">Alert Portal</p><p class="brand-subtitle">Monitoring workspace</p></div></div>
    <section class="auth-card" aria-labelledby="login-title">
      <p class="eyebrow">Secure workspace</p>
      <h1 id="login-title">Welcome back</h1>
      <p class="intro">Sign in to manage Prometheus alert rules and monitoring access.</p>
      <form method="post" action="/login">
        <input type="hidden" name="csrf_token" value="CSRF_PLACEHOLDER">
        <div class="field"><label for="username">Username</label><input id="username" name="username" autocomplete="username" required maxlength="64" autofocus placeholder="Enter your username"></div>
        <div class="field"><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required maxlength="1024" placeholder="Enter your password"></div>
        <button class="button" type="submit">Sign in</button>
      </form>
      <p class="footnote">Access is managed by your Alert Portal administrator.</p>
    </section>
  </main>
</body>
</html>
    """

    return HTMLResponse(
        html.replace("CSRF_PLACEHOLDER", csrf_token),
        headers={"Cache-Control": "no-store"},
    )


@router.post("/login")
async def login(
    csrf_token: str = Form(..., min_length=32, max_length=128),
    username: str = Form(..., min_length=1, max_length=64),
    password: str = Form(..., min_length=1, max_length=1024),
):
    """Validate CSRF and credentials before creating a session."""
    submitted_csrf_hash = hash_csrf_token(csrf_token)

    try:
        with get_database_connection() as connection:
            csrf_row = connection.execute(
                """
                DELETE FROM login_csrf_tokens
                WHERE token_hash = %s
                  AND expires_at > NOW()
                RETURNING token_hash
                """,
                (submitted_csrf_hash,),
            ).fetchone()
            connection.commit()
    except psycopg.Error:
        return login_error(
            "Sign-in is temporarily unavailable. Please try again.",
            status_code=503,
        )

    if csrf_row is None:
        return login_error("Sign-in form expired or invalid")

    normalized_username = username.strip()

    # Identify an existing portal account before deciding
    # which authentication provider can verify its password.
    try:
        with get_database_connection() as connection:
            account = connection.execute(
                """
                SELECT
                    id,
                    username,
                    password_hash,
                    role,
                    auth_provider,
                    is_active
                FROM users
                WHERE username = %s
                """,
                (normalized_username,),
            ).fetchone()

    except psycopg.Error:
        return login_error(
            "Sign-in is temporarily unavailable. Please try again.",
            status_code=503,
        )

    user = None

    if account is not None and account[4] == "local":
        # Local accounts must authenticate locally.
        # Never fall back to AD after a failed local login.
        if (
            account[5]
            and account[2] is not None
            and await run_in_threadpool(
                verify_password,
                password,
                account[2],
            )
        ):
            user = account[:4]

    elif account is not None and not account[5]:
        # A disabled portal account cannot authenticate
        # through either provider.
        user = None

    else:
        # No matching account, or an existing LDAP account.
        # LDAP authentication remains optional.
        try:
            ldap_settings = load_ldap_settings()

        except (ValueError, KeyError):
            return login_error(
                "Sign-in is temporarily unavailable. Please try again.",
                status_code=503,
            )

        if ldap_settings is not None:
            try:
                identity = await run_in_threadpool(
                    authenticate_ldap,
                    normalized_username,
                    password,
                    ldap_settings,
                )

                if identity is not None:
                    portal_user = await run_in_threadpool(
                        resolve_ldap_portal_user,
                        identity,
                    )

                    if portal_user is not None:
                        # Never replace a different account
                        # that already owns this username.
                        if account is None or (
                            account[4] == "ldap"
                            and account[0] == portal_user.id
                        ):
                            user = (
                                portal_user.id,
                                portal_user.username,
                                None,
                                portal_user.role,
                            )

            except LDAPAccountConflict:
                # Avoid exposing account existence or
                # username collisions to unauthenticated users.
                user = None

            except (LDAPUnavailable, psycopg.Error):
                return login_error(
                    "Sign-in is temporarily unavailable. Please try again.",
                    status_code=503,
                )

    if user is None:
        try:
            record_audit_event(
                action="login_failed",
                target_type="user",
                target_id=normalized_username[:64],
            )

        except psycopg.Error:
            return login_error(
                "Sign-in is temporarily unavailable. Please try again.",
                status_code=503,
            )

        return login_error(
            "Invalid username or password",
            status_code=401,
        )
    session_token = generate_session_token()
    session_token_hash = hash_session_token(session_token)

    csrf_session_token = generate_csrf_token()
    csrf_session_hash = hash_csrf_token(csrf_session_token)

    expires_at = datetime.now(timezone.utc) + timedelta(
        hours=SESSION_HOURS
    )

    try:
        with get_database_connection() as connection:
            connection.execute(
                """
                INSERT INTO user_sessions (
                    user_id,
                    token_hash,
                    csrf_token_hash,
                    expires_at
                )
                VALUES (%s, %s, %s, %s)
                """,
                (
                    user[0],
                    session_token_hash,
                    csrf_session_hash,
                    expires_at,
                ),
            )
            connection.execute(
                "UPDATE users SET last_login_at = NOW() WHERE id = %s",
                (user[0],),
            )
            insert_audit_event(
                connection,
                action="login_succeeded",
                actor_user_id=user[0],
                target_type="user",
                target_id=str(user[0]),
            )
            connection.commit()
    except psycopg.Error:
        return login_error(
            "Sign-in is temporarily unavailable. Please try again.",
            status_code=503,
        )

    response = RedirectResponse("/", status_code=303)
    response.headers["Cache-Control"] = "no-store"

    response.set_cookie(
        key="alert_portal_session",
        value=session_token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=SESSION_HOURS * 3600,
        path="/",
    )
    response.set_cookie(
        key="alert_portal_csrf",
        value=csrf_session_token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=SESSION_HOURS * 3600,
        path="/",
    )
    return response


@router.post("/logout")
async def logout(
    request: Request,
    csrf_token: str = Form(..., min_length=32, max_length=128),
):
    """Revoke the session only when its session-bound CSRF token is valid."""
    session_token = request.cookies.get("alert_portal_session")
    csrf_cookie = request.cookies.get("alert_portal_csrf")

    if not session_token or not csrf_cookie:
        return login_error("Session expired or invalid", status_code=401)

    if not secrets.compare_digest(csrf_token, csrf_cookie):
        return login_error("Invalid logout request", status_code=403)

    session_hash = hash_session_token(session_token)
    csrf_hash = hash_csrf_token(csrf_cookie)

    try:
        with get_database_connection() as connection:
            revoked_session = connection.execute(
                """
                UPDATE user_sessions
                SET revoked_at = NOW()
                WHERE token_hash = %s
                  AND csrf_token_hash = %s
                  AND revoked_at IS NULL
                  AND expires_at > NOW()
                RETURNING user_id
                """,
                (session_hash, csrf_hash),
            ).fetchone()

            if revoked_session is None:
                connection.commit()
                return login_error("Invalid logout request", status_code=403)

            insert_audit_event(
                connection,
                action="logout_succeeded",
                actor_user_id=revoked_session[0],
                target_type="user",
                target_id=str(revoked_session[0]),
            )
            connection.commit()
    except psycopg.Error:
        return login_error(
            "Sign-out is temporarily unavailable. Please try again.",
            status_code=503,
        )

    response = RedirectResponse("/login", status_code=303)
    response.headers["Cache-Control"] = "no-store"

    for cookie_name in ("alert_portal_session", "alert_portal_csrf"):
        response.delete_cookie(
            key=cookie_name,
            path="/",
            secure=COOKIE_SECURE,
            httponly=True,
            samesite="lax",
        )

    return response