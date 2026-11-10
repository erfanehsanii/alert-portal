import os
from html import escape

import psycopg
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from app.auth.dependencies import get_user_from_session_token
from app.auth.security import hash_csrf_token, hash_session_token
from app.routes.auth import router as auth_router
from app.routes.dashboard import router as dashboard_router
from app.routes.mattermost import router as mattermost_router
from app.routes.rules import router as rules_router
from app.routes.users import router as users_router
from app.routes.user_dashboard import router as user_dashboard_router
from app.services.database import get_database_connection


app = FastAPI(
    title="Alert Portal",
    description="A controlled interface for managing Prometheus alert rules, Mattermost destinations, and local or Active Directory users.",
    version="0.1.20",
)

app.include_router(auth_router)
app.include_router(rules_router)
app.include_router(mattermost_router)
app.include_router(dashboard_router)
app.include_router(users_router)
app.include_router(user_dashboard_router)


HOME_STYLES = r"""
:root { color-scheme: light; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: #172033; background: #f4f6fb; font-synthesis: none; text-rendering: optimizeLegibility; --surface:#fff; --surface-soft:#f8faff; --ink:#172033; --muted:#667085; --line:#e1e7f0; --line-strong:#cad4e2; --primary:#3159d9; --primary-hover:#2448bb; --primary-soft:#edf2ff; --success:#087443; --success-soft:#eaf8f0; --radius:14px; --shadow:0 5px 20px rgba(28,43,74,.045); }
* { box-sizing:border-box; }
body { margin:0; color:var(--ink); line-height:1.5; }
a { color:var(--primary); text-decoration:none; }
a:hover { text-decoration:underline; }
button,input,select { font:inherit; }
:focus-visible { outline:3px solid #9cb6ff; outline-offset:3px; }
.shell { width:min(1240px,calc(100% - 40px)); margin:0 auto; }
.topbar { display:flex; align-items:center; gap:1rem; flex-wrap:wrap; padding:20px 0; border-bottom:1px solid var(--line); }
.brand { display:flex; align-items:center; gap:.75rem; min-width:max-content; }
.brand-mark { display:grid; place-items:center; width:42px; height:42px; border-radius:13px; color:#fff; background:linear-gradient(145deg,#4268ee,#2545b4); font-weight:850; letter-spacing:-.04em; box-shadow:0 5px 12px rgba(49,89,217,.22); }
.brand-name { margin:0; font-size:1.02rem; font-weight:780; letter-spacing:-.025em; }
.brand-subtitle { margin:.1rem 0 0; color:var(--muted); font-size:.78rem; }
.top-nav { display:flex; gap:.35rem; flex-wrap:wrap; margin-left:auto; }
.top-nav a { display:inline-flex; padding:.48rem .7rem; border-radius:8px; color:#48546b; font-size:.9rem; font-weight:500; }
.top-nav a[aria-current=page] { color:var(--primary); background:var(--primary-soft); }
.topbar-right { display:flex; align-items:center; gap:.6rem; }
.user-pill { display:inline-flex; align-items:center; gap:.5rem; padding:.42rem .7rem; border:1px solid var(--line); border-radius:999px; background:var(--surface); color:#48546b; font-size:.84rem; white-space:nowrap; }
.user-dot { width:8px; height:8px; border-radius:50%; background:#28a16a; }
.button { display:inline-flex; align-items:center; justify-content:center; min-height:40px; padding:.58rem .9rem; border:1px solid var(--line-strong); border-radius:9px; background:var(--surface); color:#344054; font-weight:700; font-size:.9rem; cursor:pointer; text-decoration:none; }
.button:hover { background:#f8faff; border-color:#b2bfd3; text-decoration:none; }
.button-primary { border-color:var(--primary); color:white; background:var(--primary); box-shadow:0 2px 4px rgba(49,89,217,.16); }
.button-primary:hover { border-color:var(--primary-hover); color:white; background:var(--primary-hover); }
main { padding:34px 0 56px; }
.eyebrow { margin:0 0 .4rem; color:var(--primary); font-size:.76rem; font-weight:800; letter-spacing:.11em; text-transform:uppercase; }
h1,h2,h3,p { margin-top:0; }
h1 { margin-bottom:.48rem; font-size:clamp(1.9rem,4vw,2.65rem); line-height:1.12; letter-spacing:-.05em; }
h2 { margin-bottom:.4rem; font-size:1.15rem; letter-spacing:-.025em; }
.intro { max-width:700px; margin:0; color:var(--muted); font-size:.98rem; }
.hero { display:flex; align-items:flex-end; justify-content:space-between; gap:1.5rem; margin-bottom:26px; }
.home-grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:18px; }
.home-card { position:relative; display:flex; flex-direction:column; min-height:245px; padding:24px; border:1px solid var(--line); border-radius:var(--radius); background:var(--surface); box-shadow:var(--shadow); }
.card-mark { display:grid; place-items:center; width:44px; height:44px; margin-bottom:22px; border:1px solid #dce5ff; border-radius:13px; background:var(--primary-soft); color:var(--primary); font-size:.9rem; font-weight:850; letter-spacing:-.03em; }
.home-card h2 { font-size:1.25rem; }
.home-card p { max-width:430px; margin-bottom:22px; color:var(--muted); font-size:.91rem; }
.card-link { display:inline-flex; align-items:center; gap:.5rem; margin-top:auto; font-size:.9rem; font-weight:750; }
.workspace-note { display:flex; align-items:flex-start; gap:12px; margin-top:22px; padding:17px 18px; border:1px solid var(--line); border-radius:12px; background:#f9fbff; color:#48546b; font-size:.87rem; }
.note-dot { flex:0 0 auto; width:8px; height:8px; margin-top:.45rem; border-radius:50%; background:#4268ee; }
.footer { padding:18px 0 24px; border-top:1px solid var(--line); color:var(--muted); font-size:.78rem; }
@media (max-width:760px) { .shell { width:min(100% - 28px,1240px); } .topbar { align-items:flex-start; } .top-nav { order:3; width:100%; margin:0; } .topbar-right { margin-left:auto; } .hero { align-items:flex-start; flex-direction:column; } .home-grid { grid-template-columns:1fr; } .home-card { min-height:220px; } }
@media (prefers-reduced-motion:reduce) { *,*::before,*::after { transition:none !important; scroll-behavior:auto !important; } }
"""


def redirect_to_login(clear_cookies: bool = False) -> RedirectResponse:
    """Redirect to login and optionally clear invalid authentication cookies."""
    response = RedirectResponse("/login", status_code=303)
    response.headers["Cache-Control"] = "no-store"

    if clear_cookies:
        cookie_secure = os.getenv("COOKIE_SECURE", "false").lower() == "true"
        for cookie_name in ("alert_portal_session", "alert_portal_csrf"):
            response.delete_cookie(
                key=cookie_name,
                path="/",
                secure=cookie_secure,
                httponly=True,
                samesite="lax",
            )

    return response


@app.get("/health/live", include_in_schema=False)
async def liveness():
    """Indicate that the application process is running."""
    return {"status": "ok"}


@app.get("/health/ready", include_in_schema=False)
async def readiness():
    """Check whether the application can connect to PostgreSQL."""
    try:
        with get_database_connection() as connection:
            connection.execute("SELECT 1").fetchone()
        return {"status": "ok"}
    except (psycopg.Error, KeyError, ValueError):
        return JSONResponse(
            status_code=503,
            content={"status": "not ready"},
            headers={"Cache-Control": "no-store"},
        )


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Render the authenticated portal home workspace."""
    session_token = request.cookies.get("alert_portal_session")
    csrf_token = request.cookies.get("alert_portal_csrf")
    if not session_token or not csrf_token:
        return redirect_to_login(clear_cookies=True)

    try:
        user = get_user_from_session_token(session_token)
    except HTTPException as exc:
        if exc.status_code == 401:
            return redirect_to_login(clear_cookies=True)
        raise

    session_hash = hash_session_token(session_token)
    csrf_hash = hash_csrf_token(csrf_token)
    try:
        with get_database_connection() as connection:
            row = connection.execute(
                """
                SELECT id
                FROM user_sessions
                WHERE token_hash = %s
                  AND csrf_token_hash = %s
                  AND user_id = %s
                  AND revoked_at IS NULL
                  AND expires_at > NOW()
                """,
                (session_hash, csrf_hash, user.id),
            ).fetchone()
    except psycopg.Error:
        return JSONResponse(
            status_code=503,
            content={"status": "authentication service temporarily unavailable"},
            headers={"Cache-Control": "no-store"},
        )

    if row is None:
        return redirect_to_login(clear_cookies=True)

    username = escape(user.username)
    is_admin = user.role == "admin"
    user_management_nav = (
        '<a href="/users">User management</a>' if is_admin else ""
    )
    user_management_card = (
        """
        <article class="home-card" aria-labelledby="users-card-title">
          <div class="card-mark" aria-hidden="true">UM</div>
          <h2 id="users-card-title">User management</h2>
          <p>Create local accounts, manage local and Active Directory users, assign roles, and reset local passwords.</p>
          <a class="card-link" href="/users">Manage users <span aria-hidden="true">→</span></a>
        </article>
        """
        if is_admin else ""
    )

    page = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light">
  <title>Home — Alert Portal</title>
  <style>{HOME_STYLES}</style>
</head>
<body>
  <div class="shell">
    <header class="topbar">
      <a class="brand" href="/" aria-label="Alert Portal home" style="color:inherit;text-decoration:none">
        <span class="brand-mark" aria-hidden="true">AP</span>
        <span><span class="brand-name" style="display:block">Alert Portal</span><span class="brand-subtitle" style="display:block">Monitoring workspace</span></span>
      </a>
      <nav class="top-nav" aria-label="Primary navigation">
        <a href="/" aria-current="page">Home</a>
        <a href="/alerts">Alert rules</a>
        <a href="/destinations">Mattermost destinations</a>
        {user_management_nav}
      </nav>
      <div class="topbar-right">
        <span class="user-pill"><span class="user-dot" aria-hidden="true"></span>{username}</span>
        <form method="post" action="/logout">
          <input type="hidden" name="csrf_token" value="{escape(csrf_token, quote=True)}">
          <button class="button" type="submit">Sign out</button>
        </form>
      </div>
    </header>
    <main>
      <section class="hero" aria-labelledby="home-title">
        <div>
          <p class="eyebrow">Monitoring workspace</p>
          <h1 id="home-title">Your monitoring workspace</h1>
          <p class="intro">Create and manage Prometheus alert rules from one place. Choose a workspace to get started.</p>
        </div>
      </section>
      <section class="home-grid" aria-label="Workspaces">
        <article class="home-card" aria-labelledby="alerts-card-title">
          <div class="card-mark" aria-hidden="true">AR</div>
          <h2 id="alerts-card-title">Alert rules</h2>
          <p>Define alert conditions, configure severity and duration, and organize rules with custom labels.</p>
          <a class="card-link" href="/alerts">Open alert rules <span aria-hidden="true">→</span></a>
        </article>
        <article class="home-card" aria-labelledby="destinations-card-title">
          <div class="card-mark" aria-hidden="true">MM</div>
          <h2 id="destinations-card-title">Mattermost destinations</h2>
          <p>Choose Mattermost channels and have Alert Portal Bot deliver firing and resolved notifications.</p>
          <a class="card-link" href="/destinations">Manage destinations <span aria-hidden="true">→</span></a>
        </article>
        {user_management_card}
      </section>
      <aside class="workspace-note"><span class="note-dot" aria-hidden="true"></span><div><strong>Changes are managed centrally.</strong><br>Alert rules created here are stored in Kubernetes and loaded by Prometheus. Your available actions depend on your account permissions.</div></aside>
    </main>
    <footer class="footer">Alert Portal · Prometheus alert-rule management</footer>
  </div>
</body>
</html>"""
    return HTMLResponse(
        page,
        headers={
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
        },
    )
