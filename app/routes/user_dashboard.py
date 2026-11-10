import json
import os
from html import escape

import psycopg
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from app.auth.dependencies import get_user_from_session_token
from app.auth.security import hash_csrf_token, hash_session_token
from app.services.database import get_database_connection


router = APIRouter()


def _redirect_to_login(clear_cookies: bool = False) -> RedirectResponse:
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


@router.get("/users", response_class=HTMLResponse)
async def user_management_dashboard(request: Request):
    """Render the user-management page for active administrators."""
    session_token = request.cookies.get("alert_portal_session")
    csrf_token = request.cookies.get("alert_portal_csrf")

    if not session_token or not csrf_token:
        return _redirect_to_login(clear_cookies=True)

    try:
        user = get_user_from_session_token(session_token)
    except HTTPException as exc:
        if exc.status_code == 401:
            return _redirect_to_login(clear_cookies=True)

        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
            headers={"Cache-Control": "no-store"},
        )

    if user.role != "admin":
        return HTMLResponse(
            """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light">
  <title>Access denied — Alert Portal</title>
  <style>
    :root { color-scheme:light; font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; color:#172033; background:#f4f6fb; --line:#e1e7f0; --muted:#667085; --primary:#3159d9; }
    * { box-sizing:border-box; } body { margin:0; min-height:100vh; display:grid; place-items:center; padding:24px; }
    .card { width:min(100%,480px); padding:32px; border:1px solid var(--line); border-radius:18px; background:#fff; box-shadow:0 12px 40px rgba(28,43,74,.08); }
    .mark { display:grid; place-items:center; width:44px; height:44px; margin-bottom:23px; border-radius:14px; color:#fff; background:linear-gradient(145deg,#4268ee,#2545b4); font-weight:850; }
    .eyebrow { margin:0 0 8px; color:var(--primary); font-size:.75rem; font-weight:800; letter-spacing:.11em; text-transform:uppercase; }
    h1 { margin:0 0 10px; font-size:1.8rem; letter-spacing:-.04em; } p { color:var(--muted); line-height:1.6; }
    a { display:inline-flex; min-height:42px; align-items:center; margin-top:8px; padding:10px 15px; border-radius:9px; color:#fff; background:var(--primary); font-weight:700; text-decoration:none; }
    a:focus-visible { outline:3px solid #9cb6ff; outline-offset:3px; }
  </style>
</head>
<body><main class="card"><div class="mark" aria-hidden="true">AP</div><p class="eyebrow">Access control</p><h1>Administrator access required</h1><p>User management is restricted to administrators. Your account permissions have not been changed.</p><a href="/">Return to workspace</a></main></body>
</html>""",
            status_code=403,
            headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"},
        )

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
                (
                    hash_session_token(session_token),
                    hash_csrf_token(csrf_token),
                    user.id,
                ),
            ).fetchone()

    except psycopg.Error:
        return JSONResponse(
            status_code=503,
            content={
                "detail": "Authentication service temporarily unavailable."
            },
            headers={"Cache-Control": "no-store"},
        )

    if row is None:
        return _redirect_to_login(clear_cookies=True)

    page = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light">
  <title>User Management — Alert Portal</title>
  <style>
    :root { color-scheme:light; font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; color:#172033; background:#f4f6fb; font-synthesis:none; text-rendering:optimizeLegibility; --surface:#fff; --surface-soft:#f8faff; --ink:#172033; --muted:#667085; --line:#e1e7f0; --line-strong:#cad4e2; --primary:#3159d9; --primary-hover:#2448bb; --primary-soft:#edf2ff; --danger:#b42318; --danger-soft:#fff0ef; --success:#087443; --success-soft:#eaf8f0; --warning:#985b00; --warning-soft:#fff4d9; --radius:14px; --shadow:0 5px 20px rgba(28,43,74,.045); }
    * { box-sizing:border-box; }
    body { margin:0; color:var(--ink); line-height:1.5; }
    a { color:var(--primary); text-decoration:none; } a:hover { text-decoration:underline; }
    button,input,select { font:inherit; } button { cursor:pointer; } button:disabled,input:disabled,select:disabled { cursor:not-allowed; opacity:.6; }
    :focus-visible { outline:3px solid #9cb6ff; outline-offset:2px; }
    .shell { width:min(1420px,calc(100% - 40px)); margin:0 auto; }
    .topbar { display:flex; align-items:center; gap:1rem; flex-wrap:wrap; padding:20px 0; border-bottom:1px solid var(--line); }
    .brand { display:flex; align-items:center; gap:.75rem; min-width:max-content; color:inherit; text-decoration:none; }
    .brand:hover { text-decoration:none; }
    .brand-mark { display:grid; place-items:center; width:42px; height:42px; flex:0 0 auto; border-radius:13px; color:#fff; background:linear-gradient(145deg,#4268ee,#2545b4); font-weight:850; letter-spacing:-.04em; box-shadow:0 5px 12px rgba(49,89,217,.22); }
    .brand-name { display:block; margin:0; font-size:1.02rem; font-weight:780; letter-spacing:-.025em; }
    .brand-subtitle { display:block; margin:.1rem 0 0; color:var(--muted); font-size:.78rem; }
    .top-nav { display:flex; align-items:center; gap:.35rem; flex-wrap:wrap; margin-left:auto; }
    .top-nav a { display:inline-flex; padding:.48rem .7rem; border-radius:8px; color:#48546b; font-size:.9rem; font-weight:500; }
    .top-nav a[aria-current=page] { color:var(--primary); background:var(--primary-soft); }
    .topbar-right { display:flex; align-items:center; gap:.6rem; }
    .user-pill { display:inline-flex; align-items:center; gap:.5rem; padding:.42rem .7rem; border:1px solid var(--line); border-radius:999px; background:var(--surface); color:#48546b; font-size:.84rem; white-space:nowrap; }
    .user-dot { width:8px; height:8px; border-radius:50%; background:#28a16a; }
    main { padding:32px 0 50px; }
    h1,h2,h3,h4,p { margin-top:0; } h1 { margin-bottom:.45rem; font-size:clamp(1.8rem,3vw,2.35rem); line-height:1.14; letter-spacing:-.045em; } h2 { margin-bottom:.3rem; font-size:1.12rem; letter-spacing:-.025em; } h3 { margin-bottom:0; font-size:1rem; letter-spacing:-.02em; } h4 { margin-bottom:12px; font-size:.9rem; }
    .eyebrow { margin:0 0 .38rem; color:var(--primary); font-size:.76rem; font-weight:800; letter-spacing:.11em; text-transform:uppercase; }
    .page-heading { display:flex; align-items:flex-end; justify-content:space-between; gap:1.2rem; margin-bottom:22px; }
    .page-intro { max-width:720px; margin:0; color:var(--muted); font-size:.96rem; }
    .button { display:inline-flex; align-items:center; justify-content:center; gap:.45rem; min-height:40px; padding:.58rem .9rem; border:1px solid var(--line-strong); border-radius:9px; background:var(--surface); color:#344054; font-weight:700; font-size:.88rem; text-decoration:none; transition:background .12s ease,border-color .12s ease; }
    .button:hover { background:#f8faff; border-color:#b2bfd3; text-decoration:none; }
    .button-primary { border-color:var(--primary); color:white; background:var(--primary); box-shadow:0 2px 4px rgba(49,89,217,.16); }
    .button-primary:hover { border-color:var(--primary-hover); color:white; background:var(--primary-hover); }
    .button-danger { color:var(--danger); } .button-danger:hover { border-color:#f0b6b2; background:var(--danger-soft); }
    .button-small { min-height:34px; padding:.38rem .65rem; font-size:.82rem; }
    .metrics { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:14px; margin-bottom:20px; }
    .metric { position:relative; overflow:hidden; padding:17px 19px; border:1px solid var(--line); border-radius:var(--radius); background:var(--surface); box-shadow:var(--shadow); }
    .metric:after { position:absolute; top:0; left:0; width:4px; height:100%; background:var(--metric-color,#4268ee); content:""; }
    .metric-label { margin:0 0 .45rem; color:var(--muted); font-size:.84rem; font-weight:650; }
    .metric-value { margin:0; font-size:1.8rem; line-height:1.1; letter-spacing:-.05em; font-weight:800; font-variant-numeric:tabular-nums; }
    .metric-total { --metric-color:#4268ee; } .metric-active { --metric-color:#28a16a; } .metric-inactive { --metric-color:#98a2b3; }
    .workspace { display:grid; grid-template-columns:minmax(300px,.75fr) minmax(0,1.45fr); align-items:start; gap:19px; }
    .panel { min-width:0; overflow:hidden; border:1px solid var(--line); border-radius:var(--radius); background:var(--surface); box-shadow:var(--shadow); }
    .panel-heading { padding:19px 21px 16px; border-bottom:1px solid var(--line); background:linear-gradient(180deg,#fff,#fcfdff); }
    .panel-heading p { margin:.3rem 0 0; color:var(--muted); font-size:.86rem; }
    .panel-body { padding:21px; }
    .field { min-width:0; margin-top:15px; } .field:first-child { margin-top:0; }
    label { display:block; margin-bottom:.38rem; color:#344054; font-size:.85rem; font-weight:720; }
    input,select { display:block; width:100%; min-width:0; max-width:100%; min-height:42px; padding:.65rem .75rem; border:1px solid #cfd7e4; border-radius:9px; outline:none; background:#fff; color:var(--ink); box-shadow:0 1px 2px rgba(16,24,40,.025); }
    input:focus,select:focus { border-color:#7695fa; box-shadow:0 0 0 3px rgba(65,103,232,.12); } input::placeholder { color:#98a2b3; }
    .field-help { margin:.4rem 0 0; color:var(--muted); font-size:.77rem; }
    .form-actions { display:flex; justify-content:flex-end; gap:.7rem; margin-top:25px; padding-top:21px; border-top:1px solid var(--line); }
    .muted { color:var(--muted); } .status-message { min-height:24px; margin:0 0 15px; color:#344054; font-size:.88rem; } .status-message:empty { display:none; }
    .status-message[data-kind=success] { color:var(--success); } .status-message[data-kind=error] { color:var(--danger); }
    .list-heading { display:flex; align-items:center; justify-content:space-between; gap:1rem; flex-wrap:wrap; }
    .search-row { display:grid; grid-template-columns:minmax(0,1fr) auto; align-items:end; gap:12px; padding:17px 21px; border-bottom:1px solid var(--line); }
    .search-row .field { margin:0; } .search-row label { margin-bottom:5px; }
    .count-line { padding:0 21px; margin:13px 0 0; color:var(--muted); font-size:.8rem; }
    #users-list { display:grid; gap:13px; padding:16px 21px 21px; }
    .empty-state { padding:28px 18px; border:1px dashed var(--line-strong); border-radius:11px; background:#fbfcff; text-align:center; }
    .empty-state-mark { display:grid; place-items:center; width:40px; height:40px; margin:0 auto 10px; border-radius:12px; background:var(--primary-soft); color:var(--primary); font-weight:850; }
    .empty-state h3 { margin-bottom:5px; } .empty-state p { margin:0; color:var(--muted); font-size:.85rem; }
    .user-card { min-width:0; padding:17px; border:1px solid var(--line); border-radius:12px; background:#fff; }
    .user-heading { display:flex; align-items:flex-start; justify-content:space-between; gap:12px; }
    .user-title-line { display:flex; align-items:center; gap:8px; flex-wrap:wrap; min-width:0; }
    .user-id { color:var(--muted); font-size:.76rem; font-weight:600; }
    .status-pill,.role-pill { display:inline-flex; align-items:center; padding:.24rem .55rem; border-radius:999px; font-size:.74rem; font-weight:750; white-space:nowrap; }
    .status-active { color:var(--success); background:var(--success-soft); } .status-inactive { color:#596579; background:#edf0f5; }
    .role-admin { color:#6842a6; background:#f1eaff; } .role-editor { color:#245bb2; background:#eaf2ff; } .role-viewer { color:#566274; background:#edf0f5; }
    .user-meta { display:flex; flex-wrap:wrap; gap:.35rem 1.1rem; margin:10px 0 0; color:var(--muted); font-size:.78rem; }
    .user-meta p { margin:0; }
    .user-section { margin-top:15px; padding:14px; border:1px solid #e9edf4; border-radius:10px; background:#fafbfe; }
    .access-fields { display:grid; grid-template-columns:minmax(0,1fr) minmax(0,1fr); align-items:end; gap:12px; }
    .access-fields label { margin-bottom:5px; } .access-fields select { min-height:40px; }
    .checkbox-field { display:flex; align-items:center; gap:9px; min-height:40px; padding:0 3px; }
    .checkbox-field label { margin:0; } .checkbox-field input { width:17px; min-height:17px; height:17px; margin:0; accent-color:var(--primary); }
    .user-section-actions { display:flex; justify-content:flex-end; margin-top:12px; }
    .password-row { display:grid; grid-template-columns:minmax(0,1fr) auto; align-items:end; gap:10px; }
    .password-row .field { margin:0; } .password-row label { margin-bottom:5px; }
    .self-note { margin:11px 0 0; color:var(--muted); font-size:.78rem; }
    .footer { padding:19px 0 25px; border-top:1px solid var(--line); color:var(--muted); font-size:.78rem; }
    [hidden] { display:none !important; }
    @media (max-width:1000px) { .workspace { grid-template-columns:minmax(0,.85fr) minmax(0,1.15fr); } .search-row { grid-template-columns:1fr; } }
    @media (max-width:780px) { .shell { width:min(100% - 28px,1420px); } .topbar { align-items:flex-start; } .top-nav { order:3; width:100%; margin:0; } .topbar-right { margin-left:auto; } main { padding-top:25px; } .page-heading { align-items:flex-start; flex-direction:column; } .metrics { gap:9px; } .metric { padding:14px; } .metric-value { font-size:1.5rem; } .workspace { grid-template-columns:1fr; } .panel-body { padding:17px; } .panel-heading { padding:17px; } .search-row { padding:15px 17px; } #users-list { padding:15px 17px 17px; } }
    @media (max-width:460px) { .metrics { grid-template-columns:1fr; } .metric { padding:13px 16px; } .metric-value { font-size:1.35rem; } .access-fields,.password-row { grid-template-columns:1fr; } .password-row .button { width:100%; } .user-heading { align-items:flex-start; flex-direction:column; } .topbar-right { width:100%; justify-content:space-between; margin-left:0; } }
    @media (prefers-reduced-motion:reduce) { *,*::before,*::after { transition:none !important; scroll-behavior:auto !important; } }
  </style>
</head>
<body>
  <div class="shell">
    <header class="topbar">
      <a class="brand" href="/" aria-label="Alert Portal home">
        <span class="brand-mark" aria-hidden="true">AP</span>
        <span><span class="brand-name">Alert Portal</span><span class="brand-subtitle">Monitoring workspace</span></span>
      </a>
      <nav class="top-nav" aria-label="Primary navigation">
        <a href="/">Home</a>
        <a href="/alerts">Alert rules</a>
        <a href="/destinations">Mattermost destinations</a>
        <a href="/users" aria-current="page">User management</a>
      </nav>
      <div class="topbar-right">
        <span class="user-pill"><span class="user-dot" aria-hidden="true"></span>USERNAME_PLACEHOLDER</span>
        <form method="post" action="/logout">
          <input type="hidden" name="csrf_token" value="CSRF_HTML_PLACEHOLDER">
          <button class="button" type="submit">Sign out</button>
        </form>
      </div>
    </header>

    <main>
      <section class="page-heading">
        <div><p class="eyebrow">Access &amp; users</p><h1>User management</h1><p class="page-intro">Create local accounts and assign rule access. Editors may create rules but can edit or delete only their own; administrators can manage all rules.</p></div>
        <a class="button button-primary" href="#create-account-panel">＋ Create account</a>
      </section>

      <section class="metrics" aria-label="Account summary">
        <article class="metric metric-total"><p class="metric-label">Total accounts</p><p class="metric-value" id="metric-total-users">—</p></article>
        <article class="metric metric-active"><p class="metric-label">Active accounts</p><p class="metric-value" id="metric-active-users">—</p></article>
        <article class="metric metric-inactive"><p class="metric-label">Inactive accounts</p><p class="metric-value" id="metric-inactive-users">—</p></article>
      </section>

      <p id="status" class="status-message" role="status" aria-live="polite"></p>

      <div class="workspace">
        <section class="panel" id="create-account-panel" aria-labelledby="create-account-title">
          <div class="panel-heading"><p class="eyebrow">New account</p><h2 id="create-account-title">Create local account</h2><p>Provide an initial password and the least-privileged role that meets the user's needs.</p></div>
          <div class="panel-body">
            <form id="create-user-form">
              <div class="field"><label for="new-username">Username</label><input id="new-username" type="text" required minlength="1" maxlength="64" pattern="[A-Za-z0-9._-]+" autocomplete="off" placeholder="e.g. monitoring.editor"><p class="field-help">1–64 characters: letters, numbers, dots, underscores, and hyphens.</p></div>
              <div class="field"><label for="new-password">Initial password</label><input id="new-password" type="password" required minlength="12" maxlength="1024" autocomplete="new-password" placeholder="At least 12 characters"><p class="field-help">Passwords are not displayed after submission.</p></div>
              <div class="field"><label for="new-role">Role</label><select id="new-role"><option value="viewer">Viewer — view all alert rules</option><option value="editor">Editor — create rules and manage own rules</option><option value="admin">Administrator — manage users and all rules</option></select><p class="field-help">All roles can view rules. Only administrators can edit or delete rules owned by other users.</p></div>
              <div class="form-actions"><button class="button button-primary" id="create-user-button" type="submit">Create account</button></div>
            </form>
          </div>
        </section>

        <section class="panel" aria-labelledby="local-accounts-title">
          <div class="panel-heading">
            <div class="list-heading"><div><p class="eyebrow">Directory</p><h2 id="local-accounts-title">All accounts</h2><p>Manage local and Active Directory access. AD passwords are managed in Active Directory.</p></div><button class="button button-small" id="refresh-users" type="button">Refresh</button></div>
          </div>
          <div class="search-row"><div class="field"><label for="user-search">Search accounts</label><input id="user-search" type="search" placeholder="Username, role or status…" autocomplete="off"></div></div>
          <p class="count-line" id="user-count" aria-live="polite">Loading accounts…</p>
          <div id="users-list" aria-live="polite"><div class="empty-state"><div class="empty-state-mark" aria-hidden="true">…</div><h3>Loading accounts</h3><p>Fetching local users and their current access.</p></div></div>
        </section>
      </div>
    </main>
    <footer class="footer">Alert Portal · User and access administration</footer>
  </div>

<script>
"use strict";

const csrfToken = CSRF_JS_PLACEHOLDER;
const currentUserId = CURRENT_USER_ID_PLACEHOLDER;
const roles = ["admin", "editor", "viewer"];

const statusElement = document.getElementById("status");
const usersList = document.getElementById("users-list");
const createForm = document.getElementById("create-user-form");
const createButton = document.getElementById("create-user-button");
const userSearch = document.getElementById("user-search");
const userCount = document.getElementById("user-count");
const totalMetric = document.getElementById("metric-total-users");
const activeMetric = document.getElementById("metric-active-users");
const inactiveMetric = document.getElementById("metric-inactive-users");
let allUsers = [];

function setStatus(message, kind = "") {
  statusElement.textContent = message;
  statusElement.dataset.kind = kind;
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (options.method && options.method !== "GET") {
    headers.set("X-CSRF-Token", csrfToken);
    if (options.body) headers.set("Content-Type", "application/json");
  }
  const response = await fetch(path, {
    ...options, headers, credentials: "same-origin", cache: "no-store"
  });
  let data = {};
  try { data = await response.json(); } catch (_) { data = {}; }
  if (!response.ok) throw new Error(data.detail || `Request failed (HTTP ${response.status})`);
  return data;
}

function addText(parent, tag, value, className = "") {
  const element = document.createElement(tag);
  element.textContent = value == null ? "" : String(value);
  if (className) element.className = className;
  parent.appendChild(element);
  return element;
}

function roleClass(role) {
  return `role-${roles.includes(role) ? role : "viewer"}`;
}

function addRoleOptions(select, selectedRole) {
  for (const role of roles) {
    const option = document.createElement("option");
    option.value = role;
    option.textContent = role === "admin" ? "Administrator" : role[0].toUpperCase() + role.slice(1);
    option.selected = role === selectedRole;
    select.appendChild(option);
  }
}

function userCard(user) {
  const card = document.createElement("article");
  card.className = "user-card";
  card.dataset.username = String(user.username || "").toLocaleLowerCase();
  const isLdap = user.auth_provider === "ldap";

  const heading = document.createElement("div");
  heading.className = "user-heading";
  const titleLine = document.createElement("div");
  titleLine.className = "user-title-line";
  addText(titleLine, "h3", user.username);
  addText(titleLine, "span", `ID ${user.id}`, "user-id");
  addText(titleLine, "span", isLdap ? "Active Directory" : "Local", "role-pill role-viewer");
  addText(titleLine, "span", user.role === "admin" ? "Administrator" : user.role[0].toUpperCase() + user.role.slice(1), `role-pill ${roleClass(user.role)}`);
  heading.appendChild(titleLine);
  addText(heading, "span", user.is_active ? "Active" : "Inactive", `status-pill ${user.is_active ? "status-active" : "status-inactive"}`);
  card.appendChild(heading);

  const meta = document.createElement("div");
  meta.className = "user-meta";
  addText(meta, "p", `Created: ${user.created_at || "—"}`);
  addText(meta, "p", `Last login: ${user.last_login_at || "Never"}`);
  card.appendChild(meta);

  const isSelf = user.id === currentUserId;
  const accessSection = document.createElement("section");
  accessSection.className = "user-section";
  addText(accessSection, "h4", "Access settings");
  const accessFields = document.createElement("div");
  accessFields.className = "access-fields";

  const roleContainer = document.createElement("div");
  const roleLabel = addText(roleContainer, "label", "Role");
  const roleSelect = document.createElement("select");
  roleSelect.id = `role-${user.id}`;
  roleLabel.htmlFor = roleSelect.id;
  addRoleOptions(roleSelect, user.role);
  roleSelect.disabled = isSelf;
  roleContainer.appendChild(roleSelect);
  accessFields.appendChild(roleContainer);

  const activeContainer = document.createElement("div");
  activeContainer.className = "checkbox-field";
  const activeCheckbox = document.createElement("input");
  activeCheckbox.type = "checkbox";
  activeCheckbox.checked = Boolean(user.is_active);
  activeCheckbox.id = `active-${user.id}`;
  activeCheckbox.disabled = isSelf;
  const activeLabel = addText(activeContainer, "label", "Account active");
  activeLabel.htmlFor = activeCheckbox.id;
  activeContainer.appendChild(activeCheckbox);
  accessFields.appendChild(activeContainer);
  accessSection.appendChild(accessFields);

  if (isSelf) addText(accessSection, "p", "The current administrator's role and active status cannot be changed here.", "self-note");
  const saveAccess = document.createElement("button");
  saveAccess.type = "button";
  saveAccess.className = "button button-small button-primary";
  saveAccess.textContent = "Save access changes";
  saveAccess.disabled = isSelf;
  saveAccess.addEventListener("click", async () => {
    saveAccess.disabled = true;
    try {
      await api(`/api/users/${user.id}`, {
        method: "PATCH",
        body: JSON.stringify({ role: roleSelect.value, is_active: activeCheckbox.checked })
      });
      setStatus(`Access settings saved for ${user.username}.`, "success");
      await loadUsers();
    } catch (error) {
      setStatus(error.message, "error");
      saveAccess.disabled = false;
    }
  });
  const accessActions = document.createElement("div");
  accessActions.className = "user-section-actions";
  accessActions.appendChild(saveAccess);
  accessSection.appendChild(accessActions);
  card.appendChild(accessSection);

  if (isLdap) {
    const directoryNote = document.createElement("section");
    directoryNote.className = "user-section";
    addText(directoryNote, "h4", "Active Directory authentication");
    addText(directoryNote, "p", "This account signs in with Active Directory. Reset its password and manage directory group membership in Active Directory.", "self-note");
    card.appendChild(directoryNote);
  } else {
    const passwordSection = document.createElement("section");
    passwordSection.className = "user-section";
    addText(passwordSection, "h4", "Reset password");
    const passwordForm = document.createElement("form");
    passwordForm.className = "password-row";
    const passwordField = document.createElement("div");
    passwordField.className = "field";
    const passwordLabel = addText(passwordField, "label", "New password");
    const passwordInput = document.createElement("input");
    passwordInput.type = "password";
    passwordInput.required = true;
    passwordInput.minLength = 12;
    passwordInput.maxLength = 1024;
    passwordInput.autocomplete = "new-password";
    passwordInput.placeholder = "At least 12 characters";
    passwordInput.id = `password-${user.id}`;
    passwordLabel.htmlFor = passwordInput.id;
    passwordField.appendChild(passwordInput);
    passwordForm.appendChild(passwordField);
    const resetButton = document.createElement("button");
    resetButton.type = "submit";
    resetButton.className = "button button-small";
    resetButton.textContent = "Reset password";
    passwordForm.appendChild(resetButton);

    passwordForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (!window.confirm(`Reset the password for ${user.username}? Their existing sessions will be revoked.`)) return;
      resetButton.disabled = true;
      try {
        const result = await api(`/api/users/${user.id}/password`, {
          method: "POST", body: JSON.stringify({ password: passwordInput.value })
        });
        passwordInput.value = "";
        if (result.current_session_revoked) { window.location.assign("/login"); return; }
        setStatus(`Password reset for ${user.username}. ${result.sessions_revoked} existing session(s) revoked.`, "success");
      } catch (error) {
        setStatus(error.message, "error");
      } finally {
        resetButton.disabled = false;
      }
    });
    passwordSection.appendChild(passwordForm);
    card.appendChild(passwordSection);
  }
  return card;
}

function updateMetrics() {
  totalMetric.textContent = String(allUsers.length);
  activeMetric.textContent = String(allUsers.filter(user => Boolean(user.is_active)).length);
  inactiveMetric.textContent = String(allUsers.filter(user => !user.is_active).length);
}

function renderUsers() {
  const query = userSearch.value.trim().toLocaleLowerCase();
  const filtered = allUsers.filter(user => {
    const haystack = [user.username, user.role, user.auth_provider, user.auth_provider === "ldap" ? "active directory" : "local", user.id, user.is_active ? "active" : "inactive", user.created_at, user.last_login_at].join(" ").toLocaleLowerCase();
    return !query || haystack.includes(query);
  });
  usersList.replaceChildren();
  userCount.textContent = `${filtered.length} of ${allUsers.length} account(s) shown`;
  if (filtered.length === 0) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    addText(empty, "div", allUsers.length ? "⌕" : "＋", "empty-state-mark");
    addText(empty, "h3", allUsers.length ? "No accounts match" : "No accounts yet");
    addText(empty, "p", allUsers.length ? "Try another username, role, or status." : "Create a local account to grant access to the portal.");
    if (allUsers.length && query) {
      const clear = addText(empty, "button", "Clear search", "button button-small");
      clear.type = "button";
      clear.addEventListener("click", () => { userSearch.value = ""; renderUsers(); userSearch.focus(); });
    }
    usersList.appendChild(empty);
    return;
  }
  for (const user of filtered) usersList.appendChild(userCard(user));
}

async function loadUsers() {
  usersList.replaceChildren();
  const loading = document.createElement("div");
  loading.className = "empty-state";
  addText(loading, "div", "…", "empty-state-mark");
  addText(loading, "h3", "Loading accounts");
  addText(loading, "p", "Fetching local and Active Directory accounts and their current access.");
  usersList.appendChild(loading);
  userCount.textContent = "Loading accounts…";
  try {
    const data = await api("/api/users");
    allUsers = Array.isArray(data.items) ? data.items : [];
    updateMetrics();
    renderUsers();
  } catch (error) {
    allUsers = [];
    updateMetrics();
    usersList.replaceChildren();
    userCount.textContent = "Accounts could not be loaded";
    const empty = document.createElement("div");
    empty.className = "empty-state";
    addText(empty, "div", "!", "empty-state-mark");
    addText(empty, "h3", "Unable to load accounts");
    addText(empty, "p", error.message);
    const retry = addText(empty, "button", "Try again", "button button-small");
    retry.type = "button";
    retry.addEventListener("click", loadUsers);
    usersList.appendChild(empty);
  }
}

createForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  createButton.disabled = true;
  const username = document.getElementById("new-username").value.trim();
  const password = document.getElementById("new-password").value;
  const role = document.getElementById("new-role").value;
  try {
    const user = await api("/api/users", {
      method: "POST", body: JSON.stringify({ username, password, role })
    });
    createForm.reset();
    setStatus(`Account "${user.username}" created with role ${user.role}.`, "success");
    await loadUsers();
    document.getElementById("user-search").value = "";
    renderUsers();
  } catch (error) {
    setStatus(error.message, "error");
  } finally {
    createButton.disabled = false;
  }
});

document.getElementById("refresh-users").addEventListener("click", loadUsers);
userSearch.addEventListener("input", renderUsers);
loadUsers();
</script>
</body>
</html>
"""

    replacements = {
        "USERNAME_PLACEHOLDER": escape(user.username),
        "CSRF_HTML_PLACEHOLDER": escape(csrf_token, quote=True),
        "CSRF_JS_PLACEHOLDER": json.dumps(csrf_token),
        "CURRENT_USER_ID_PLACEHOLDER": str(int(user.id)),
    }

    for placeholder, value in replacements.items():
        page = page.replace(placeholder, value)

    return HTMLResponse(
        page,
        headers={
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
        },
    )
