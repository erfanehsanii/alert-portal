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


def redirect_to_login(clear_cookies: bool = False) -> RedirectResponse:
    response = RedirectResponse("/login", status_code=303)
    response.headers["Cache-Control"] = "no-store"

    if clear_cookies:
        secure = os.getenv("COOKIE_SECURE", "false").lower() == "true"
        for cookie_name in ("alert_portal_session", "alert_portal_csrf"):
            response.delete_cookie(
                key=cookie_name,
                path="/",
                secure=secure,
                httponly=True,
                samesite="lax",
            )

    return response


@router.get("/alerts", response_class=HTMLResponse)
async def alerts_dashboard(request: Request):
    """Render the alert-rule dashboard for a valid authenticated session."""
    session_token = request.cookies.get("alert_portal_session")
    csrf_token = request.cookies.get("alert_portal_csrf")

    if not session_token or not csrf_token:
        return redirect_to_login(clear_cookies=True)

    try:
        user = get_user_from_session_token(session_token)
    except HTTPException as exc:
        if exc.status_code == 401:
            return redirect_to_login(clear_cookies=True)
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
            headers={"Cache-Control": "no-store"},
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
            content={"detail": "Authentication service temporarily unavailable."},
            headers={"Cache-Control": "no-store"},
        )

    if row is None:
        return redirect_to_login(clear_cookies=True)

    can_edit = user.role in ("admin", "editor")
    is_admin = user.role == "admin"

    page = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light">
  <title>Alert rules — Alert Portal</title>
  <style>
    :root {
      color-scheme: light;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color: #172033;
      background: #f4f6fb;
      font-synthesis: none;
      text-rendering: optimizeLegibility;
      --surface: #ffffff;
      --surface-soft: #f8faff;
      --ink: #172033;
      --muted: #667085;
      --line: #e1e7f0;
      --line-strong: #cad4e2;
      --primary: #3159d9;
      --primary-hover: #2448bb;
      --primary-soft: #edf2ff;
      --danger: #b42318;
      --danger-soft: #fff0ef;
      --success: #087443;
      --success-soft: #eaf8f0;
      --warning: #985b00;
      --warning-soft: #fff4d9;
      --radius: 14px;
      --shadow: 0 5px 20px rgba(28, 43, 74, .045);
    }
    * { box-sizing: border-box; }
    body { margin: 0; line-height: 1.5; color: var(--ink); }
    a { color: var(--primary); text-decoration: none; }
    a:hover { text-decoration: underline; }
    button, input, textarea, select { font: inherit; }
    button { cursor: pointer; }
    button:disabled { cursor: not-allowed; opacity: .6; }
    :focus-visible { outline: 3px solid #9cb6ff; outline-offset: 2px; }
    .shell { width: min(1420px, calc(100% - 40px)); margin: 0 auto; }
    .topbar { display: flex; align-items: center; justify-content: space-between; gap: 1rem; padding: 20px 0; border-bottom: 1px solid var(--line); }
    .brand { display: flex; align-items: center; gap: .75rem; min-width: 0; }
    .brand-mark { display: grid; place-items: center; width: 42px; height: 42px; flex: 0 0 auto; border-radius: 13px; color: white; background: linear-gradient(145deg, #4268ee, #2545b4); font-weight: 800; letter-spacing: -.04em; box-shadow: 0 5px 12px rgba(49, 89, 217, .22); }
    .brand-name { margin: 0; font-size: 1.02rem; font-weight: 760; letter-spacing: -.025em; }
    .brand-subtitle { margin: .1rem 0 0; color: var(--muted); font-size: .78rem; }
    .topbar-right, .top-nav, .heading-actions, .rule-actions, .form-actions { display: flex; align-items: center; gap: .65rem; flex-wrap: wrap; }
    .top-nav { margin-left: auto; margin-right: .5rem; }
    .top-nav a { display: inline-flex; padding: .48rem .7rem; border-radius: 8px; color: #48546b; font-weight: 500; font-size: .9rem; }
    .top-nav a[aria-current="page"] { background: var(--primary-soft); color: var(--primary); }
    .user-pill { display: inline-flex; align-items: center; gap: .5rem; padding: .42rem .7rem; border: 1px solid var(--line); border-radius: 999px; background: var(--surface); color: #48546b; font-size: .84rem; white-space: nowrap; }
    .user-dot { width: 8px; height: 8px; border-radius: 50%; background: #28a16a; }
    main { padding: 32px 0 48px; }
    .page-heading { display: flex; justify-content: space-between; align-items: flex-end; gap: 1.2rem; margin-bottom: 23px; }
    .eyebrow { margin: 0 0 .38rem; color: var(--primary); font-size: .76rem; font-weight: 800; letter-spacing: .11em; text-transform: uppercase; }
    h1, h2, h3, p { margin-top: 0; }
    h1 { margin-bottom: .42rem; font-size: clamp(1.8rem, 3vw, 2.35rem); line-height: 1.14; letter-spacing: -.045em; }
    h2 { margin-bottom: .35rem; font-size: 1.15rem; letter-spacing: -.025em; }
    h3 { font-size: 1rem; letter-spacing: -.015em; }
    .page-intro { max-width: 720px; margin: 0; color: var(--muted); font-size: .97rem; }
    .button { display: inline-flex; align-items: center; justify-content: center; gap: .45rem; min-height: 40px; padding: .58rem .9rem; border: 1px solid var(--line-strong); border-radius: 9px; background: var(--surface); color: #344054; font-weight: 680; font-size: .9rem; transition: background .12s ease, border-color .12s ease, transform .12s ease; }
    .button:hover { background: #f8faff; border-color: #b2bfd3; }
    .button-primary { border-color: var(--primary); color: white; background: var(--primary); box-shadow: 0 2px 4px rgba(49, 89, 217, .16); }
    .button-primary:hover { border-color: var(--primary-hover); background: var(--primary-hover); }
    .button-danger { color: var(--danger); }
    .button-danger:hover { border-color: #f0b6b2; background: var(--danger-soft); }
    .button-small { min-height: 34px; padding: .38rem .65rem; font-size: .84rem; }
    .metrics { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 14px; margin-bottom: 23px; }
    .metric { position: relative; overflow: hidden; padding: 18px 19px; border: 1px solid var(--line); border-radius: var(--radius); background: var(--surface); box-shadow: var(--shadow); }
    .metric::after { position: absolute; top: 0; left: 0; width: 4px; height: 100%; background: var(--metric-color, #8c9bb4); content: ""; }
    .metric-label { margin: 0 0 .5rem; color: var(--muted); font-size: .86rem; font-weight: 600; }
    .metric-value { margin: 0; font-size: 1.85rem; line-height: 1.05; letter-spacing: -.05em; font-weight: 780; font-variant-numeric: tabular-nums; }
    .metric-total { --metric-color: #4268ee; }
    .metric-critical { --metric-color: #d04444; }
    .metric-warning { --metric-color: #d58b13; }
    .metric-info { --metric-color: #3090c8; }
    .workspace { display: grid; grid-template-columns: minmax(340px, .84fr) minmax(0, 1.3fr); align-items: start; gap: 20px; }
    .panel { min-width: 0; overflow: hidden; border: 1px solid var(--line); border-radius: var(--radius); background: var(--surface); box-shadow: var(--shadow); }
    .panel-heading { padding: 19px 21px 16px; border-bottom: 1px solid var(--line); background: linear-gradient(180deg, #fff, #fcfdff); }
    .panel-heading p { margin: .25rem 0 0; color: var(--muted); font-size: .87rem; }
    .panel-body { padding: 21px; }
    .form-section + .form-section { margin-top: 22px; padding-top: 21px; border-top: 1px solid var(--line); }
    .section-kicker { display: flex; align-items: center; gap: .55rem; margin: 0 0 .3rem; color: #3d4d69; font-size: .76rem; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }
    .section-number { display: grid; place-items: center; width: 22px; height: 22px; border-radius: 7px; background: var(--primary-soft); color: var(--primary); font-size: .72rem; letter-spacing: 0; }
    .section-help { margin: 0 0 13px; color: var(--muted); font-size: .84rem; }
    .field { min-width: 0; margin-top: 13px; }
    .field:first-child { margin-top: 0; }
    .field-grid { display: grid; grid-template-columns: minmax(0, 1.3fr) minmax(130px, .7fr); gap: 12px; }
    label { display: block; margin-bottom: .35rem; color: #344054; font-size: .86rem; font-weight: 700; }
    .optional { color: var(--muted); font-weight: 500; }
    input, textarea, select { display: block; width: 100%; min-width: 0; max-width: 100%; padding: .68rem .76rem; border: 1px solid #cfd7e4; border-radius: 9px; outline: none; background: #fff; color: var(--ink); box-shadow: 0 1px 2px rgba(16, 24, 40, .025); transition: border-color .12s ease, box-shadow .12s ease; }
    input::placeholder, textarea::placeholder { color: #98a2b3; }
    input:focus, textarea:focus, select:focus { border-color: #7695fa; box-shadow: 0 0 0 3px rgba(65, 103, 232, .12); }
    textarea { min-height: 94px; resize: vertical; }
    .promql { min-height: 108px; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .88rem; line-height: 1.6; }
    .field-hint { margin: .35rem 0 0; color: var(--muted); font-size: .78rem; }
    .labels-heading { display: flex; justify-content: space-between; align-items: center; gap: .8rem; margin-bottom: .2rem; }
    .label-count { color: var(--muted); font-size: .8rem; white-space: nowrap; }
    .label-editor { display: grid; gap: 10px; margin-top: 13px; }
    .custom-label-row { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1.15fr) auto; align-items: start; gap: 9px; padding: 12px; border: 1px solid var(--line); border-radius: 11px; background: var(--surface-soft); }
    .custom-label-row label { margin-bottom: .32rem; font-size: .78rem; }
    .custom-label-row input { padding: .58rem .62rem; font-size: .88rem; }
    .label-counter { display: block; margin-top: .28rem; color: var(--muted); font-size: .72rem; text-align: right; font-variant-numeric: tabular-nums; }
    .remove-label-button { align-self: center; min-width: 34px; min-height: 34px; padding: .3rem .45rem; border: 1px solid transparent; border-radius: 8px; background: transparent; color: #667085; font-weight: 700; }
    .remove-label-button:hover { border-color: #f0c5c2; color: var(--danger); background: var(--danger-soft); }
    .add-label-row { margin-top: 11px; border-style: dashed; border-color: #aebce0; color: var(--primary); background: #f8faff; }
    .label-guidance { margin-top: 12px; padding: 11px 12px; border-radius: 9px; color: #52617b; background: #f5f7fc; font-size: .78rem; }
    .label-error { margin: 10px 0 0; color: var(--danger); font-size: .83rem; font-weight: 650; }
    .form-actions { justify-content: flex-start; gap: .65rem; margin-top: 27px; padding-top: 19px; border-top: 1px solid var(--line); }
    .form-actions .button-primary { min-width: 125px; }
    .form-footnote { margin: 11px 0 0; color: var(--muted); font-size: .76rem; }
    .expression-validation-status { margin: .65rem 0 0; padding: .65rem .75rem; border: 1px solid var(--line); border-radius: 8px; font-size: .82rem; overflow-wrap: anywhere; }
    .expression-validation-success { border-color: #b9e4cd; color: var(--success); background: var(--success-soft); }
    .expression-validation-error { border-color: #f1c1be; color: var(--danger); background: var(--danger-soft); }
    .expression-validation-pending { border-color: #bfd0ff; color: #2448bb; background: var(--primary-soft); }
    .template-builder { margin: 13px 0 15px; padding: 13px; border: 1px solid var(--line); border-radius: 10px; background: var(--surface-soft); }
    .template-builder-heading { margin-bottom: 5px; }
    .template-builder-heading label { margin-bottom: .2rem; }
    .template-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 7px 12px; }
    .template-grid .field { margin-top: 9px; }
    .template-grid label { font-size: .8rem; }
    .template-grid input, .template-grid select { padding: .58rem .62rem; font-size: .84rem; }
    .template-actions { display: flex; align-items: center; flex-wrap: wrap; gap: 9px; margin-top: 12px; }
    .template-options-status, .template-generation-status { margin: 0; font-size: .78rem; overflow-wrap: anywhere; }
    .template-options-status { color: var(--muted); }
    .template-options-status.error, .template-generation-status.error { color: var(--danger); }
    .template-generation-status.success { color: var(--success); }
    #status { margin: 0 0 18px; padding: 0; font-size: .9rem; }
    .status-message { display: flex; align-items: flex-start; gap: .6rem; padding: .8rem .95rem; border: 1px solid var(--line); border-radius: 10px; background: var(--surface); }
    .status-success { border-color: #b9e4cd; color: var(--success); background: var(--success-soft); }
    .status-error { border-color: #f1c1be; color: var(--danger); background: var(--danger-soft); }
    .status-pending { border-color: #bfd0ff; color: #2448bb; background: var(--primary-soft); }
    .rules-toolbar { display: grid; grid-template-columns: minmax(0, 1fr) minmax(125px, .42fr); gap: 10px; margin-bottom: 12px; }
    .rules-toolbar label { margin: 0; }
    .search-wrap { position: relative; }
    .search-wrap input { padding-left: 2.4rem; }
    .search-mark { position: absolute; top: 50%; left: .82rem; color: #8b96a9; font-size: 1.05rem; transform: translateY(-53%); pointer-events: none; }
    .results-summary { display: flex; justify-content: space-between; gap: .75rem; align-items: center; margin: 12px 0 15px; color: var(--muted); font-size: .8rem; }
    .rules-list { display: grid; gap: 12px; }
    .rule-card { min-width: 0; padding: 16px; border: 1px solid var(--line); border-radius: 12px; background: #fff; transition: border-color .12s ease, box-shadow .12s ease; }
    .rule-card:hover { border-color: #cbd6e9; box-shadow: 0 4px 14px rgba(28, 43, 74, .05); }
    .rule-card-top { display: flex; align-items: flex-start; justify-content: space-between; gap: .7rem; }
    .rule-title { margin: 0; font-size: .98rem; line-height: 1.35; overflow-wrap: anywhere; }
    .resource-name { display: block; margin-top: .28rem; color: var(--muted); font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .72rem; overflow-wrap: anywhere; }
    .severity-badge { display: inline-flex; align-items: center; flex: 0 0 auto; padding: .25rem .53rem; border-radius: 999px; font-size: .72rem; line-height: 1.2; font-weight: 800; text-transform: uppercase; letter-spacing: .035em; }
    .severity-critical { color: #a72525; background: #ffebeb; }
    .severity-warning { color: #8b5500; background: #fff2d5; }
    .severity-info { color: #145d91; background: #e5f3ff; }
    .rule-summary { margin: 11px 0 0; color: #475467; font-size: .88rem; overflow-wrap: anywhere; }
    .rule-meta { display: flex; flex-wrap: wrap; gap: .35rem .8rem; margin-top: 11px; color: var(--muted); font-size: .76rem; }
    .rule-meta span { display: inline-flex; align-items: center; gap: .25rem; }
    .rule-expression { margin: 12px 0 0; padding: 10px 11px; border-radius: 8px; background: #f6f8fc; color: #344054; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .78rem; line-height: 1.55; overflow-wrap: anywhere; white-space: pre-wrap; }
    .rule-label-heading { margin: 12px 0 0; color: #475467; font-size: .74rem; font-weight: 800; letter-spacing: .06em; text-transform: uppercase; }
    .label-list { display: flex; flex-wrap: wrap; gap: 5px; margin-top: 7px; }
    .label-chip { display: inline-flex; max-width: 100%; padding: .25rem .47rem; border: 1px solid #e1e7f1; border-radius: 6px; background: #f5f7fb; color: #45516a; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .72rem; overflow-wrap: anywhere; }
    .rule-card-actions { display: flex; justify-content: flex-end; gap: .5rem; margin-top: 14px; padding-top: 12px; border-top: 1px solid #edf0f5; }
    .empty-state { padding: 30px 18px; border: 1px dashed var(--line-strong); border-radius: 11px; text-align: center; background: #fbfcff; }
    .empty-state-mark { display: grid; place-items: center; width: 42px; height: 42px; margin: 0 auto 11px; border-radius: 13px; background: var(--primary-soft); color: var(--primary); font-size: 1.2rem; font-weight: 800; }
    .empty-state h3 { margin-bottom: .35rem; }
    .empty-state p { max-width: 340px; margin: 0 auto; color: var(--muted); font-size: .85rem; }
    .loading-state { padding: 20px 10px; color: var(--muted); text-align: center; font-size: .88rem; }
    .page-footer { padding: 20px 0 30px; border-top: 1px solid var(--line); color: var(--muted); font-size: .77rem; }
    code { padding: .1rem .25rem; border-radius: 4px; background: #f0f3f8; color: #344054; overflow-wrap: anywhere; }
    [hidden] { display: none !important; }
    @media (max-width: 1060px) {
      .workspace { grid-template-columns: minmax(0, .95fr) minmax(0, 1.05fr); gap: 14px; }
      .panel-body { padding: 17px; }
      .custom-label-row { grid-template-columns: minmax(0, 1fr) minmax(0, 1fr) auto; }
      .rules-toolbar { grid-template-columns: minmax(0, 1fr); }
    }
    @media (max-width: 780px) {
      .shell { width: min(100% - 28px, 680px); }
      .topbar { align-items: flex-start; flex-wrap: wrap; }
      .top-nav { order: 3; width: 100%; margin: 0; }
      .topbar-right { margin-left: auto; }
      main { padding-top: 25px; }
      .page-heading { align-items: flex-start; flex-direction: column; }
      .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }
      .metric { padding: 15px; }
      .metric-value { font-size: 1.6rem; }
      .workspace { grid-template-columns: minmax(0, 1fr); }
      .workspace > .panel:first-child { order: 1; }
      .workspace > .panel:last-child { order: 2; }
    }
    @media (max-width: 480px) {
      .shell { width: calc(100% - 20px); }
      .topbar { padding: 13px 0; }
      .brand-mark { width: 37px; height: 37px; }
      .brand-subtitle { font-size: .73rem; }
      .user-pill { font-size: .76rem; }
      .top-nav a { padding: .4rem .5rem; font-size: .82rem; }
      .panel-heading { padding: 16px; }
      .panel-body { padding: 14px; }
      .custom-label-row { grid-template-columns: minmax(0, 1fr); }
      .remove-label-button { justify-self: start; }
      .field-grid { grid-template-columns: minmax(0, 1fr); }
      .template-grid { grid-template-columns: minmax(0, 1fr); }
      .rule-card { padding: 13px; }
      .results-summary { align-items: flex-start; flex-direction: column; }
    }
    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after { scroll-behavior: auto !important; transition: none !important; }
    }
  </style>
</head>
<body>
  <div class="shell">
    <header class="topbar">
      <div class="brand" aria-label="Alert Portal">
        <div class="brand-mark" aria-hidden="true">AP</div>
        <div>
          <p class="brand-name">Alert Portal</p>
          <p class="brand-subtitle">Prometheus rule management</p>
        </div>
      </div>
      <nav class="top-nav" aria-label="Main navigation">
        <a href="/">Home</a>
        <a href="/alerts" aria-current="page">Alert rules</a>
        USER_NAV_PLACEHOLDER
      </nav>
      <div class="topbar-right">
        <span class="user-pill"><span class="user-dot" aria-hidden="true"></span> USERNAME_PLACEHOLDER</span>
        <form method="post" action="/logout">
          <input type="hidden" name="csrf_token" value="CSRF_HTML_PLACEHOLDER">
          <button class="button" type="submit">Sign out</button>
        </form>
      </div>
    </header>

    <main>
      <div class="page-heading">
        <div>
          <p class="eyebrow">Monitoring workspace</p>
          <h1>Alert rules</h1>
          <p class="page-intro">View the alert rules Prometheus evaluates. Administrators can manage every rule; editors can create rules and manage only the rules they own.</p>
        </div>
        <div class="heading-actions" EDITOR_CTA_HIDDEN_PLACEHOLDER>
          <button id="new-rule-button" class="button button-primary" type="button">＋ Create alert rule</button>
        </div>
      </div>

      <p id="status" role="status" aria-live="polite" hidden></p>

      <section class="metrics" aria-label="Managed rule counts">
        <div class="metric metric-total"><p class="metric-label">Managed rules</p><p id="metric-total" class="metric-value">—</p></div>
        <div class="metric metric-critical"><p class="metric-label">Critical severity</p><p id="metric-critical" class="metric-value">—</p></div>
        <div class="metric metric-warning"><p class="metric-label">Warning severity</p><p id="metric-warning" class="metric-value">—</p></div>
        <div class="metric metric-info"><p class="metric-label">Info severity</p><p id="metric-info" class="metric-value">—</p></div>
      </section>

      <div class="workspace">
        <section class="panel" id="editor-panel" EDITOR_HIDDEN_PLACEHOLDER>
          <div class="panel-heading">
            <h2 id="form-title">Create alert rule</h2>
            <p>Define when an alert should fire and how teams can identify it.</p>
          </div>
          <div class="panel-body">
            <form id="rule-form">
              <div class="form-section">
                <p class="section-kicker"><span class="section-number">1</span> Alert details</p>
                <p class="section-help">Choose a clear name and severity for this rule.</p>
                <div class="field">
                  <label for="alert-name">Alert name</label>
                  <input id="alert-name" required maxlength="128" pattern="[A-Za-z_][A-Za-z0-9_]*" placeholder="ApplicationTargetDown" autocomplete="off">
                  <p class="field-hint">Start with a letter or underscore; use letters, numbers and underscores.</p>
                </div>
                <div class="field-grid field">
                  <div>
                    <label for="severity">Severity</label>
                    <select id="severity">
                      <option value="warning">Warning</option>
                      <option value="critical">Critical</option>
                      <option value="info">Info</option>
                    </select>
                  </div>
                  <div>
                    <label for="duration">For duration</label>
                    <input id="duration" value="5m" required maxlength="64" placeholder="5m">
                    <p class="field-hint">Example: 0s, 5m, 1h</p>
                  </div>
                </div>
              </div>

              <div class="form-section">
                <p class="section-kicker"><span class="section-number">2</span> Condition</p>
                <p class="section-help">Enter the PromQL expression that defines the alert condition.</p>
                <div class="field">
                  <div id="promql-template-builder" class="template-builder">
                    <div class="template-builder-heading">
                      <label for="promql-template">Start from a query template <span class="optional">(optional)</span></label>
                      <p class="field-hint">Generate a CPU, memory, or disk usage query, then review and validate it before saving.</p>
                    </div>
                    <div class="template-grid">
                      <div class="field">
                        <label for="promql-template">Template</label>
                        <select id="promql-template">
                          <option value="">Custom PromQL (no template)</option>
                          <option value="cpu">CPU usage above threshold</option>
                          <option value="memory">Memory usage above threshold</option>
                          <option value="disk">Disk usage above threshold</option>
                        </select>
                      </div>
                      <div class="field" id="template-threshold-wrap" hidden>
                        <label for="template-threshold">Threshold (%)</label>
                        <input id="template-threshold" type="number" min="1" max="100" step="1" value="80" inputmode="numeric">
                      </div>
                      <div class="field" id="template-job-wrap" hidden>
                        <label for="template-job">Job</label>
                        <select id="template-job">
                          <option value="">All compatible jobs</option>
                        </select>
                      </div>
                      <div class="field" id="template-instance-wrap" hidden>
                        <label for="template-instance">Instance</label>
                        <select id="template-instance">
                          <option value="">All compatible instances</option>
                        </select>
                      </div>
                      <div class="field" id="template-mountpoint-wrap" hidden>
                        <label for="template-mountpoint">Filesystem mount point</label>
                        <select id="template-mountpoint">
                          <option value="">All persistent mount points</option>
                        </select>
                      </div>
                      <div class="field" id="template-device-wrap" hidden>
                        <label for="template-device">Device</label>
                        <select id="template-device">
                          <option value="">All devices</option>
                        </select>
                      </div>
                    </div>
                    <div class="template-actions">
                      <button id="apply-promql-template" class="button button-small" type="button" hidden>Generate query</button>
                      <p id="template-options-status" class="template-options-status" role="status" aria-live="polite" hidden></p>
                      <p id="template-generation-status" class="template-generation-status" role="status" aria-live="polite" hidden></p>
                    </div>
                  </div>
                  <label for="expression">PromQL expression</label>
                  <textarea id="expression" class="promql" required maxlength="4096" placeholder="up == 0" spellcheck="false"></textarea>
                  <p class="field-hint">Keep the expression focused on the condition that needs attention.</p>
                  <p id="expression-validation-status" class="expression-validation-status" role="status" aria-live="polite" hidden></p>
                </div>
              </div>

              <div class="form-section">
                <p class="section-kicker"><span class="section-number">3</span> Alert message</p>
                <div class="field">
                  <label for="summary">Summary</label>
                  <input id="summary" required maxlength="500" placeholder="A monitored target is down">
                </div>
                <div class="field">
                  <label for="description">Description <span class="optional">(optional)</span></label>
                  <textarea id="description" maxlength="2000" placeholder="Additional context or suggested action"></textarea>
                </div>
              </div>

              <div class="form-section">
                <p class="section-kicker"><span class="section-number">4</span> Notification destination</p>
                <div class="field">
                  <label for="notification-destination">Mattermost channel <span class="optional">(optional)</span></label>
                  <select id="notification-destination">
                    <option value="">No Mattermost notification</option>
                  </select>
                  <p class="field-hint">Choose one of your registered destinations. <a href="/destinations">Manage Mattermost destinations</a>. Both firing and resolved notifications are forwarded.</p>
                </div>
              </div>

              <div class="form-section">
                <p class="section-kicker"><span class="section-number">5</span> Labels</p>
                <div class="labels-heading">
                  <h3 style="margin:0">Custom labels <span class="optional">(optional)</span></h3>
                  <span id="label-count" class="label-count">0 labels added</span>
                </div>
                <p class="section-help">Add as many labels as needed. Each name is limited to 63 characters and each value to 256.</p>
                <div id="custom-labels" class="label-editor"></div>
                <button id="add-label-row" class="button add-label-row button-small" type="button">＋ Add label</button>
                <div class="label-guidance">
                  <strong>Automatically managed:</strong> <code>severity</code> is set above and <code>created_by</code> is assigned when the rule is created, and notification-routing labels are managed automatically. Reserved labels cannot be added here. Example labels: <code>team=platform</code>, <code>environment=production</code>.
                </div>
                <p id="label-error" class="label-error" role="alert" hidden></p>
              </div>

              <div class="form-actions">
                <button id="validate-expression-button" class="button" type="button">Validate PromQL</button>
                <button id="submit-button" class="button button-primary" type="submit">Create rule</button>
                <button id="cancel-edit" class="button" type="button" hidden>Cancel edit</button>
              </div>
              <p class="form-footnote">Changes are stored as a Kubernetes PrometheusRule and then picked up by Prometheus.</p>
            </form>
          </div>
        </section>

        <section class="panel" aria-labelledby="managed-rules-title">
          <div class="panel-heading">
            <div class="rule-actions" style="justify-content:space-between">
              <div>
                <h2 id="managed-rules-title">Managed rules</h2>
                <p>Search and filter the rules managed through this portal.</p>
              </div>
              <button id="refresh-button" class="button button-small" type="button">↻ Refresh</button>
            </div>
          </div>
          <div class="panel-body">
            <div class="rules-toolbar">
              <div class="search-wrap">
                <span class="search-mark" aria-hidden="true">⌕</span>
                <label for="rule-search" style="position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0">Search rules</label>
                <input id="rule-search" type="search" placeholder="Search name, expression, creator or label…" autocomplete="off">
              </div>
              <div>
                <label for="severity-filter" style="position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0">Filter by severity</label>
                <select id="severity-filter">
                  <option value="all">All severities</option>
                  <option value="critical">Critical</option>
                  <option value="warning">Warning</option>
                  <option value="info">Info</option>
                </select>
              </div>
            </div>
            <div class="results-summary">
              <span id="result-count">Loading rules…</span>
              <span>Counts reflect managed rule definitions</span>
            </div>
            <div id="rules-list" class="rules-list" aria-live="polite"><div class="loading-state">Loading managed rules…</div></div>
          </div>
        </section>
      </div>
    </main>
    <footer class="page-footer">Alert Portal · Rule configuration is managed through Kubernetes and evaluated by Prometheus.</footer>
  </div>

<script>
"use strict";

const csrfToken = CSRF_JS_PLACEHOLDER;
// Role-level permission to create rules. Edit/delete permissions are per rule.
const canEdit = CAN_EDIT_PLACEHOLDER;

const form = document.getElementById("rule-form");
const editorPanel = document.getElementById("editor-panel");
const formTitle = document.getElementById("form-title");
const submitButton = document.getElementById("submit-button");
const validateExpressionButton = document.getElementById("validate-expression-button");
const expressionInput = document.getElementById("expression");
const expressionValidationStatus = document.getElementById("expression-validation-status");
const promqlTemplateSelect = document.getElementById("promql-template");
const templateThresholdWrap = document.getElementById("template-threshold-wrap");
const templateThresholdInput = document.getElementById("template-threshold");
const templateJobWrap = document.getElementById("template-job-wrap");
const templateJobSelect = document.getElementById("template-job");
const templateInstanceWrap = document.getElementById("template-instance-wrap");
const templateInstanceSelect = document.getElementById("template-instance");
const templateMountpointWrap = document.getElementById("template-mountpoint-wrap");
const templateMountpointSelect = document.getElementById("template-mountpoint");
const templateDeviceWrap = document.getElementById("template-device-wrap");
const templateDeviceSelect = document.getElementById("template-device");
const applyPromqlTemplateButton = document.getElementById("apply-promql-template");
const templateOptionsStatus = document.getElementById("template-options-status");
const templateGenerationStatus = document.getElementById("template-generation-status");
const cancelButton = document.getElementById("cancel-edit");
const list = document.getElementById("rules-list");
const status = document.getElementById("status");
const searchInput = document.getElementById("rule-search");
const severityFilter = document.getElementById("severity-filter");
const resultCount = document.getElementById("result-count");
const customLabelsContainer = document.getElementById("custom-labels");
const addLabelButton = document.getElementById("add-label-row");
const labelCount = document.getElementById("label-count");
const labelError = document.getElementById("label-error");
const notificationDestinationSelect = document.getElementById("notification-destination");

let editingName = null;
let allRules = [];
let notificationDestinationsLoaded = false;
let labelRowSequence = 0;
let dirty = false;
let expressionValidationRequestId = 0;
let liveTemplateOptions = { targets: [], filesystems: [] };

const LABEL_NAME_MAX = 63;
const LABEL_VALUE_MAX = 256;
const RESERVED_LABELS = new Set(["severity", "created_by", "alertname", "alert_route", "portal_destination"]);
const LABEL_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;

function showStatus(message, type = "info") {
  status.textContent = message;
  status.hidden = !message;
  status.className = message ? `status-message status-${type}` : "";
  status.setAttribute("role", type === "error" ? "alert" : "status");
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (options.method && options.method !== "GET") {
    headers.set("X-CSRF-Token", csrfToken);
    if (options.body) headers.set("Content-Type", "application/json");
  }

  const response = await fetch(path, {
    ...options,
    headers,
    credentials: "same-origin",
    cache: "no-store"
  });

  let data = {};
  try { data = await response.json(); } catch (_) { data = {}; }
  if (!response.ok) {
    let message = data.detail || `Request failed (HTTP ${response.status})`;
    if (Array.isArray(message)) message = message.map(item => item.msg || String(item)).join("; ");
    throw new Error(message);
  }
  return data;
}

async function loadNotificationDestinations(selectedDestinationId = "") {
  notificationDestinationsLoaded = false;
  notificationDestinationSelect.replaceChildren();
  const noDestination = document.createElement("option");
  noDestination.value = "";
  noDestination.textContent = "No Mattermost notification";
  notificationDestinationSelect.appendChild(noDestination);

  try {
    const data = await api("/api/destinations");
    const items = Array.isArray(data.items) ? data.items : [];
    for (const destination of items) {
      const option = document.createElement("option");
      option.value = destination.id;
      option.textContent = `${destination.name} — ${destination.team_name} / ${destination.channel_name}`;
      notificationDestinationSelect.appendChild(option);
    }
    if (selectedDestinationId && !items.some(item => item.id === selectedDestinationId)) {
      const existing = document.createElement("option");
      existing.value = selectedDestinationId;
      existing.textContent = "Existing destination (registered by another user)";
      notificationDestinationSelect.appendChild(existing);
    }
    notificationDestinationSelect.value = selectedDestinationId || "";
    notificationDestinationsLoaded = true;
  } catch (error) {
    notificationDestinationSelect.value = "";
    showStatus(`Mattermost destinations could not be loaded. Refresh before editing rules so routing is not accidentally changed. ${error.message}`, "error");
  }
}

function setExpressionValidationStatus(message, type = "pending") {
  expressionValidationStatus.textContent = message;
  expressionValidationStatus.hidden = !message;
  expressionValidationStatus.className = message
    ? `expression-validation-status expression-validation-${type}`
    : "expression-validation-status";
  expressionValidationStatus.setAttribute("role", type === "error" ? "alert" : "status");
}

function clearExpressionValidation() {
  expressionValidationRequestId += 1;
  setExpressionValidationStatus("");
}

async function validatePromQLExpression() {
  const expression = expressionInput.value.trim();
  if (!expression) {
    clearExpressionValidation();
    setExpressionValidationStatus("Enter a PromQL expression before validating it.", "error");
    expressionInput.focus();
    return;
  }

  const requestId = ++expressionValidationRequestId;
  validateExpressionButton.disabled = true;
  validateExpressionButton.textContent = "Validating…";
  setExpressionValidationStatus("Querying Prometheus…", "pending");

  try {
    const result = await api("/api/rules/validate-expression", {
      method: "POST",
      body: JSON.stringify({ expression })
    });
    if (requestId !== expressionValidationRequestId) return;

    if (result.valid && result.result_type === "vector") {
      if (result.has_results) {
        const count = Number.isInteger(result.result_count) ? result.result_count : 0;
        const countMessage = Number.isInteger(result.result_limit) && count >= result.result_limit
          ? `at least ${count} series (results are capped at ${result.result_limit})`
          : `${count} series`;
        setExpressionValidationStatus(
          `Valid PromQL. The current query returned ${countMessage}. This is a point-in-time check and does not predict whether an alert will fire later.`,
          "success"
        );
      } else {
        setExpressionValidationStatus(
          "Valid PromQL. The query currently returns no matching series. It may still be useful when matching series appear.",
          "success"
        );
      }
    } else if (result.kind === "invalid") {
      setExpressionValidationStatus(`Invalid alert expression: ${result.message || "Prometheus rejected this expression."}`, "error");
    } else {
      setExpressionValidationStatus(`Prometheus could not evaluate this expression: ${result.message || "No additional details were returned."}`, "error");
    }
  } catch (error) {
    if (requestId === expressionValidationRequestId) {
      setExpressionValidationStatus(`PromQL validation unavailable: ${error.message}`, "error");
    }
  } finally {
    validateExpressionButton.disabled = false;
    validateExpressionButton.textContent = "Validate PromQL";
  }
}


const TEMPLATE_DEFAULT_THRESHOLDS = { cpu: 80, memory: 85, disk: 80 };
const PSEUDO_FILESYSTEM_TYPES = "tmpfs|overlay|squashfs|ramfs|devtmpfs|proc|sysfs|cgroup2?|pstore|debugfs|tracefs|securityfs|bpf|configfs|efivarfs|autofs|nsfs|hugetlbfs|mqueue|fusectl";
const TEMPLATE_LABELS = {
  cpu: "CPU usage",
  memory: "Memory usage",
  disk: "Disk usage"
};

function setTemplateOptionsStatus(message, isError = false) {
  templateOptionsStatus.textContent = message;
  templateOptionsStatus.hidden = !message;
  templateOptionsStatus.className = `template-options-status${isError ? " error" : ""}`;
}

function setTemplateGenerationStatus(message, type = "success") {
  templateGenerationStatus.textContent = message;
  templateGenerationStatus.hidden = !message;
  templateGenerationStatus.className = `template-generation-status${message ? ` ${type}` : ""}`;
  templateGenerationStatus.setAttribute("role", type === "error" ? "alert" : "status");
}

function fillTemplateSelect(select, values, allLabel, selectedValue = select.value) {
  select.replaceChildren();
  const allOption = document.createElement("option");
  allOption.value = "";
  allOption.textContent = allLabel;
  select.appendChild(allOption);
  for (const value of values) {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = value;
    select.appendChild(option);
  }
  select.value = values.includes(selectedValue) ? selectedValue : "";
}

function uniqueSorted(values) {
  return [...new Set(values.filter(value => typeof value === "string" && value !== ""))].sort();
}

function currentTargets() {
  const job = templateJobSelect.value;
  return liveTemplateOptions.targets.filter(target => !job || target.job === job);
}

function updateTemplateInstanceOptions() {
  const selectedInstance = templateInstanceSelect.value;
  const instances = uniqueSorted(currentTargets().map(target => target.instance));
  fillTemplateSelect(
    templateInstanceSelect,
    instances,
    "All compatible instances",
    selectedInstance
  );
}

function currentFilesystemChoices() {
  const job = templateJobSelect.value;
  const instance = templateInstanceSelect.value;
  return liveTemplateOptions.filesystems.filter(filesystem =>
    (!job || filesystem.job === job) &&
    (!instance || filesystem.instance === instance)
  );
}

function updateTemplateFilesystemOptions() {
  const filesystems = currentFilesystemChoices();
  const chosenMountpoint = templateMountpointSelect.value;
  const chosenDevice = templateDeviceSelect.value;

  const mountpoints = uniqueSorted(filesystems.map(filesystem => filesystem.mountpoint));
  fillTemplateSelect(
    templateMountpointSelect,
    mountpoints,
    "All persistent mount points",
    chosenMountpoint
  );

  const effectiveMountpoint = templateMountpointSelect.value;
  const devices = uniqueSorted(filesystems
    .filter(filesystem => !effectiveMountpoint || filesystem.mountpoint === effectiveMountpoint)
    .map(filesystem => filesystem.device));
  fillTemplateSelect(templateDeviceSelect, devices, "All devices", chosenDevice);
}

async function loadPromQLTemplateOptions() {
  try {
    const options = await api("/api/rules/template-options");
    liveTemplateOptions = {
      targets: Array.isArray(options.targets) ? options.targets : [],
      filesystems: Array.isArray(options.filesystems) ? options.filesystems : []
    };
    const jobs = uniqueSorted(liveTemplateOptions.targets.map(target => target.job));
    fillTemplateSelect(templateJobSelect, jobs, "All compatible jobs", templateJobSelect.value);
    updateTemplateInstanceOptions();
    updateTemplateFilesystemOptions();
    setTemplateOptionsStatus(
      `Loaded ${liveTemplateOptions.targets.length} compatible targets and ` +
      `${liveTemplateOptions.filesystems.length} persistent filesystems from Prometheus.`
    );
  } catch (_) {
    liveTemplateOptions = { targets: [], filesystems: [] };
    fillTemplateSelect(templateJobSelect, [], "All compatible jobs", "");
    fillTemplateSelect(templateInstanceSelect, [], "All compatible instances", "");
    fillTemplateSelect(templateMountpointSelect, [], "All persistent mount points", "");
    fillTemplateSelect(templateDeviceSelect, [], "All devices", "");
    setTemplateOptionsStatus(
      "Live target choices are unavailable. You can still generate an all-target query and validate it.",
      true
    );
  }
}

function updatePromQLTemplateControls() {
  const template = promqlTemplateSelect.value;
  const selected = Boolean(template);
  templateThresholdWrap.hidden = !selected;
  templateJobWrap.hidden = !selected;
  templateInstanceWrap.hidden = !selected;
  templateMountpointWrap.hidden = template !== "disk";
  templateDeviceWrap.hidden = template !== "disk";
  applyPromqlTemplateButton.hidden = !selected;
  if (selected && Object.prototype.hasOwnProperty.call(TEMPLATE_DEFAULT_THRESHOLDS, template)) {
    templateThresholdInput.value = String(TEMPLATE_DEFAULT_THRESHOLDS[template]);
  }
  setTemplateGenerationStatus("");
}

function promqlQuote(value) {
  return `"${String(value)
    .replace(/\\/g, "\\\\")
    .replace(/"/g, "\\\"")
    .replace(/\n/g, "\\n")
    .replace(/\r/g, "\\r")
    .replace(/\t/g, "\\t")}"`;
}

function templateSelector(metric, extraMatchers = []) {
  const matchers = [...extraMatchers];
  const job = templateJobSelect.value;
  const instance = templateInstanceSelect.value;
  if (job) matchers.push(`job=${promqlQuote(job)}`);
  if (instance) matchers.push(`instance=${promqlQuote(instance)}`);
  return matchers.length ? `${metric}{${matchers.join(", ")}}` : metric;
}

function generatePromQLTemplate() {
  const template = promqlTemplateSelect.value;
  if (!template || !Object.prototype.hasOwnProperty.call(TEMPLATE_DEFAULT_THRESHOLDS, template)) {
    setTemplateGenerationStatus("Choose a template first.", "error");
    return;
  }

  const threshold = templateThresholdInput.valueAsNumber;
  if (!Number.isFinite(threshold) || threshold < 1 || threshold > 100) {
    setTemplateGenerationStatus("Threshold must be between 1 and 100 percent.", "error");
    templateThresholdInput.focus();
    return;
  }

  if (templateJobSelect.value && !uniqueSorted(liveTemplateOptions.targets.map(item => item.job)).includes(templateJobSelect.value)) {
    setTemplateGenerationStatus("Choose a job from the available Prometheus options.", "error");
    return;
  }
  if (templateInstanceSelect.value && !currentTargets().some(item => item.instance === templateInstanceSelect.value)) {
    setTemplateGenerationStatus("Choose an instance available for the selected job.", "error");
    return;
  }

  let expression;
  if (template === "cpu") {
    const idleCpu = templateSelector(
      "node_cpu_seconds_total",
      ['mode="idle"']
    );
    expression = `100 * (1 - avg by (job, instance) (rate(${idleCpu}[5m]))) > ${threshold}`;
  } else if (template === "memory") {
    const available = templateSelector("node_memory_MemAvailable_bytes");
    const total = templateSelector("node_memory_MemTotal_bytes");
    expression = `100 * (1 - (${available} / ${total})) > ${threshold}`;
  } else {
    const extraMatchers = [`fstype!~${promqlQuote(PSEUDO_FILESYSTEM_TYPES)}`];
    if (templateMountpointSelect.value) {
      extraMatchers.push(`mountpoint=${promqlQuote(templateMountpointSelect.value)}`);
    }
    if (templateDeviceSelect.value) {
      extraMatchers.push(`device=${promqlQuote(templateDeviceSelect.value)}`);
    }
    const available = templateSelector("node_filesystem_avail_bytes", extraMatchers);
    const total = templateSelector("node_filesystem_size_bytes", extraMatchers);
    expression = `100 * (1 - (${available} / ${total})) > ${threshold}`;
  }

  expressionInput.value = expression;
  clearExpressionValidation();
  formHasChanged();
  setTemplateGenerationStatus(
    `${TEMPLATE_LABELS[template]} query generated. Review it below, then validate it before saving.`,
    "success"
  );
  expressionInput.focus();
}

promqlTemplateSelect.addEventListener("change", updatePromQLTemplateControls);
templateJobSelect.addEventListener("change", () => {
  updateTemplateInstanceOptions();
  updateTemplateFilesystemOptions();
});
templateInstanceSelect.addEventListener("change", updateTemplateFilesystemOptions);
templateMountpointSelect.addEventListener("change", updateTemplateFilesystemOptions);
templateDeviceSelect.addEventListener("change", updateTemplateFilesystemOptions);
applyPromqlTemplateButton.addEventListener("click", generatePromQLTemplate);


function addText(parent, tagName, text, className = "") {
  const element = document.createElement(tagName);
  element.textContent = text == null ? "" : String(text);
  if (className) element.className = className;
  parent.appendChild(element);
  return element;
}

function appendMeta(parent, label, value) {
  const span = document.createElement("span");
  addText(span, "strong", `${label}: `);
  span.appendChild(document.createTextNode(value == null || value === "" ? "—" : String(value)));
  parent.appendChild(span);
}

function updateLabelCount() {
  const rows = [...customLabelsContainer.querySelectorAll(".custom-label-row")];
  const count = rows.filter(row => {
    const inputs = row.querySelectorAll("input");
    return inputs[0].value.trim() !== "" || inputs[1].value.trim() !== "";
  }).length;
  labelCount.textContent = `${count} label${count === 1 ? "" : "s"} added`;
}

function clearLabelError() {
  labelError.textContent = "";
  labelError.hidden = true;
  customLabelsContainer.querySelectorAll("input").forEach(input => input.removeAttribute("aria-invalid"));
}

function addLabelRow(name = "", value = "") {
  labelRowSequence += 1;
  const row = document.createElement("div");
  row.className = "custom-label-row";

  const nameField = document.createElement("div");
  nameField.className = "label-field";
  const nameId = `custom-label-name-${labelRowSequence}`;
  const nameLabel = document.createElement("label");
  nameLabel.htmlFor = nameId;
  nameLabel.textContent = "Label name";
  const nameInput = document.createElement("input");
  nameInput.id = nameId;
  nameInput.type = "text";
  nameInput.maxLength = LABEL_NAME_MAX;
  nameInput.pattern = "[A-Za-z_][A-Za-z0-9_]*";
  nameInput.autocomplete = "off";
  nameInput.placeholder = "team";
  nameInput.value = name;
  nameInput.setAttribute("aria-label", "Custom label name");
  const nameCounter = document.createElement("span");
  nameCounter.className = "label-counter";
  nameCounter.setAttribute("aria-live", "polite");

  const valueField = document.createElement("div");
  valueField.className = "label-field";
  const valueId = `custom-label-value-${labelRowSequence}`;
  const valueLabel = document.createElement("label");
  valueLabel.htmlFor = valueId;
  valueLabel.textContent = "Label value";
  const valueInput = document.createElement("input");
  valueInput.id = valueId;
  valueInput.type = "text";
  valueInput.maxLength = LABEL_VALUE_MAX;
  valueInput.autocomplete = "off";
  valueInput.placeholder = "platform";
  valueInput.value = value;
  valueInput.setAttribute("aria-label", "Custom label value");
  const valueCounter = document.createElement("span");
  valueCounter.className = "label-counter";
  valueCounter.setAttribute("aria-live", "polite");

  function refreshCounters() {
    nameCounter.textContent = `${nameInput.value.length}/${LABEL_NAME_MAX} characters`;
    valueCounter.textContent = `${valueInput.value.length}/${LABEL_VALUE_MAX} characters`;
    dirty = true;
    clearLabelError();
    updateLabelCount();
  }
  nameInput.addEventListener("input", refreshCounters);
  valueInput.addEventListener("input", refreshCounters);

  nameField.append(nameLabel, nameInput, nameCounter);
  valueField.append(valueLabel, valueInput, valueCounter);

  const removeButton = document.createElement("button");
  removeButton.type = "button";
  removeButton.className = "remove-label-button";
  removeButton.textContent = "×";
  removeButton.title = "Remove label";
  removeButton.setAttribute("aria-label", "Remove custom label row");
  removeButton.addEventListener("click", () => {
    row.remove();
    dirty = true;
    clearLabelError();
    updateLabelCount();
  });

  row.append(nameField, valueField, removeButton);
  customLabelsContainer.appendChild(row);
  nameCounter.textContent = `${nameInput.value.length}/${LABEL_NAME_MAX} characters`;
  valueCounter.textContent = `${valueInput.value.length}/${LABEL_VALUE_MAX} characters`;
  updateLabelCount();
}

function renderCustomLabels(labels = {}) {
  customLabelsContainer.replaceChildren();
  for (const [name, value] of Object.entries(labels || {})) addLabelRow(name, value);
  if (customLabelsContainer.children.length === 0) addLabelRow();
  updateLabelCount();
  clearLabelError();
}

function collectCustomLabels() {
  const labels = {};
  const rows = customLabelsContainer.querySelectorAll(".custom-label-row");
  for (const row of rows) {
    const inputs = row.querySelectorAll("input");
    const name = inputs[0].value.trim();
    const value = inputs[1].value.trim();
    if (!name && !value) continue;

    let error = "";
    if (!name || !value) error = "Complete both the label name and value, or remove the empty row.";
    else if (name.length > LABEL_NAME_MAX) error = `Label names must be ${LABEL_NAME_MAX} characters or fewer.`;
    else if (value.length > LABEL_VALUE_MAX) error = `Label values must be ${LABEL_VALUE_MAX} characters or fewer.`;
    else if (!LABEL_NAME_PATTERN.test(name) || name.startsWith("__")) error = "Use a valid label name: start with a letter or underscore and use only letters, numbers, or underscores.";
    else if (RESERVED_LABELS.has(name)) error = `The label name '${name}' is reserved and is managed by Alert Portal or Prometheus.`;
    else if (Object.prototype.hasOwnProperty.call(labels, name)) error = `Duplicate label name '${name}'. Each custom label name must be unique.`;
    else if (/[\u0000-\u001f\u007f]/.test(value)) error = "Label values cannot contain control characters.";

    if (error) {
      inputs.forEach(input => input.setAttribute("aria-invalid", "true"));
      labelError.textContent = error;
      labelError.hidden = false;
      inputs[0].focus();
      throw new Error(error);
    }
    labels[name] = value;
  }
  clearLabelError();
  return labels;
}

function formHasChanged() {
  dirty = true;
}

function removeUnownedDestinationOptions() {
  Array.from(notificationDestinationSelect.options)
    .filter(option => option.dataset.unownedDestination === "true")
    .forEach(option => option.remove());
}

function resetForm() {
  clearExpressionValidation();
  editingName = null;
  removeUnownedDestinationOptions();
  form.reset();
  promqlTemplateSelect.value = "";
  updatePromQLTemplateControls();
  renderCustomLabels({});
  notificationDestinationSelect.value = "";
  document.getElementById("duration").value = "5m";
  formTitle.textContent = "Create alert rule";
  submitButton.textContent = "Create rule";
  cancelButton.hidden = true;
  dirty = false;
  clearLabelError();
}

function beginEdit(rule) {
  if (!canEdit || rule.can_edit !== true) {
    showStatus("You do not have permission to edit this alert rule. Refresh the list if your access has changed.", "error");
    return;
  }
  clearExpressionValidation();
  removeUnownedDestinationOptions();
  promqlTemplateSelect.value = "";
  updatePromQLTemplateControls();
  editingName = rule.name;
  document.getElementById("alert-name").value = rule.alert_name;
  document.getElementById("expression").value = rule.expression;
  document.getElementById("duration").value = rule.duration || "0s";
  document.getElementById("severity").value = rule.severity;
  document.getElementById("summary").value = rule.summary;
  document.getElementById("description").value = rule.description || "";
  const destinationId = rule.notification_destination_id || "";
  if (destinationId && !Array.from(notificationDestinationSelect.options).some(option => option.value === destinationId)) {
    const existingDestination = document.createElement("option");
    existingDestination.value = destinationId;
    existingDestination.dataset.unownedDestination = "true";
    existingDestination.textContent = "Existing destination (registered by another user)";
    notificationDestinationSelect.appendChild(existingDestination);
  }
  notificationDestinationSelect.value = destinationId;
  renderCustomLabels(rule.custom_labels || {});
  formTitle.textContent = "Edit alert rule";
  submitButton.textContent = "Save changes";
  cancelButton.hidden = false;
  dirty = false;
  editorPanel.scrollIntoView({ behavior: "smooth", block: "start" });
  document.getElementById("alert-name").focus({ preventScroll: true });
  showStatus(`Editing ${rule.alert_name}. The original creator is preserved.`, "pending");
}

function searchableText(rule) {
  const labelText = Object.entries(rule.labels || {}).map(([key, value]) => `${key}=${value}`).join(" ");
  return [rule.name, rule.alert_name, rule.expression, rule.duration, rule.severity,
    rule.summary, rule.description, rule.created_by, labelText].join(" ").toLocaleLowerCase();
}

function updateMetrics() {
  document.getElementById("metric-total").textContent = String(allRules.length);
  document.getElementById("metric-critical").textContent = String(allRules.filter(rule => rule.severity === "critical").length);
  document.getElementById("metric-warning").textContent = String(allRules.filter(rule => rule.severity === "warning").length);
  document.getElementById("metric-info").textContent = String(allRules.filter(rule => rule.severity === "info").length);
}

function renderRules() {
  const query = searchInput.value.trim().toLocaleLowerCase();
  const severity = severityFilter.value;
  const filteredRules = allRules.filter(rule => {
    return (!query || searchableText(rule).includes(query)) && (severity === "all" || rule.severity === severity);
  });

  list.replaceChildren();
  resultCount.textContent = `${filteredRules.length} of ${allRules.length} rule${allRules.length === 1 ? "" : "s"} shown`;

  if (filteredRules.length === 0) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    addText(empty, "div", query || severity !== "all" ? "⌕" : "✓", "empty-state-mark");
    addText(empty, "h3", allRules.length === 0 ? "No managed rules yet" : "No rules match these filters");
    addText(empty, "p", allRules.length === 0
      ? (canEdit ? "Create your first alert rule using the form. It will be stored in Kubernetes and evaluated by Prometheus." : "No alert rules have been created through this portal yet.")
      : "Try another search term or choose a different severity.");
    if (allRules.length > 0) {
      const clear = addText(empty, "button", "Clear filters", "button button-small");
      clear.type = "button";
      clear.addEventListener("click", () => { searchInput.value = ""; severityFilter.value = "all"; renderRules(); });
    }
    list.appendChild(empty);
    return;
  }

  for (const rule of filteredRules) {
    const card = document.createElement("article");
    card.className = "rule-card";

    const top = document.createElement("div");
    top.className = "rule-card-top";
    const titleGroup = document.createElement("div");
    addText(titleGroup, "h3", rule.alert_name || "Unnamed alert", "rule-title");
    addText(titleGroup, "span", `Resource: ${rule.name || "—"}`, "resource-name");
    const severityClass = ["critical", "warning", "info"].includes(rule.severity) ? `severity-${rule.severity}` : "";
    addText(top, "span", rule.severity || "unknown", `severity-badge ${severityClass}`.trim());
    top.insertBefore(titleGroup, top.firstChild);
    card.appendChild(top);

    if (rule.summary) addText(card, "p", rule.summary, "rule-summary");

    const meta = document.createElement("div");
    meta.className = "rule-meta";
    appendMeta(meta, "Creator", rule.created_by || "Not recorded");
    appendMeta(meta, "For", rule.duration || "0s");
    const mayEditRule = canEdit && rule.can_edit === true;
    const mayDeleteRule = canEdit && rule.can_delete === true;
    if (canEdit && !mayEditRule && !mayDeleteRule) {
      appendMeta(meta, "Access", "View only");
    }
    card.appendChild(meta);

    addText(card, "pre", rule.expression || "No expression", "rule-expression");
    if (rule.description) {
      const description = document.createElement("details");
      description.style.marginTop = "10px";
      const summary = addText(description, "summary", "Description");
      summary.style.color = "#667085";
      summary.style.cursor = "pointer";
      addText(description, "p", rule.description, "rule-summary");
      card.appendChild(description);
    }

    addText(card, "p", "Labels", "rule-label-heading");
    const labels = document.createElement("div");
    labels.className = "label-list";
    const entries = Object.entries(rule.labels || {});
    if (entries.length === 0) addText(labels, "span", "No labels", "label-chip");
    else for (const [key, value] of entries) addText(labels, "span", `${key}=${value}`, "label-chip");
    card.appendChild(labels);

    if (mayEditRule || mayDeleteRule) {
      const actions = document.createElement("div");
      actions.className = "rule-card-actions";
      if (mayEditRule) {
        const editButton = addText(actions, "button", "Edit rule", "button button-small");
        editButton.type = "button";
        editButton.addEventListener("click", () => {
          if (dirty && !window.confirm("Discard the unsaved changes and edit a different rule?")) return;
          beginEdit(rule);
        });
      }

      if (mayDeleteRule) {
        const deleteButton = addText(actions, "button", "Delete", "button button-small button-danger");
        deleteButton.type = "button";
        deleteButton.addEventListener("click", async () => {
          if (!window.confirm(`Delete alert "${rule.alert_name}"? This cannot be undone.`)) return;
          deleteButton.disabled = true;
          try {
            await api(`/api/rules/${encodeURIComponent(rule.name)}`, { method: "DELETE" });
            showStatus(`Deleted ${rule.alert_name}.`, "success");
            if (editingName === rule.name) resetForm();
            await loadRules();
          } catch (error) {
            showStatus(error.message, "error");
            deleteButton.disabled = false;
            await loadRules();
          }
        });
      }
      card.appendChild(actions);
    }
    list.appendChild(card);
  }
}

async function loadRules() {
  list.replaceChildren();
  const loading = addText(list, "div", "Loading managed rules…", "loading-state");
  loading.setAttribute("role", "status");
  resultCount.textContent = "Loading rules…";
  try {
    const data = await api("/api/rules");
    allRules = Array.isArray(data.items) ? data.items : [];
    if (editingName && !allRules.some(rule => rule.name === editingName && rule.can_edit === true)) {
      resetForm();
      showStatus("The selected alert rule is no longer available for editing. Your changes were not saved.", "error");
    }
    updateMetrics();
    renderRules();
  } catch (error) {
    allRules = [];
    updateMetrics();
    list.replaceChildren();
    const empty = document.createElement("div");
    empty.className = "empty-state";
    addText(empty, "div", "!", "empty-state-mark");
    addText(empty, "h3", "Could not load alert rules");
    addText(empty, "p", error.message);
    const retry = addText(empty, "button", "Try again", "button button-primary");
    retry.type = "button";
    retry.style.marginTop = "14px";
    retry.addEventListener("click", loadRules);
    list.appendChild(empty);
    resultCount.textContent = "Rules unavailable";
  }
}

if (!canEdit) {
  editorPanel.hidden = true;
}

if (canEdit) {
  document.getElementById("new-rule-button").addEventListener("click", () => {
    if (dirty && !window.confirm("Discard the unsaved changes and start a new rule?")) return;
    resetForm();
    showStatus("Ready to create a new alert rule.", "pending");
    editorPanel.scrollIntoView({ behavior: "smooth", block: "start" });
    document.getElementById("alert-name").focus({ preventScroll: true });
  });
}

expressionInput.addEventListener("input", clearExpressionValidation);
validateExpressionButton.addEventListener("click", validatePromQLExpression);
form.addEventListener("input", formHasChanged);
form.addEventListener("change", formHasChanged);
form.addEventListener("submit", async event => {
  event.preventDefault();
  if (!canEdit) {
    showStatus("This account can view rules but cannot change them.", "error");
    return;
  }
  if (editingName && !allRules.some(rule => rule.name === editingName && rule.can_edit === true)) {
    showStatus("You do not have permission to edit the selected alert rule. Refresh the rule list.", "error");
    return;
  }
  if (!notificationDestinationsLoaded) {
    showStatus("Mattermost destinations have not loaded. Refresh the page before saving so notification routing is preserved.", "error");
    return;
  }

  let customLabels;
  try {
    customLabels = collectCustomLabels();
  } catch (error) {
    showStatus(error.message, "error");
    return;
  }

  const payload = {
    alert_name: document.getElementById("alert-name").value.trim(),
    expression: document.getElementById("expression").value.trim(),
    duration: document.getElementById("duration").value.trim(),
    severity: document.getElementById("severity").value,
    summary: document.getElementById("summary").value.trim(),
    description: document.getElementById("description").value.trim(),
    custom_labels: customLabels,
    notification_destination_id: notificationDestinationSelect.value || null
  };

  submitButton.disabled = true;
  showStatus(editingName ? "Saving your changes…" : "Creating the alert rule…", "pending");
  try {
    if (editingName) {
      await api(`/api/rules/${encodeURIComponent(editingName)}`, { method: "PUT", body: JSON.stringify(payload) });
      showStatus("Alert rule updated successfully.", "success");
    } else {
      await api("/api/rules", { method: "POST", body: JSON.stringify(payload) });
      showStatus("Alert rule created successfully.", "success");
    }
    resetForm();
    await loadRules();
  } catch (error) {
    showStatus(error.message, "error");
  } finally {
    submitButton.disabled = false;
  }
});

cancelButton.addEventListener("click", () => {
  if (dirty && !window.confirm("Discard the unsaved changes?")) return;
  resetForm();
  showStatus("Editing cancelled. No changes were saved.", "pending");
});

addLabelButton.addEventListener("click", () => {
  addLabelRow();
  customLabelsContainer.lastElementChild.querySelector("input").focus();
});
searchInput.addEventListener("input", renderRules);
severityFilter.addEventListener("change", renderRules);
document.getElementById("refresh-button").addEventListener("click", loadRules);

renderCustomLabels({});
updateMetrics();
(async function initializeDashboard() {
  await loadNotificationDestinations();
  await loadRules();
  if (canEdit) {
    updatePromQLTemplateControls();
    loadPromQLTemplateOptions();
  }
})();
</script>
</body>
</html>
"""

    user_nav = '<a href="/destinations">Mattermost destinations</a>'
    if is_admin:
        user_nav += '<a href="/users">User management</a>'
    replacements = {
        "USERNAME_PLACEHOLDER": escape(user.username),
        "CSRF_HTML_PLACEHOLDER": escape(csrf_token, quote=True),
        "CSRF_JS_PLACEHOLDER": json.dumps(csrf_token),
        "CAN_EDIT_PLACEHOLDER": "true" if can_edit else "false",
        "EDITOR_HIDDEN_PLACEHOLDER": "" if can_edit else "hidden",
        "EDITOR_CTA_HIDDEN_PLACEHOLDER": "" if can_edit else "hidden",
        "USER_NAV_PLACEHOLDER": user_nav,
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
