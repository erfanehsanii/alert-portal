"""Mattermost bot destinations and authenticated Alertmanager forwarding."""

from __future__ import annotations

import json
import os
import secrets
from html import escape
from typing import Annotated, Any

import psycopg
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from app.auth.dependencies import AuthenticatedUser, get_current_user, require_roles
from app.auth.security import hash_csrf_token, hash_session_token
from app.routes.rules import require_valid_csrf
from app.services.audit import record_audit_event
from app.services.database import get_database_connection
from app.services.mattermost_destinations import (
    DestinationConfigurationError,
    DestinationConflictError,
    DestinationNotFoundError,
    DestinationValidationError,
    MattermostDeliveryError,
    canonical_destination_id,
    create_user_destination,
    delete_user_destination,
    forward_alertmanager_notification,
    is_destination_used_in_legacy_routes,
    legacy_route_keys,
    list_legacy_route_mappings,
    list_mattermost_channels,
    list_user_destinations,
    update_legacy_route_mappings,
)
from app.services.prometheus_rules import KubernetesServiceError, list_portal_rules


router = APIRouter(tags=["mattermost destinations"])
MAX_WEBHOOK_BODY_BYTES = 4_194_304


class CreateDestinationPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=80)
    channel_id: str = Field(min_length=20, max_length=32)


class LegacyRouteMappingsPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    routes: dict[str, str] = Field(min_length=4, max_length=4)


def _safe_audit(*, action: str, user: AuthenticatedUser, destination: dict[str, Any]) -> None:
    """Audit channel metadata only; never record access tokens or webhook URLs."""
    record_audit_event(
        action=action,
        actor_user_id=user.id,
        target_type="mattermost_bot_destination",
        target_id=destination["id"],
        details={
            "name": destination["name"],
            "team_name": destination["team_name"],
            "channel_name": destination["channel_name"],
            "channel_id": destination["channel_id"],
        },
    )


def _destination_error(exc: Exception) -> HTTPException:
    if isinstance(exc, DestinationValidationError):
        return HTTPException(status_code=422, detail=str(exc))
    if isinstance(exc, DestinationNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, DestinationConflictError):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, DestinationConfigurationError):
        return HTTPException(
            status_code=503,
            detail="Mattermost bot integration is not configured correctly. Ask an administrator to verify the bot token and server settings.",
        )
    if isinstance(exc, MattermostDeliveryError):
        return HTTPException(
            status_code=502,
            detail="Mattermost could not accept the notification. Alertmanager may retry.",
        )
    if isinstance(exc, KubernetesServiceError):
        return HTTPException(status_code=503, detail="The alert-rule service is temporarily unavailable.")
    if isinstance(exc, psycopg.Error):
        return HTTPException(status_code=503, detail="The database service is temporarily unavailable.")
    return HTTPException(status_code=503, detail="Mattermost destination handling is temporarily unavailable.")


@router.get("/api/mattermost/channels")
def channels_available_to_bot(user: AuthenticatedUser = Depends(get_current_user)):
    """List only standard channels the configured bot can access."""
    try:
        return list_mattermost_channels()
    except (DestinationConfigurationError, DestinationValidationError, MattermostDeliveryError) as exc:
        raise _destination_error(exc) from None


@router.get("/api/destinations")
def list_destinations(user: AuthenticatedUser = Depends(get_current_user)):
    """List channel destinations owned by the authenticated portal user."""
    try:
        return {"items": list_user_destinations(user.id)}
    except (DestinationConfigurationError, DestinationValidationError,
            DestinationNotFoundError, DestinationConflictError,
            MattermostDeliveryError, KubernetesServiceError, psycopg.Error) as exc:
        raise _destination_error(exc) from None


@router.post("/api/destinations", status_code=status.HTTP_201_CREATED)
def create_destination(
    payload: CreateDestinationPayload,
    user: AuthenticatedUser = Depends(get_current_user),
    csrf_user: AuthenticatedUser = Depends(require_valid_csrf),
):
    """Register a channel the shared bot is already a member of."""
    try:
        destination = create_user_destination(
            user_id=user.id,
            name=payload.name,
            channel_id=payload.channel_id,
        )
        try:
            _safe_audit(action="mattermost_bot_destination_created", user=user, destination=destination)
        except psycopg.Error:
            raise HTTPException(
                status_code=503,
                detail="The destination was registered, but its audit entry could not be saved. Refresh the list before retrying.",
            ) from None
        return destination
    except HTTPException:
        raise
    except (DestinationConfigurationError, DestinationValidationError,
            DestinationNotFoundError, DestinationConflictError,
            MattermostDeliveryError, KubernetesServiceError, psycopg.Error) as exc:
        raise _destination_error(exc) from None


def _destination_is_used(destination_id: str) -> bool:
    """Prevent deleting a destination used by either a rule or a global route."""
    for resource in list_portal_rules():
        for group in resource.get("spec", {}).get("groups", []) or []:
            for rule in group.get("rules", []) or []:
                labels = rule.get("labels", {}) or {}
                if labels.get("portal_destination") == destination_id:
                    return True
    return is_destination_used_in_legacy_routes(destination_id)


@router.delete("/api/destinations/{destination_id}")
def remove_destination(
    destination_id: str,
    user: AuthenticatedUser = Depends(get_current_user),
    csrf_user: AuthenticatedUser = Depends(require_valid_csrf),
):
    """Delete an owned channel only if no alert rule or system route references it."""
    try:
        destination_id = canonical_destination_id(destination_id)
        # Ownership check occurs inside the service's SELECT/DELETE predicates.
        from app.services.mattermost_destinations import get_user_destination
        destination = get_user_destination(destination_id, user.id)
        if _destination_is_used(destination_id):
            raise HTTPException(
                status_code=409,
                detail="This channel is selected by an alert rule or existing Alertmanager route. Change that routing first.",
            )
        deleted = delete_user_destination(destination_id, user.id)
        try:
            _safe_audit(action="mattermost_bot_destination_deleted", user=user, destination=deleted)
        except psycopg.Error:
            raise HTTPException(
                status_code=503,
                detail="The destination was deleted, but its audit entry could not be saved. Refresh the list before retrying.",
            ) from None
        return {"status": "deleted", "id": deleted["id"]}
    except HTTPException:
        raise
    except (DestinationConfigurationError, DestinationValidationError,
            DestinationNotFoundError, DestinationConflictError,
            MattermostDeliveryError, KubernetesServiceError, psycopg.Error) as exc:
        raise _destination_error(exc) from None


@router.get("/api/mattermost/legacy-routes")
def get_legacy_routes(
    user: AuthenticatedUser = Depends(require_roles("admin")),
):
    """Return system-wide CPU/Disk/Memory/Uptime mappings for administrators."""
    try:
        mappings = {item["route_key"]: item for item in list_legacy_route_mappings()}
        return {
            "route_keys": list(legacy_route_keys()),
            "mappings": {
                key: mappings.get(key, {}).get("id") for key in legacy_route_keys()
            },
            "items": list_legacy_route_mappings(),
            "admin_destinations": list_user_destinations(user.id),
        }
    except (DestinationConfigurationError, DestinationValidationError,
            DestinationNotFoundError, DestinationConflictError,
            MattermostDeliveryError, KubernetesServiceError, psycopg.Error) as exc:
        raise _destination_error(exc) from None


@router.put("/api/mattermost/legacy-routes")
def put_legacy_routes(
    payload: LegacyRouteMappingsPayload,
    user: AuthenticatedUser = Depends(require_roles("admin")),
    csrf_user: AuthenticatedUser = Depends(require_valid_csrf),
):
    """Atomically map the four existing Alertmanager routes to bot destinations."""
    try:
        items = update_legacy_route_mappings(admin_user_id=user.id, routes=payload.routes)
        try:
            record_audit_event(
                action="mattermost_bot_legacy_routes_updated",
                actor_user_id=user.id,
                target_type="mattermost_bot_route_mapping",
                target_id="all",
                details={
                    "routes": {
                        item["route_key"]: {
                            "destination_id": item["id"],
                            "channel_name": item["channel_name"],
                            "channel_id": item["channel_id"],
                        }
                        for item in items
                    }
                },
            )
        except psycopg.Error:
            raise HTTPException(
                status_code=503,
                detail="The route mappings were saved, but the audit entry could not be saved. Refresh to verify the assignments.",
            ) from None
        return {"status": "saved", "items": items}
    except HTTPException:
        raise
    except (DestinationConfigurationError, DestinationValidationError,
            DestinationNotFoundError, DestinationConflictError,
            MattermostDeliveryError, KubernetesServiceError, psycopg.Error) as exc:
        raise _destination_error(exc) from None


@router.post("/api/alertmanager/notify", include_in_schema=False)
async def alertmanager_notify(request: Request):
    """Accept authenticated Alertmanager notifications and post them as the bot."""
    configured_token = os.getenv("ALERTMANAGER_WEBHOOK_TOKEN", "")
    authorization = request.headers.get("authorization", "")
    expected = f"Bearer {configured_token}" if configured_token else ""

    if not configured_token:
        raise HTTPException(status_code=503, detail="Alertmanager webhook authentication is not configured.")
    if not authorization or not secrets.compare_digest(authorization.encode("utf-8"), expected.encode("utf-8")):
        raise HTTPException(status_code=401, detail="Unauthorized Alertmanager webhook.")

    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_WEBHOOK_BODY_BYTES:
                raise HTTPException(status_code=413, detail="Alertmanager payload is too large.")
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid content length.") from None

    body_parts: list[bytes] = []
    body_size = 0
    async for chunk in request.stream():
        body_size += len(chunk)
        if body_size > MAX_WEBHOOK_BODY_BYTES:
            raise HTTPException(status_code=413, detail="Alertmanager payload is too large.")
        body_parts.append(chunk)
    try:
        payload = json.loads(b"".join(body_parts))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(status_code=400, detail="Alertmanager payload must be JSON.") from None

    try:
        result = await run_in_threadpool(forward_alertmanager_notification, payload)
        return JSONResponse(
            result,
            headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
        )
    except (DestinationConfigurationError, DestinationValidationError,
            DestinationNotFoundError, DestinationConflictError,
            MattermostDeliveryError, KubernetesServiceError, psycopg.Error) as exc:
        raise _destination_error(exc) from None


def _redirect_to_login() -> RedirectResponse:
    response = RedirectResponse("/login", status_code=303)
    response.headers["Cache-Control"] = "no-store"
    return response


@router.get("/destinations", response_class=HTMLResponse)
async def destinations_dashboard(request: Request):
    """Render the channel selector and optional administrator route mapping form."""
    session_token = request.cookies.get("alert_portal_session")
    csrf_token = request.cookies.get("alert_portal_csrf")
    if not session_token or not csrf_token:
        return _redirect_to_login()

    try:
        from app.auth.dependencies import get_user_from_session_token
        user = get_user_from_session_token(session_token)
    except HTTPException:
        return _redirect_to_login()

    try:
        with get_database_connection() as connection:
            row = connection.execute(
                """
                SELECT id FROM user_sessions
                WHERE token_hash = %s AND csrf_token_hash = %s AND user_id = %s
                  AND revoked_at IS NULL AND expires_at > NOW()
                """,
                (hash_session_token(session_token), hash_csrf_token(csrf_token), user.id),
            ).fetchone()
    except psycopg.Error:
        return JSONResponse(
            status_code=503,
            content={"detail": "Authentication service temporarily unavailable."},
            headers={"Cache-Control": "no-store"},
        )
    if row is None:
        return _redirect_to_login()

    user_nav = '<a href="/users">User management</a>' if user.role == "admin" else ""
    admin_route_panel = r'''
<section class="panel route-panel">
  <h2>Existing alert route destinations</h2>
  <p class="muted">Map your current CPU, Disk, Memory, and Uptime Alertmanager routes to channels. After the Helm receiver migration, these notifications will also be posted by Alert Portal Bot. Use destinations registered by this administrator account.</p>
  <form id="legacy-route-form">
    <div class="route-grid">
      <div class="field"><label for="route-cpu">CPU alerts</label><select id="route-cpu" data-route="cpu" required><option value="">Choose a channel destination</option></select></div>
      <div class="field"><label for="route-disk">Disk alerts</label><select id="route-disk" data-route="disk" required><option value="">Choose a channel destination</option></select></div>
      <div class="field"><label for="route-memory">Memory alerts</label><select id="route-memory" data-route="memory" required><option value="">Choose a channel destination</option></select></div>
      <div class="field"><label for="route-uptime">Uptime alerts</label><select id="route-uptime" data-route="uptime" required><option value="">Choose a channel destination</option></select></div>
    </div>
    <div class="actions"><button id="save-routes" class="button primary" type="submit">Save all four routes</button></div>
  </form>
  <p id="route-status" class="status" role="status" aria-live="polite" hidden></p>
</section>'''
    if user.role != "admin":
        admin_route_panel = ""

    page = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light"><title>Mattermost destinations — Alert Portal</title>
<style>
:root{font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;color:#172033;background:#f4f6fb;--line:#e1e7f0;--muted:#667085;--primary:#3159d9;--soft:#edf2ff;--danger:#b42318}
*{box-sizing:border-box}body{margin:0;line-height:1.5}a{color:var(--primary);text-decoration:none}.shell{width:min(1120px,calc(100% - 32px));margin:auto}.topbar{display:flex;align-items:center;gap:1rem;flex-wrap:wrap;padding:20px 0;border-bottom:1px solid var(--line)}.brand{display:flex;align-items:center;gap:.7rem;color:inherit;font-weight:800}.brand-mark{display:grid;place-items:center;background:linear-gradient(145deg,#4268ee,#2545b4);color:white;border-radius:12px;width:42px;height:42px}.top-nav{display:flex;gap:.35rem;flex-wrap:wrap;margin-left:auto}.top-nav a{padding:.5rem .7rem;border-radius:8px;color:#48546b;font-size:.9rem;font-weight:500}.top-nav a[aria-current=page]{color:var(--primary);background:var(--soft)}.topbar-right{display:flex;align-items:center;gap:.6rem}.pill{border:1px solid var(--line);border-radius:999px;padding:.4rem .7rem;font-size:.85rem}.button{display:inline-flex;align-items:center;justify-content:center;min-height:40px;padding:.58rem .9rem;border:1px solid #cad4e2;border-radius:9px;background:white;color:#344054;font-weight:700;cursor:pointer}.button:disabled{opacity:.55;cursor:not-allowed}.primary{background:var(--primary);border-color:var(--primary);color:white}.danger{color:var(--danger)}main{padding:34px 0 55px}h1{margin:0 0 .5rem;font-size:clamp(1.8rem,4vw,2.5rem);line-height:1.15;letter-spacing:-.04em}.intro{color:var(--muted);max-width:800px}.layout{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:18px;margin-top:26px}.panel{border:1px solid var(--line);border-radius:14px;background:white;padding:22px;box-shadow:0 5px 20px rgba(28,43,74,.04);min-width:0}.panel h2{font-size:1.1rem;margin:0 0 .35rem}.muted{color:var(--muted);font-size:.9rem}.field{margin-top:18px}.field label{display:block;font-size:.88rem;font-weight:750;margin-bottom:6px}.field input,.field select{display:block;width:100%;padding:.7rem .8rem;border:1px solid #cad4e2;border-radius:8px;background:white;font:inherit}.field-hint{font-size:.82rem;color:var(--muted);margin:.4rem 0 0}.actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:20px}.status{margin:16px 0 0;padding:12px 14px;border-radius:9px;background:#f8faff;color:#344054;white-space:pre-wrap}.status.error{color:var(--danger);background:#fff1f0}.status.success{color:#087443;background:#eaf8f0}.destination{padding:15px 0;border-bottom:1px solid var(--line)}.destination:last-child{border-bottom:0}.destination strong{display:block}.destination .host{font-size:.85rem;color:var(--muted);overflow-wrap:anywhere}.destination .row{display:flex;justify-content:space-between;align-items:flex-start;gap:12px}.empty{border:1px dashed #cad4e2;border-radius:10px;padding:22px;color:var(--muted);text-align:center}.footer{margin-top:24px;padding:18px 0;border-top:1px solid var(--line);color:var(--muted);font-size:.8rem}.route-panel{margin-top:18px}.route-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}@media(max-width:760px){.layout,.route-grid{grid-template-columns:1fr}.topbar-right{margin-left:auto}.top-nav{order:3;width:100%;margin:0}}
</style></head><body><div class="shell">
<header class="topbar"><a class="brand" href="/"><span class="brand-mark">AP</span><span>Alert Portal</span></a>
<nav class="top-nav"><a href="/">Home</a><a href="/alerts">Alert rules</a><a href="/destinations" aria-current="page">Mattermost destinations</a>USER_NAV_PLACEHOLDER</nav>
<div class="topbar-right"><span class="pill">USERNAME_PLACEHOLDER</span><form method="post" action="/logout"><input type="hidden" name="csrf_token" value="CSRF_HTML_PLACEHOLDER"><button class="button" type="submit">Sign out</button></form></div></header>
<main><h1>Mattermost destinations</h1><p class="intro">Choose a channel the shared <strong>Alert Portal Bot</strong> belongs to. Messages are published through the bot's Mattermost API identity; users do not need to create or paste webhook URLs.</p>
<div class="layout"><section class="panel"><h2>Register a channel destination</h2><p class="muted">Only channels where the bot is already a member are listed. Add the bot to a Mattermost team/channel first, then refresh this list.</p>
<form id="destination-form"><div class="field"><label for="destination-name">Destination name</label><input id="destination-name" required maxlength="80" placeholder="Platform on-call"></div>
<div class="field"><label for="channel-id">Mattermost channel</label><select id="channel-id" required><option value="">Loading channels accessible to the bot…</option></select><p class="field-hint">Private and public channels are available only when the bot is a member. Direct and group messages are excluded.</p></div>
<div class="actions"><button id="save-destination" class="button primary" type="submit">Register destination</button><button id="refresh-channels" class="button" type="button">Refresh channels</button></div></form><p id="status" class="status" role="status" aria-live="polite" hidden></p></section>
<section class="panel"><h2>Your destinations</h2><p class="muted">Choose one of your registered channels when creating an alert rule. Destinations used by rules or global legacy routes cannot be deleted.</p>
<div id="destination-list"><div class="empty">Loading destinations…</div></div><button id="refresh-destinations" class="button" type="button" style="margin-top:14px">Refresh destinations</button></section></div>
ADMIN_ROUTE_SECTION_PLACEHOLDER
<footer class="footer">Alert Portal · All notifications are sent by the shared Mattermost bot account.</footer></main></div>
<script>
"use strict";
const csrfToken = CSRF_JS_PLACEHOLDER;
const form = document.getElementById("destination-form");
const nameInput = document.getElementById("destination-name");
const channelSelect = document.getElementById("channel-id");
const saveButton = document.getElementById("save-destination");
const list = document.getElementById("destination-list");
const statusNode = document.getElementById("status");
function showStatus(message, kind="info"){statusNode.textContent=message;statusNode.hidden=!message;statusNode.className="status"+(kind==="error"?" error":kind==="success"?" success":"");}
async function api(path, options={}){const headers=new Headers(options.headers||{});if(options.method&&options.method!=="GET"){headers.set("X-CSRF-Token",csrfToken);if(options.body)headers.set("Content-Type","application/json");}const response=await fetch(path,{...options,headers,credentials:"same-origin",cache:"no-store"});let data={};try{data=await response.json()}catch(_){}if(!response.ok){throw new Error(data.detail||`Request failed (HTTP ${response.status})`)}return data;}
function addText(parent,tag,text,className=""){const node=document.createElement(tag);node.textContent=String(text??"");if(className)node.className=className;parent.appendChild(node);return node;}
function destinationLabel(item){return `${item.name} — ${item.team_name} / ${item.channel_name}`;}
async function loadChannels(){channelSelect.replaceChildren();addText(channelSelect,"option","Loading channels accessible to the bot…","").value="";try{const data=await api("/api/mattermost/channels");channelSelect.replaceChildren();const items=Array.isArray(data.items)?data.items:[];if(!items.length){addText(channelSelect,"option","No channels found. Add the bot to a channel.").value="";showStatus("No eligible Mattermost channels were found for the bot.","error");return;}addText(channelSelect,"option","Choose a channel…").value="";for(const item of items){const option=addText(channelSelect,"option",`${item.team_name} / ${item.display_name} (#${item.channel_name})`);option.value=item.id;}showStatus(`Loaded ${items.length} channel(s) available to @${data.bot?.username||"Alert Portal Bot"}.`,"success");}catch(error){channelSelect.replaceChildren();addText(channelSelect,"option","Channels could not be loaded").value="";showStatus(`Mattermost bot configuration or channel lookup failed. ${error.message}`,"error");}}
async function loadDestinations(){list.replaceChildren();addText(list,"div","Loading destinations…","empty");try{const data=await api("/api/destinations");list.replaceChildren();const items=Array.isArray(data.items)?data.items:[];if(!items.length){addText(list,"div","No Mattermost destinations registered yet.","empty");await refreshLegacyDestinationOptions(items);return;}for(const item of items){const card=addText(list,"div","","destination");const row=addText(card,"div","","row");const details=addText(row,"div","");addText(details,"strong",item.name);addText(details,"div",`${item.team_name} / ${item.channel_name} (#${item.channel_id})`,"host");addText(details,"div",`Server: ${item.server_host}`,"host");if(item.created_at)addText(details,"div",`Added ${new Date(item.created_at).toLocaleString()}`,"host");const remove=addText(row,"button","Delete","button danger");remove.type="button";remove.addEventListener("click",async()=>{if(!window.confirm(`Delete destination “${item.name}”?`))return;remove.disabled=true;try{await api(`/api/destinations/${encodeURIComponent(item.id)}`,{method:"DELETE"});showStatus(`Deleted “${item.name}”.`,"success");await loadDestinations();}catch(error){showStatus(error.message,"error");remove.disabled=false;}});}await refreshLegacyDestinationOptions(items);}catch(error){list.replaceChildren();addText(list,"div",error.message,"empty");}}
async function refreshLegacyDestinationOptions(items){const formNode=document.getElementById("legacy-route-form");if(!formNode)return;const prior={};for(const select of formNode.querySelectorAll("select[data-route]"))prior[select.dataset.route]=select.value;for(const select of formNode.querySelectorAll("select[data-route]")){select.replaceChildren();addText(select,"option","Choose a destination…").value="";for(const item of items){const option=addText(select,"option",destinationLabel(item));option.value=item.id;}if(prior[select.dataset.route])select.value=prior[select.dataset.route];}}
async function loadLegacyRoutes(){const routeForm=document.getElementById("legacy-route-form");if(!routeForm)return;const routeStatus=document.getElementById("route-status");try{const data=await api("/api/mattermost/legacy-routes");await refreshLegacyDestinationOptions(data.admin_destinations||[]);for(const select of routeForm.querySelectorAll("select[data-route]"))select.value=data.mappings?.[select.dataset.route]||"";}catch(error){routeStatus.textContent=error.message;routeStatus.hidden=false;routeStatus.className="status error";}}
form.addEventListener("submit",async event=>{event.preventDefault();saveButton.disabled=true;showStatus("Registering channel destination…");try{const item=await api("/api/destinations",{method:"POST",body:JSON.stringify({name:nameInput.value.trim(),channel_id:channelSelect.value})});nameInput.value="";channelSelect.value="";showStatus(`Registered “${item.name}” for ${item.team_name} / ${item.channel_name}. Notifications will be sent by Alert Portal Bot.`,"success");await loadDestinations();}catch(error){showStatus(error.message,"error");}finally{saveButton.disabled=false;}});
document.getElementById("refresh-destinations").addEventListener("click",loadDestinations);
document.getElementById("refresh-channels").addEventListener("click",loadChannels);
const routeForm=document.getElementById("legacy-route-form");
if(routeForm){routeForm.addEventListener("submit",async event=>{event.preventDefault();const button=document.getElementById("save-routes");const message=document.getElementById("route-status");const routes={};for(const select of routeForm.querySelectorAll("select[data-route]")){routes[select.dataset.route]=select.value;}if(Object.values(routes).some(value=>!value)){message.textContent="Choose a registered channel for all four routes.";message.hidden=false;message.className="status error";return;}button.disabled=true;message.textContent="Saving existing Alertmanager routes…";message.hidden=false;message.className="status";try{await api("/api/mattermost/legacy-routes",{method:"PUT",body:JSON.stringify({routes})});message.textContent="CPU, Disk, Memory, and Uptime routes are mapped. The routing change takes effect once the Alertmanager Helm receiver overlay is applied.";message.className="status success";}catch(error){message.textContent=error.message;message.className="status error";}finally{button.disabled=false;}});}
loadChannels();loadDestinations();loadLegacyRoutes();
</script></body></html>'''
    replacements = {
        "USERNAME_PLACEHOLDER": escape(user.username),
        "CSRF_HTML_PLACEHOLDER": escape(csrf_token, quote=True),
        "CSRF_JS_PLACEHOLDER": json.dumps(csrf_token),
        "USER_NAV_PLACEHOLDER": user_nav,
        "ADMIN_ROUTE_SECTION_PLACEHOLDER": admin_route_panel,
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
