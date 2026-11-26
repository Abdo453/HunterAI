"""
HunterAI Control Center — Scope & Target Management Router
==========================================================
Manages authorized targets, excluded domains, firewall rules, scope locking
(HTTP 423 Locked), and live target-in-scope checks.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Union

from fastapi import APIRouter, Body, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from core.dashboard.agent_manager import AgentManager, get_agent_manager
from core.dashboard.live_feed import LiveFeedManager, get_live_feed_manager

router = APIRouter(prefix="/api/scope", tags=["scope"])


class ScopeUpdateRequest(BaseModel):
    """Payload for updating target scope, exclusions, and firewall rules."""

    targets: Optional[Union[List[str], str]] = None
    excluded_domains: Optional[Union[List[str], str]] = None
    firewall_rules: Optional[Union[List[str], str]] = None
    active_target: Optional[str] = None


class ScopeTargetRequest(BaseModel):
    """Payload for adding or removing an individual target URL."""

    url: Optional[str] = None
    target: Optional[str] = None


class ScopeLockRequest(BaseModel):
    """Payload for toggling or setting the scope lock state."""

    locked: Optional[bool] = None


class ScopeCheckRequest(BaseModel):
    """Payload for checking whether a target belongs to the authorized scope."""

    target: str
    scope: Optional[List[str]] = None


def _normalize_list_field(value: Optional[Union[List[str], str]]) -> Optional[List[str]]:
    """Normalize newline- or comma-delimited scope strings into clean lists."""
    if value is None:
        return None
    if isinstance(value, str):
        items = [line.strip() for chunk in value.splitlines() for line in chunk.split(",")]
        return [item for item in items if item]
    return [str(item).strip() for item in value if str(item).strip()]


def _locked_or_result(result: Dict[str, Any]) -> Dict[str, Any] | JSONResponse:
    """Return HTTP 423 Locked whenever a scope mutation is blocked by scope lock."""
    if isinstance(result, dict) and result.get("locked") and result.get("ok") is False:
        payload = {**result, "detail": result.get("error", "Scope is locked")}
        return JSONResponse(status_code=423, content=payload)
    return result


@router.get("")
async def get_scope() -> Dict[str, Any]:
    """Return the current scope state, active target, exclusions, and lock status."""
    feed: LiveFeedManager = get_live_feed_manager(get_agent_manager())
    return feed.get_scope_state()


@router.post("")
@router.put("")
async def update_scope(payload: Optional[ScopeUpdateRequest] = Body(default=None)):
    """Update targets, excluded domains, firewall rules, or active target."""
    feed: LiveFeedManager = get_live_feed_manager(get_agent_manager())
    req = payload or ScopeUpdateRequest()
    result = feed.update_scope(
        targets=_normalize_list_field(req.targets),
        excluded_domains=_normalize_list_field(req.excluded_domains),
        firewall_rules=_normalize_list_field(req.firewall_rules),
        active_target=req.active_target,
    )
    return _locked_or_result(result)


@router.post("/targets")
async def add_scope_target(payload: ScopeTargetRequest = Body(...)):
    """Add a target URL to the authorized scope unless locked."""
    feed: LiveFeedManager = get_live_feed_manager(get_agent_manager())
    target_url = (payload.url or payload.target or "").strip()
    if not target_url:
        if feed.get_scope_state().get("locked"):
            return JSONResponse(
                status_code=423,
                content={"ok": False, "locked": True, "error": "Scope is locked", "detail": "Scope is locked"},
            )
        raise HTTPException(status_code=400, detail="Target URL is required")
    return _locked_or_result(feed.add_target(target_url))


@router.delete("/targets")
async def remove_scope_target(
    request: Request,
    url: Optional[str] = Query(default=None),
    target: Optional[str] = Query(default=None),
):
    """Remove a target URL from scope (supports query param or JSON body) unless locked."""
    feed: LiveFeedManager = get_live_feed_manager(get_agent_manager())
    target_url = (url or target or "").strip()
    if not target_url:
        try:
            body = await request.json()
            if isinstance(body, dict):
                target_url = str(body.get("url") or body.get("target") or "").strip()
        except Exception:
            pass

    if not target_url:
        if feed.get_scope_state().get("locked"):
            return JSONResponse(
                status_code=423,
                content={"ok": False, "locked": True, "error": "Scope is locked", "detail": "Scope is locked"},
            )
        raise HTTPException(status_code=400, detail="Target URL is required")

    return _locked_or_result(feed.remove_target(target_url))


@router.post("/lock")
async def lock_scope(payload: Optional[ScopeLockRequest] = Body(default=None)) -> Dict[str, Any]:
    """Lock or unlock scope mutations."""
    feed: LiveFeedManager = get_live_feed_manager(get_agent_manager())
    if payload is not None and payload.locked is not None:
        desired = bool(payload.locked)
    else:
        desired = not bool(feed.get_scope_state().get("locked", False))
    return feed.set_scope_locked(desired)


@router.post("/check")
async def check_scope(payload: ScopeCheckRequest = Body(...)) -> Dict[str, Any]:
    """Verify whether a target is permitted within the given or active scope."""
    feed: LiveFeedManager = get_live_feed_manager(get_agent_manager())
    return feed.check_target_scope(target=payload.target, scope=payload.scope)
