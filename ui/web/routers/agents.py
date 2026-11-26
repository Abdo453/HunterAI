"""
HunterAI Control Center — Agent Lifecycle Router
=================================================
Exposes start, pause, stop, restart, pause-all, and live status endpoints for
managed security agents (`brain`, `browser`, `burp`, `code_intel`).
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Body, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from core.dashboard.agent_manager import AgentManager, get_agent_manager
from core.dashboard.live_feed import LiveFeedManager, get_live_feed_manager

router = APIRouter(prefix="/api/agents", tags=["agents"])


class AgentStartRequest(BaseModel):
    """Optional payload when starting an agent."""

    target: Optional[str] = None
    task: Optional[str] = None


def _dispatch_agent_action(result: Dict[str, Any]) -> Dict[str, Any] | JSONResponse:
    """Return HTTP 404 when AgentManager reports an unknown agent."""
    if isinstance(result, dict) and result.get("ok") is False:
        err = str(result.get("error", "")).lower()
        if "unknown" in err or "not found" in err:
            return JSONResponse(status_code=404, content={**result, "detail": result.get("error")})
    return result


@router.get("")
async def list_agents_status() -> Dict[str, Any]:
    """Return current status and telemetry for all managed agents."""
    manager: AgentManager = get_agent_manager()
    return manager.get_all_status()


@router.post("/pause-all")
async def pause_all_agents() -> Dict[str, Any]:
    """Pause all active agents without wiping collected evidence."""
    manager: AgentManager = get_agent_manager()
    result = manager.pause_all()
    get_live_feed_manager()
    return result


@router.post("/{agent_id}/start")
async def start_agent(
    agent_id: str,
    payload: Optional[AgentStartRequest] = Body(default=None),
):
    """Start or resume a specific agent with optional target and task context."""
    manager: AgentManager = get_agent_manager()
    try:
        result = manager.start_agent(
            agent_id,
            target=payload.target if payload else None,
            task=payload.task if payload else None,
        )
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return _dispatch_agent_action(result)


@router.post("/{agent_id}/pause")
async def pause_agent(agent_id: str):
    """Pause a running agent."""
    manager: AgentManager = get_agent_manager()
    try:
        result = manager.pause_agent(agent_id)
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return _dispatch_agent_action(result)


@router.post("/{agent_id}/stop")
async def stop_agent(agent_id: str):
    """Stop a specific agent."""
    manager: AgentManager = get_agent_manager()
    try:
        result = manager.stop_agent(agent_id)
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return _dispatch_agent_action(result)


@router.post("/{agent_id}/restart")
async def restart_agent(agent_id: str):
    """Restart a specific agent."""
    manager: AgentManager = get_agent_manager()
    try:
        result = manager.restart_agent(agent_id)
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return _dispatch_agent_action(result)
