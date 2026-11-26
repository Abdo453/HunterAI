"""
HunterAI Control Center — MCP Server Monitor Router
===================================================
Provides status monitoring, failed server retries, and dynamic server
configuration endpoints backed by `opencode.json`.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Body, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from core.dashboard.agent_manager import AgentManager, get_agent_manager
from core.dashboard.live_feed import LiveFeedManager, get_live_feed_manager

router = APIRouter(prefix="/api/mcp", tags=["mcp"])


class McpRetryRequest(BaseModel):
    """Optional payload targeting a specific MCP server to retry."""

    server_id: Optional[str] = None


class McpConfigureRequest(BaseModel):
    """Payload to update an MCP server configuration."""

    server_id: str
    enabled: Optional[bool] = None
    timeout: Optional[int] = None
    command_or_url: Optional[str] = None
    command: Optional[str] = None
    url: Optional[str] = None


def _mcp_error_check(result: Dict[str, Any]):
    """Return HTTP 404 when an MCP server ID is unknown or missing."""
    if isinstance(result, dict) and result.get("ok") is False:
        err = str(result.get("error", "")).lower()
        if "not found" in err or "unknown" in err:
            return JSONResponse(status_code=404, content={**result, "detail": result.get("error")})
    return result


@router.get("/status")
async def mcp_status() -> Dict[str, Any]:
    """Return configured, connected, failed, and disabled MCP server status."""
    manager: AgentManager = get_agent_manager()
    feed: LiveFeedManager = get_live_feed_manager(manager)
    return feed.get_mcp_status()


@router.post("/retry")
async def retry_mcp(payload: Optional[McpRetryRequest] = Body(default=None)):
    """Retry failed MCP server checks (all failed servers if server_id omitted)."""
    manager: AgentManager = get_agent_manager()
    feed: LiveFeedManager = get_live_feed_manager(manager)
    server_id = payload.server_id if payload else None
    return _mcp_error_check(feed.retry_failed_mcp(server_id=server_id))


@router.post("/configure")
async def configure_mcp(payload: McpConfigureRequest = Body(...)):
    """Configure an MCP server's enabled state, timeout, or command/URL."""
    manager: AgentManager = get_agent_manager()
    feed: LiveFeedManager = get_live_feed_manager(manager)
    cmd_or_url = payload.command_or_url or payload.command or payload.url
    try:
        result = feed.configure_mcp(
            server_id=payload.server_id,
            enabled=payload.enabled,
            timeout=payload.timeout,
            command_or_url=cmd_or_url,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return _mcp_error_check(result)
