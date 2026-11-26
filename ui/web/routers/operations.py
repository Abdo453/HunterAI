"""
HunterAI Control Center — Operational Telemetry & Findings Router
=================================================================
Exposes live findings, Burp issue export, false-positive marking, Evidence Court
status, system health metrics, and interactive console execution endpoints.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Body, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from core.dashboard.agent_manager import AgentManager, get_agent_manager
from core.dashboard.live_feed import LiveFeedManager, get_live_feed_manager

router = APIRouter(prefix="/api", tags=["operations"])


class FalsePositiveRequest(BaseModel):
    """Optional reason when marking a finding as a false positive."""

    reason: str = "Marked by operator"


class TerminalCommandRequest(BaseModel):
    """Interactive console command submission payload."""

    command: str


def _finding_not_found_check(result: Any, finding_id: str):
    """Raise or return 404 when a finding lookup/mutation fails to locate the ID."""
    if result is None:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found")
    if isinstance(result, dict) and result.get("ok") is False:
        err = str(result.get("error", "")).lower()
        if "not found" in err or "unknown" in err:
            return JSONResponse(status_code=404, content={**result, "detail": result.get("error")})
    return result


@router.get("/findings")
async def list_findings(limit: int = Query(default=50, ge=1, le=500)) -> Dict[str, Any]:
    """Return recent live findings and high-severity alerts."""
    feed: LiveFeedManager = get_live_feed_manager(get_agent_manager())
    return feed.get_findings(limit=limit)


@router.get("/findings/{finding_id}")
async def get_finding_details(finding_id: str):
    """Return full details and evidence for a specific finding."""
    feed: LiveFeedManager = get_live_feed_manager(get_agent_manager())
    details = feed.get_finding_details(finding_id)
    return _finding_not_found_check(details, finding_id)


@router.post("/findings/{finding_id}/export-burp")
async def export_finding_to_burp(finding_id: str):
    """Export a finding to Burp Suite via BurpIssueExporter."""
    feed: LiveFeedManager = get_live_feed_manager(get_agent_manager())
    result = feed.export_finding_to_burp(finding_id)
    return _finding_not_found_check(result, finding_id)


@router.post("/findings/{finding_id}/false-positive")
async def mark_finding_false_positive(
    finding_id: str,
    payload: Optional[FalsePositiveRequest] = Body(default=None),
):
    """Mark a finding as a false positive and record the operator rationale."""
    feed: LiveFeedManager = get_live_feed_manager(get_agent_manager())
    reason = payload.reason if payload and payload.reason else "Marked by operator"
    result = feed.mark_false_positive(finding_id, reason=reason)
    return _finding_not_found_check(result, finding_id)


@router.get("/court/status")
async def get_court_status() -> Dict[str, Any]:
    """Return Evidence Court queue counters and live adjudication feed."""
    feed: LiveFeedManager = get_live_feed_manager(get_agent_manager())
    return feed.get_court_status()


@router.get("/metrics/system")
async def get_system_metrics() -> Dict[str, Any]:
    """Sample and return real-time CPU, RAM, Disk I/O, and Network telemetry."""
    feed: LiveFeedManager = get_live_feed_manager(get_agent_manager())
    return feed.sample_metrics()


@router.get("/terminal/state")
async def get_terminal_state() -> Dict[str, Any]:
    """Return interactive terminal output buffer and command history."""
    feed: LiveFeedManager = get_live_feed_manager(get_agent_manager())
    return feed.get_terminal_state()


@router.post("/terminal/command")
async def execute_terminal_command(payload: TerminalCommandRequest = Body(...)) -> Dict[str, Any]:
    """Execute a Control Center console command and return updated output."""
    feed: LiveFeedManager = get_live_feed_manager(get_agent_manager())
    return feed.execute_command(payload.command)
