"""
HunterAI Control Center — Emergency Controls Router
===================================================
Provides immediate emergency stop-all, pause-all scans, volatile data reset,
and full evidence bundle export endpoints.
"""
from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter

from core.dashboard.agent_manager import AgentManager, get_agent_manager
from core.dashboard.live_feed import LiveFeedManager, get_live_feed_manager

router = APIRouter(prefix="/api/emergency", tags=["emergency"])


@router.post("/stop-all")
async def emergency_stop_all() -> Dict[str, Any]:
    """Immediately halt all running agents and active scans."""
    manager: AgentManager = get_agent_manager()
    feed: LiveFeedManager = get_live_feed_manager(manager)
    return feed.emergency_stop_all()


@router.post("/pause-all")
async def emergency_pause_all() -> Dict[str, Any]:
    """Pause all active scans across managed agents."""
    manager: AgentManager = get_agent_manager()
    feed: LiveFeedManager = get_live_feed_manager(manager)
    return feed.pause_all_scans()


@router.post("/clear-data")
async def emergency_clear_data() -> Dict[str, Any]:
    """Clear active findings, court events, and console history."""
    manager: AgentManager = get_agent_manager()
    feed: LiveFeedManager = get_live_feed_manager(manager)
    return feed.clear_all_data()


@router.get("/export-evidence")
@router.post("/export-evidence")
async def emergency_export_evidence() -> Dict[str, Any]:
    """Export all collected findings, scope state, and court evidence as a bundle."""
    manager: AgentManager = get_agent_manager()
    feed: LiveFeedManager = get_live_feed_manager(manager)
    return feed.export_all_evidence()
