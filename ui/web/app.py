"""
HunterAI Web Control API Stub
=============================
Minimal FastAPI application stub providing essential endpoints for test suites and dashboard integration.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger("hunter_ai.ui.web.app")

app = FastAPI(title="HunterAI Web Control API", version="3.0.0")

_burp_sensor_bridge = None


def get_burp_sensor_bridge():
    global _burp_sensor_bridge
    if _burp_sensor_bridge is None:
        from agents.burp_agent.extension.burp_extension_bridge import BurpExtensionBridge
        _burp_sensor_bridge = BurpExtensionBridge()
    return _burp_sensor_bridge


@app.get("/api/status")
async def api_status():
    return {"status": "ONLINE", "version": "3.0.0"}


@app.post("/api/planner/mission")
async def execute_planner_mission(req: Request):
    """Execute a security mission via StateSpacePlanner."""
    data = await req.json()
    from core.planner.schemas import SecurityGoal

    goal = SecurityGoal(**data)
    max_steps = data.get("max_steps", 8)
    brain = getattr(app.state, "active_brain", None)
    if not brain:
        from core.brain.autonomous_brain import AutonomousBrain
        from unittest.mock import MagicMock
        rm = MagicMock()
        tm = MagicMock()
        tm.is_available.return_value = True
        brain = AutonomousBrain(resource_manager=rm, tool_manager=tm, dry_run=True)
        app.state.active_brain = brain
    report = await brain.run_mission(goal, max_steps=max_steps)
    return report.model_dump()


@app.get("/api/intelligence/state")
async def get_live_security_state():
    """Returns a snapshot of the active security state."""
    brain = getattr(app.state, "active_brain", None)
    if brain and getattr(brain, "security_state", None):
        return brain.security_state.get_snapshot()

    from core.state.security_state import SecurityState
    default_state = getattr(app.state, "default_security_state", None)
    if not default_state:
        default_state = SecurityState(target="target.local")
        default_state.add_asset(host="target.local")
        app.state.default_security_state = default_state
    return default_state.get_snapshot()


@app.post("/api/burp/ingest")
async def ingest_burp_traffic(req: Request):
    """Ingest live traffic from Burp Suite extension."""
    data = await req.json()
    bridge = get_burp_sensor_bridge()
    receipt = await bridge.ingest_transaction(
        method=data.get("method", "GET"),
        url=data.get("url", "http://localhost"),
        request_headers=data.get("request_headers", {}),
        request_body=data.get("request_body", ""),
        response_status=data.get("response_status", 200),
        response_headers=data.get("response_headers", {}),
        response_body=data.get("response_body", ""),
        tool=data.get("tool", "proxy")
    )
    return {"receipt": receipt.model_dump()}


@app.get("/api/burp/artifacts")
async def list_burp_artifacts():
    """List captured artifacts."""
    bridge = get_burp_sensor_bridge()
    artifacts = bridge.artifacts.get_all_artifacts(limit=50)
    return {"artifacts": [a.model_dump() for a in artifacts], "total": len(artifacts)}


@app.get("/api/burp/evidence")
async def list_unified_evidence():
    """List captured unified evidence."""
    bridge = get_burp_sensor_bridge()
    evidence_list = bridge.evidence_store.get_all_evidence(limit=50)
    return {"evidence": [e.model_dump() for e in evidence_list], "total": len(evidence_list)}


@app.get("/api/burp/sensory_events")
async def get_sensory_events():
    """List sensory events from Burp sensor bus."""
    bridge = get_burp_sensor_bridge()
    events = bridge.bus.get_recent_events(limit=50)
    return {"events": [ev.model_dump() for ev in events], "total": len(events)}


@app.post("/api/browser/browse")
async def browser_browse(req: Request):
    """Trigger browser exploration via ActiveBrowserAgent."""
    data = await req.json()
    url = data.get("url", "").strip() or data.get("target_url", "").strip()
    visible = data.get("visible", False)
    canary = data.get("canary", "hunter_canary_probe_1337")

    if not url:
        return JSONResponse(status_code=400, content={"error": "URL required"})
    if not url.startswith("http://") and not url.startswith("https://"):
        url = f"https://{url}"

    from core.browser.active_browser_agent import ActiveBrowserAgent
    agent = ActiveBrowserAgent(headless=not visible, max_actions=20, timeout_secs=35.0)
    report = await agent.explore_and_interact(target_url=url, canary_payload=canary)
    return report.to_dict()
