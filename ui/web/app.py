"""
HunterAI Control Center — Web Application & WebSocket Hub
=========================================================
FastAPI application wiring modular Control Center routers, Jinja2 templates,
offline-capable static assets, 5 real-time WebSocket telemetry streams, and
preserved core subsystem APIs.
"""
from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any, Callable, Dict

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from core.dashboard.agent_manager import AgentManager, get_agent_manager
from core.dashboard.live_feed import LiveFeedManager, get_live_feed_manager
from ui.web.routers import ALL_ROUTERS

logger = logging.getLogger("hunter_ai.ui.web.app")

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
TEMPLATES_DIR = BASE_DIR / "templates"

STATIC_DIR.mkdir(parents=True, exist_ok=True)
TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="HunterAI Web Control API", version="3.0.0")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

for _router in ALL_ROUTERS:
    app.include_router(_router)

_burp_sensor_bridge = None


def get_burp_sensor_bridge():
    global _burp_sensor_bridge
    if _burp_sensor_bridge is None:
        from agents.burp_agent.extension.burp_extension_bridge import BurpExtensionBridge

        _burp_sensor_bridge = BurpExtensionBridge()
    return _burp_sensor_bridge


@app.get("/", response_class=HTMLResponse)
async def control_center_dashboard(request: Request):
    """Render the Artex-style HunterAI Control Center dashboard."""
    manager: AgentManager = get_agent_manager()
    feed: LiveFeedManager = get_live_feed_manager(manager)
    context: Dict[str, Any] = {
        "agents": manager.get_all_status(),
        "findings": feed.get_findings(),
        "scope": feed.get_scope_state(),
        "mcp": feed.get_mcp_status(),
        "metrics": feed.sample_metrics(),
        "court": feed.get_court_status(),
        "terminal": feed.get_terminal_state(),
    }

    template_path = TEMPLATES_DIR / "dashboard.html"
    if template_path.exists():
        try:
            return templates.TemplateResponse(
                request=request,
                name="dashboard.html",
                context=context,
            )
        except Exception as exc:
            logger.warning("Template render fallback triggered: %s", exc)

    index_path = STATIC_DIR / "index.html"
    if index_path.exists():
        return HTMLResponse(content=index_path.read_text(encoding="utf-8"))

    return HTMLResponse(
        content="<!DOCTYPE html><html><head><title>HunterAI Control Center</title></head>"
        "<body><h1>HunterAI Control Center</h1><p>Dashboard assets unavailable.</p></body></html>"
    )


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
        from unittest.mock import MagicMock
        from core.brain.autonomous_brain import AutonomousBrain

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
        tool=data.get("tool", "proxy"),
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


# ── Real-Time WebSocket Telemetry Streams ─────────────────────────────────────


async def _stream_ws_feed(
    websocket: WebSocket,
    producer: Callable[[], Dict[str, Any]],
    interval_sec: float = 2.0,
) -> None:
    """Accept a WebSocket and periodically stream JSON payloads until disconnect."""
    await websocket.accept()
    stop_event = asyncio.Event()

    async def _watch_client() -> None:
        try:
            while not stop_event.is_set():
                msg = await websocket.receive_text()
                stripped = msg.strip().lower()
                if stripped in {"close", "disconnect"}:
                    stop_event.set()
                    return
                if stripped in {"ping", "refresh"}:
                    await websocket.send_json(producer())
        except (WebSocketDisconnect, RuntimeError):
            stop_event.set()
        except Exception:
            stop_event.set()

    watcher = asyncio.create_task(_watch_client())
    try:
        while not stop_event.is_set():
            await websocket.send_json(producer())
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=interval_sec)
            except asyncio.TimeoutError:
                continue
    except (WebSocketDisconnect, RuntimeError):
        pass
    except Exception as exc:
        logger.debug("WebSocket stream closed (%s): %s", websocket.url.path, exc)
    finally:
        stop_event.set()
        watcher.cancel()
        try:
            await watcher
        except (asyncio.CancelledError, Exception):
            pass


@app.websocket("/ws/agents")
async def ws_agents(websocket: WebSocket) -> None:
    """Stream AgentManager status snapshots every 2 seconds."""
    await _stream_ws_feed(websocket, lambda: get_agent_manager().get_all_status(), interval_sec=2.0)


@app.websocket("/ws/findings")
async def ws_findings(websocket: WebSocket) -> None:
    """Stream live findings and alerts every 2 seconds."""
    await _stream_ws_feed(
        websocket,
        lambda: get_live_feed_manager(get_agent_manager()).get_findings(),
        interval_sec=2.0,
    )


@app.websocket("/ws/metrics")
async def ws_metrics(websocket: WebSocket) -> None:
    """Stream real-time system health metrics every 2 seconds."""
    await _stream_ws_feed(
        websocket,
        lambda: get_live_feed_manager(get_agent_manager()).sample_metrics(),
        interval_sec=2.0,
    )


@app.websocket("/ws/court")
async def ws_court(websocket: WebSocket) -> None:
    """Stream Evidence Court adjudication counters and live feed every 2 seconds."""
    await _stream_ws_feed(
        websocket,
        lambda: get_live_feed_manager(get_agent_manager()).get_court_status(),
        interval_sec=2.0,
    )


@app.websocket("/ws/terminal")
async def ws_terminal(websocket: WebSocket) -> None:
    """Interactive terminal WebSocket accepting plain-text or JSON commands."""
    await websocket.accept()
    feed: LiveFeedManager = get_live_feed_manager(get_agent_manager())
    try:
        initial_state = feed.get_terminal_state()
        await websocket.send_json({"type": "state", **initial_state})
        while True:
            raw = await websocket.receive_text()
            command = raw.strip()
            if raw.lstrip().startswith("{"):
                try:
                    parsed = json.loads(raw)
                    if isinstance(parsed, dict):
                        if parsed.get("type") == "ping":
                            await websocket.send_json({"type": "pong"})
                            continue
                        command = str(parsed.get("command", "")).strip()
                except json.JSONDecodeError:
                    pass
            result = feed.execute_command(command)
            await websocket.send_json({"type": "output", **result})
    except (WebSocketDisconnect, RuntimeError):
        pass
    except Exception as exc:
        logger.debug("WebSocket terminal closed: %s", exc)


# ── Legacy OmniHunter Routes & Sub-App Compatibility ──────────────────────────
from ui.web.legacy_routes import (
    AgentCoPilotState,
    copilot_state,
    get_burp_gateway,
    register_legacy_routes,
)

register_legacy_routes(app)
