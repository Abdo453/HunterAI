"""
HunterAI Unified Web Dashboard (Phase 16)
==========================================
Real-time FastAPI web dashboard providing:
  - Live metrics: active tasks, memory usage, agent states
  - Project overview: scope, secrets, tool inventory
  - Event stream: SSE-based live activity log
  - Interactive controls: pause, resume, snapshot
"""
from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, List, Optional

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

app = FastAPI(
    title="HunterAI Unified Dashboard",
    description="Real-time security assessment monitoring and control",
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url=None,
)

# ─── In-Memory State Store (injected by runtime) ─────────────────────────────
_dashboard_state: Dict[str, Any] = {
    "target": "—",
    "scope_locked": False,
    "agents": {},
    "active_tasks": [],
    "event_log": [],
    "metrics": {
        "domains": 0,
        "live_hosts": 0,
        "endpoints": 0,
        "apis": 0,
        "js_files": 0,
        "findings": 0,
    },
    "paused": False,
}


def update_state(key: str, value: Any) -> None:
    _dashboard_state[key] = value


def append_event(message: str, level: str = "INFO", agent: str = "system") -> None:
    _dashboard_state["event_log"].append({
        "ts": time.strftime("%H:%M:%S"),
        "level": level,
        "agent": agent,
        "message": message,
    })
    if len(_dashboard_state["event_log"]) > 500:
        _dashboard_state["event_log"].pop(0)


# ─── Routes ──────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index():
    return HTMLResponse(content=_build_dashboard_html(), status_code=200)


@app.get("/api/status")
async def get_status():
    """Real-time metrics and agent states."""
    return JSONResponse(_dashboard_state)


@app.get("/api/metrics")
async def get_metrics():
    return JSONResponse(_dashboard_state.get("metrics", {}))


@app.get("/api/events")
async def get_events(limit: int = 100):
    log = _dashboard_state.get("event_log", [])
    return JSONResponse({"events": log[-limit:]})


@app.get("/api/agents")
async def get_agents():
    return JSONResponse({"agents": _dashboard_state.get("agents", {})})


@app.get("/api/tasks")
async def get_tasks():
    return JSONResponse({"tasks": _dashboard_state.get("active_tasks", [])})


@app.post("/api/control/pause")
async def pause():
    _dashboard_state["paused"] = True
    append_event("System PAUSED by operator", level="WARNING", agent="dashboard")
    return {"status": "paused"}


@app.post("/api/control/resume")
async def resume():
    _dashboard_state["paused"] = False
    append_event("System RESUMED by operator", level="INFO", agent="dashboard")
    return {"status": "resumed"}


@app.post("/api/control/snapshot")
async def create_snapshot():
    """Trigger state snapshot capture."""
    try:
        from core.snapshot_manager import SnapshotManager
        sm = SnapshotManager("snapshots")
        snap = sm.snapshot(
            state_data=_dashboard_state,
            label="dashboard_triggered_checkpoint",
            metadata={"triggered_by": "dashboard_api"},
        )
        append_event(f"Snapshot created: {snap.snapshot_id}", level="INFO", agent="dashboard")
        return {"status": "snapshot_created", "snapshot_id": snap.snapshot_id}
    except Exception as e:
        return JSONResponse({"status": "error", "error": str(e)}, status_code=500)


@app.get("/api/stream/events")
async def stream_events(request: Request):
    """Server-Sent Events stream for live activity log."""
    async def event_generator() -> AsyncGenerator[str, None]:
        last_idx = len(_dashboard_state.get("event_log", []))
        while True:
            if await request.is_disconnected():
                break
            log = _dashboard_state.get("event_log", [])
            new_events = log[last_idx:]
            if new_events:
                for ev in new_events:
                    payload = json.dumps(ev)
                    yield f"data: {payload}\n\n"
                last_idx = len(log)
            await asyncio.sleep(0.5)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


# ─── Dashboard HTML ───────────────────────────────────────────────────────────

def _build_dashboard_html() -> str:
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HunterAI Unified Dashboard</title>
<style>
  :root { --bg: #0d1117; --card: #161b22; --accent: #58a6ff; --green: #3fb950; --red: #f85149; --yellow: #d29922; --text: #c9d1d9; --border: #30363d; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Courier New', monospace; }
  header { background: var(--card); border-bottom: 1px solid var(--border); padding: 16px 24px; display: flex; align-items: center; justify-content: space-between; }
  header h1 { color: var(--accent); font-size: 1.3rem; letter-spacing: 2px; }
  .badge { padding: 3px 10px; border-radius: 12px; font-size: 0.75rem; font-weight: bold; }
  .badge-green { background: rgba(63,185,80,0.15); color: var(--green); border: 1px solid var(--green); }
  .badge-red { background: rgba(248,81,73,0.15); color: var(--red); border: 1px solid var(--red); }
  .grid { display: grid; grid-template-columns: 240px 1fr; gap: 0; min-height: calc(100vh - 57px); }
  .sidebar { background: var(--card); border-right: 1px solid var(--border); padding: 20px; }
  .sidebar h3 { color: var(--accent); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px; }
  .metric { display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid var(--border); font-size: 0.85rem; }
  .metric-val { color: var(--accent); font-weight: bold; }
  .agent-pill { padding: 4px 8px; margin: 4px 0; border-radius: 4px; font-size: 0.8rem; background: rgba(88,166,255,0.08); border-left: 3px solid var(--accent); }
  .agent-pill.stalled { border-left-color: var(--red); }
  .main { padding: 20px; display: flex; flex-direction: column; gap: 16px; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }
  .card h3 { color: var(--accent); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px; }
  .event-log { max-height: 320px; overflow-y: auto; font-size: 0.8rem; }
  .event { padding: 3px 0; border-bottom: 1px solid var(--border); }
  .event .ts { color: #6e7681; }
  .event .level-info { color: var(--green); }
  .event .level-warning { color: var(--yellow); }
  .event .level-error { color: var(--red); }
  .controls { display: flex; gap: 10px; flex-wrap: wrap; }
  .btn { padding: 8px 18px; border: none; border-radius: 6px; cursor: pointer; font-size: 0.85rem; font-family: monospace; }
  .btn-pause { background: var(--yellow); color: #000; }
  .btn-resume { background: var(--green); color: #000; }
  .btn-snap { background: var(--accent); color: #000; }
</style>
</head>
<body>
<header>
  <h1>⚡ HUNTEROS · UNIFIED DASHBOARD</h1>
  <span id="status-badge" class="badge badge-green">● RUNNING</span>
</header>
<div class="grid">
  <div class="sidebar">
    <h3>Attack Surface</h3>
    <div class="metric"><span>Domains</span><span id="m-domains" class="metric-val">—</span></div>
    <div class="metric"><span>Live Hosts</span><span id="m-hosts" class="metric-val">—</span></div>
    <div class="metric"><span>Endpoints</span><span id="m-endpoints" class="metric-val">—</span></div>
    <div class="metric"><span>APIs</span><span id="m-apis" class="metric-val">—</span></div>
    <div class="metric"><span>JS Files</span><span id="m-js" class="metric-val">—</span></div>
    <div class="metric"><span>Findings</span><span id="m-findings" class="metric-val">—</span></div>
    <br>
    <h3>Active Agents</h3>
    <div id="agents-list"><div class="agent-pill">Loading…</div></div>
    <br>
    <h3>Controls</h3>
    <div class="controls">
      <button class="btn btn-pause" onclick="postControl('pause')">⏸ Pause</button>
      <button class="btn btn-resume" onclick="postControl('resume')">▶ Resume</button>
      <button class="btn btn-snap" onclick="postControl('snapshot')">📸 Snapshot</button>
    </div>
  </div>
  <div class="main">
    <div class="card">
      <h3>📡 Live Activity</h3>
      <div id="event-log" class="event-log"></div>
    </div>
    <div class="card">
      <h3>📋 Active Tasks</h3>
      <div id="task-list" style="font-size:0.82rem"></div>
    </div>
  </div>
</div>
<script>
  async function fetchStatus() {
    try {
      const r = await fetch('/api/status'); const d = await r.json();
      document.getElementById('m-domains').textContent   = d.metrics?.domains    ?? '—';
      document.getElementById('m-hosts').textContent     = d.metrics?.live_hosts ?? '—';
      document.getElementById('m-endpoints').textContent = d.metrics?.endpoints  ?? '—';
      document.getElementById('m-apis').textContent      = d.metrics?.apis       ?? '—';
      document.getElementById('m-js').textContent        = d.metrics?.js_files   ?? '—';
      document.getElementById('m-findings').textContent  = d.metrics?.findings   ?? '—';

      const badge = document.getElementById('status-badge');
      badge.textContent = d.paused ? '⏸ PAUSED' : '● RUNNING';
      badge.className = 'badge ' + (d.paused ? 'badge-red' : 'badge-green');

      const al = document.getElementById('agents-list');
      const agents = d.agents || {};
      al.innerHTML = Object.entries(agents).map(([name, state]) =>
        '<div class="agent-pill ' + (state === 'STALLED' ? 'stalled' : '') + '">' + name + ' · ' + state + '</div>'
      ).join('') || '<div class="agent-pill">No active agents</div>';

      const tl = document.getElementById('task-list');
      const tasks = d.active_tasks || [];
      tl.innerHTML = tasks.length ? tasks.map(t =>
        '<div style="padding:4px 0; border-bottom:1px solid #30363d">' + JSON.stringify(t) + '</div>'
      ).join('') : '<i style="color:#6e7681">No active tasks</i>';
    } catch(e) {}
  }

  // SSE-based event log
  const evtLog = document.getElementById('event-log');
  const es = new EventSource('/api/stream/events');
  es.onmessage = (e) => {
    const ev = JSON.parse(e.data);
    const el = document.createElement('div');
    el.className = 'event';
    el.innerHTML = '<span class="ts">' + ev.ts + '</span>  <span class="level-' + (ev.level||'info').toLowerCase() + '">[' + (ev.level||'INFO') + ']</span>  <b>' + (ev.agent||'system') + '</b>: ' + ev.message;
    evtLog.appendChild(el);
    evtLog.scrollTop = evtLog.scrollHeight;
  };
  es.onerror = () => {};

  async function postControl(action) {
    await fetch('/api/control/' + action, {method:'POST'});
    fetchStatus();
  }

  fetchStatus();
  setInterval(fetchStatus, 2000);
</script>
</body>
</html>"""
