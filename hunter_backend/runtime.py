"""Shared platform runtime, event bus, lifecycle wiring, and lazy singletons.

This module replaces the hub and runtime state previously held inside ``ui/web/*``
with zero imports from ``ui.web.*``. It connects core/ services, BurpAgent,
LearningScheduler, Go Core HTTP proxy client, and managed async tasks onto a
single uvicorn event loop.
"""

from __future__ import annotations

import asyncio
from collections import deque
import json
import logging
import os
from pathlib import Path
import threading
import time
from typing import Any, Callable, Coroutine, Deque, Dict, Iterable, List, Optional, Tuple

import httpx

from core.copilot_service import (
    CopilotService,
    collect_live_context,
    evaluate_action_policy,
)
from core.platform_store import (
    PlatformStore,
    get_platform_store,
    new_id,
    redact_payload,
    verify_proposal_digest,
)
from core.run_control import GLOBAL_RUN_CONTROLLER

logger = logging.getLogger("hunter_backend.runtime")

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = DATA_DIR / "reports"
SNAPSHOTS_DIR = DATA_DIR / "snapshots"
RUNS_DIR = DATA_DIR / "runs"
ARTEX_BASE_URL = os.environ.get("HUNTERAI_ARTEX_URL", "http://127.0.0.1:7071").rstrip("/")

# Shared runtime state dictionaries (guarded inside single-worker uvicorn / locks)
MAIN_LOOP: Optional[asyncio.AbstractEventLoop] = None
_GO_CLIENT: Optional[httpx.AsyncClient] = None
_BURP_WORKER_TASK: Optional[asyncio.Task[Any]] = None
_WIRED = False
_WIRE_LOCK = threading.Lock()
_SINGLETON_LOCK = threading.Lock()

_active_pipelines: Dict[str, Dict[str, Any]] = {}
_active_mission_tasks: Dict[str, asyncio.Task[Any]] = {}
_OMNI_RUNS: Dict[str, Dict[str, Any]] = {}
_ACTIVE_MASTER_MISSIONS: Dict[str, Dict[str, Any]] = {}
_MISSION_PROGRESS_SUBSCRIBERS: Dict[str, List[asyncio.Queue[Dict[str, Any]]]] = {}
_LATEST_RADAR_STATE: Optional[Dict[str, Any]] = None
_ACTIVE_BURP_BRIDGE: Any = None
_EXTENSION_INSTALL_LOCK = threading.Lock()

_ACTIVITY_LOGS: Deque[Dict[str, Any]] = deque(maxlen=400)
_ACTIVITY_LOCK = threading.Lock()

TARGETS_FILE = DATA_DIR / "targets.json"
CONTROL_SETTINGS_FILE = DATA_DIR / "control_settings.json"
CHECKLIST_STATE_FILE = DATA_DIR / "checklist_state.json"
RADAR_STATE_FILE = DATA_DIR / "radar" / "latest_state.json"

copilot_state: Dict[str, Any] = {
    "findings_queue": [],
    "learning_topics": [],
    "last_scan_target": None,
    "connected_ws": [],
    "hints": [],
    "questions": [],
}

_SCOPE_STATE: Dict[str, Any] = {
    "in_scope": [],
    "out_of_scope": [],
}

# Lazy singleton slots
_burp_agent_singleton: Any = None
_burp_sensor_bridge: Any = None
_static_reasoning_engine: Any = None
_hunter_agent_manager: Any = None
_tool_orchestrator: Any = None
_mcp_registry: Any = None
_flag_service: Any = None
_extension_manager: Any = None
_scope_enforcer: Any = None


def log_activity_event(
    category: str,
    action: str,
    detail: Any = "",
    status: str = "info",
) -> Dict[str, Any]:
    """Record a redacted activity log entry in memory."""
    entry = {
        "id": new_id("act"),
        "ts": time.time(),
        "category": category,
        "action": action,
        "detail": redact_payload(detail),
        "status": status,
    }
    with _ACTIVITY_LOCK:
        _ACTIVITY_LOGS.appendleft(entry)
    return entry


def get_activity_logs(limit: int = 100) -> List[Dict[str, Any]]:
    """Return recent activity log entries."""
    with _ACTIVITY_LOCK:
        return list(_ACTIVITY_LOGS)[: max(1, min(limit, 400))]


def _normalize_scope_list(value: Any) -> List[str]:
    if not value:
        return []
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def resolve_effective_scope(
    *,
    scope: Any = None,
    out_of_scope: Any = None,
    engagement_id: Optional[str] = None,
) -> Tuple[List[str], List[str]]:
    """Resolve effective in-scope and out-of-scope lists across request, store, and Phase G."""
    in_list = _normalize_scope_list(scope)
    out_list = _normalize_scope_list(out_of_scope)

    if not in_list or not out_list:
        try:
            store = get_platform_store()
            ctx = store.get_context()
            eid = engagement_id or ctx.get("active_engagement_id")
            if eid:
                eng = store.get_engagement(eid)
                if eng:
                    if not in_list:
                        in_list = _normalize_scope_list(eng.get("in_scope"))
                    if not out_list:
                        out_list = _normalize_scope_list(eng.get("out_of_scope"))
        except Exception:
            pass

    if not in_list and _SCOPE_STATE.get("in_scope"):
        in_list = list(_SCOPE_STATE["in_scope"])
    if not out_list and _SCOPE_STATE.get("out_of_scope"):
        out_list = list(_SCOPE_STATE["out_of_scope"])
    return in_list, out_list


def check_target_policy(
    target: str,
    *,
    action_type: str = "scan",
    tool_name: str = "",
    command_args: str = "",
    scope: Any = None,
    out_of_scope: Any = None,
    engagement_id: Optional[str] = None,
    allow_active_tests: bool = True,
) -> Dict[str, Any]:
    """Evaluate target safety & scope via ``evaluate_action_policy``."""
    in_list, out_list = resolve_effective_scope(
        scope=scope,
        out_of_scope=out_of_scope,
        engagement_id=engagement_id,
    )
    return evaluate_action_policy(
        action_type=action_type,
        target=target,
        tool_name=tool_name,
        command_args=command_args,
        in_scope=in_list or None,
        out_of_scope=out_list or None,
        allow_active_tests=allow_active_tests,
    )


class PlatformEventBus:
    """In-memory pub/sub fan-out backed by PlatformStore SQLite persistence."""

    def __init__(self, history_size: int = 500) -> None:
        self._history: Deque[Dict[str, Any]] = deque(maxlen=history_size)
        self._subscribers: set[asyncio.Queue[Dict[str, Any]]] = set()
        self._lock = threading.Lock()
        self._mem_seq = 0

    def push_local(self, event: Dict[str, Any]) -> None:
        """Broadcast an already-formatted event dict to in-memory backlog and subscribers."""
        if not isinstance(event, dict):
            return
        with self._lock:
            self._history.append(event)
            subs = list(self._subscribers)
        for q in subs:
            self._deliver_to_queue(q, event)

    @staticmethod
    def _deliver_to_queue(q: asyncio.Queue[Dict[str, Any]], event: Dict[str, Any]) -> None:
        loop = getattr(q, "_loop", None)
        if loop is not None and not loop.is_closed():
            try:
                running = asyncio.get_running_loop()
            except RuntimeError:
                running = None
            if running is loop:
                try:
                    q.put_nowait(event)
                except asyncio.QueueFull:
                    pass
                return
            try:
                loop.call_soon_threadsafe(PlatformEventBus._put_ignore_full, q, event)
                return
            except Exception:
                pass
        try:
            q.put_nowait(event)
        except Exception:
            pass

    @staticmethod
    def _put_ignore_full(q: asyncio.Queue[Dict[str, Any]], event: Dict[str, Any]) -> None:
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            pass

    async def publish(
        self,
        event_type: str,
        payload: Optional[Dict[str, Any]] = None,
        *,
        run_id: Optional[str] = None,
        engagement_id: Optional[str] = None,
        task_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        source: str = "platform",
        persist: bool = True,
    ) -> Dict[str, Any]:
        """Persist event (when enabled) and push to live SSE/WS subscribers."""
        safe_payload = redact_payload(payload or {})
        if persist:
            try:
                store = get_platform_store()
                event = store.append_event(
                    event_type,
                    run_id=run_id,
                    engagement_id=engagement_id,
                    task_id=task_id,
                    agent_id=agent_id,
                    source=source,
                    payload=safe_payload,
                )
                return event
            except Exception as exc:
                logger.warning("Failed to persist event %s: %s", event_type, exc)

        with self._lock:
            self._mem_seq += 1
            seq = self._mem_seq
        event = {
            "seq": seq,
            "ts": time.time(),
            "type": event_type,
            "run_id": run_id,
            "engagement_id": engagement_id,
            "task_id": task_id,
            "agent_id": agent_id,
            "source": source,
            "payload": safe_payload,
        }
        self.push_local(event)
        return event

    def publish_threadsafe(
        self,
        event_type: str,
        payload: Optional[Dict[str, Any]] = None,
        *,
        run_id: Optional[str] = None,
        engagement_id: Optional[str] = None,
        source: str = "platform",
        persist: bool = True,
    ) -> None:
        """Emit an event safely from sync code or worker threads."""
        safe_payload = redact_payload(payload or {})
        if persist:
            try:
                store = get_platform_store()
                store.append_event(
                    event_type,
                    run_id=run_id,
                    engagement_id=engagement_id,
                    source=source,
                    payload=safe_payload,
                )
                return
            except Exception:
                pass
        with self._lock:
            self._mem_seq += 1
            seq = self._mem_seq
        self.push_local(
            {
                "seq": seq,
                "ts": time.time(),
                "type": event_type,
                "run_id": run_id,
                "engagement_id": engagement_id,
                "source": source,
                "payload": safe_payload,
            }
        )

    def subscribe(self, maxsize: int = 512) -> asyncio.Queue[Dict[str, Any]]:
        """Register and return a new subscriber queue bound to the current loop."""
        q: asyncio.Queue[Dict[str, Any]] = asyncio.Queue(maxsize=maxsize)
        with self._lock:
            self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue[Dict[str, Any]]) -> None:
        """Remove a subscriber queue cleanly."""
        with self._lock:
            self._subscribers.discard(q)

    def backlog_since(
        self,
        since_seq: Optional[int],
        *,
        run_id: Optional[str] = None,
        engagement_id: Optional[str] = None,
        limit: int = 200,
    ) -> List[Dict[str, Any]]:
        """Return historical events newer than *since_seq* from store or in-memory ring."""
        seq_floor = 0 if since_seq is None else int(since_seq)
        try:
            store = get_platform_store()
            rows = store.list_events(
                since_seq=seq_floor,
                run_id=run_id,
                engagement_id=engagement_id,
                limit=limit,
            )
            if rows:
                return rows
        except Exception:
            pass

        with self._lock:
            items = list(self._history)
        filtered = [
            ev
            for ev in items
            if int(ev.get("seq") or 0) > seq_floor
            and (not run_id or ev.get("run_id") == run_id)
            and (not engagement_id or ev.get("engagement_id") == engagement_id)
        ]
        return filtered[:limit]


EVENT_BUS = PlatformEventBus()


def _on_store_event(event: Dict[str, Any]) -> None:
    EVENT_BUS.push_local(event)


def _on_run_state_change(handle: Any) -> None:
    """Sync GLOBAL_RUN_CONTROLLER transitions into PlatformStore and EVENT_BUS."""
    try:
        run_id = getattr(handle, "run_id", None) or str(handle)
        raw_state = getattr(handle, "state", None)
        new_state = getattr(raw_state, "value", str(raw_state)) if raw_state is not None else "unknown"
        info = dict(getattr(handle, "meta", None) or {})
        store = get_platform_store()
        fields: Dict[str, Any] = {"status": new_state}
        if new_state in {"completed", "failed", "stopped"}:
            fields["finished_at"] = time.time()
        existing = store.update_run(run_id, **fields)
        engagement_id = existing.get("engagement_id") if existing else None
        store.append_event(
            "run.state",
            run_id=run_id,
            engagement_id=engagement_id,
            source="run_control",
            payload={"run_id": run_id, "status": new_state, "info": redact_payload(info)},
        )
        if new_state in {"failed", "completed", "stopped"}:
            severity = "error" if new_state == "failed" else "info"
            store.add_notification(
                kind=f"run.{new_state}",
                title=f"Run {run_id} {new_state}",
                message=f"Target: {(existing or {}).get('target', 'unknown')}",
                severity=severity,
                ref_kind="run",
                ref_id=run_id,
                engagement_id=engagement_id,
                run_id=run_id,
            )
    except Exception as exc:
        logger.debug("run state hook failed: %s", exc)


def ensure_platform_wiring() -> PlatformStore:
    """Idempotently wire PlatformStore events and GLOBAL_RUN_CONTROLLER hooks."""
    global _WIRED
    store = get_platform_store()
    with _WIRE_LOCK:
        if _WIRED:
            return store
        store.register_event_listener(_on_store_event)
        GLOBAL_RUN_CONTROLLER.on_state_change = _on_run_state_change
        _WIRED = True
    return store


def register_managed_run(
    *,
    kind: str,
    target: str,
    task: Optional[asyncio.Task[Any]] = None,
    run_id: Optional[str] = None,
    engagement_id: Optional[str] = None,
    in_scope: Optional[List[str]] = None,
    out_of_scope: Optional[List[str]] = None,
    status: str = "running",
    current_phase: str = "INIT",
    meta: Optional[Dict[str, Any]] = None,
    set_active: bool = True,
) -> Dict[str, Any]:
    """Persist and register a managed run across PlatformStore and GLOBAL_RUN_CONTROLLER."""
    store = ensure_platform_wiring()
    resolved_run_id = run_id or new_id("run")

    if not engagement_id and target:
        ctx = store.get_context()
        active_eid = ctx.get("active_engagement_id")
        active_eng = store.get_engagement(active_eid) if active_eid else None
        if active_eng and active_eng.get("target") == target:
            engagement_id = active_eid
        else:
            eng = store.upsert_engagement(
                target=target,
                in_scope=in_scope or ([target] if target else []),
                out_of_scope=out_of_scope or [],
                status="authorized",
                source=kind,
            )
            engagement_id = eng["engagement_id"]

    handle = GLOBAL_RUN_CONTROLLER.register(
        resolved_run_id,
        task=task,
        kind=kind,
        meta={"target": target, **(meta or {})},
    )
    run_row = store.upsert_run(
        run_id=resolved_run_id,
        kind=kind,
        target=target,
        engagement_id=engagement_id,
        status=status,
        current_phase=current_phase,
        progress=0.0,
        meta=meta or {},
        started_at=time.time(),
    )
    if set_active:
        store.update_context(
            active_engagement_id=engagement_id,
            active_run_id=resolved_run_id,
        )
    store.append_event(
        "run.started",
        run_id=resolved_run_id,
        engagement_id=engagement_id,
        source=kind,
        payload={
            "run_id": resolved_run_id,
            "kind": kind,
            "target": target,
            "status": status,
        },
    )
    return {"run": run_row, "handle": handle, "engagement_id": engagement_id}


def schedule_background_coro(coro: Coroutine[Any, Any, Any]) -> asyncio.Task[Any]:
    """Schedule a coroutine directly onto the running loop (never async_to_sync)."""
    try:
        loop = asyncio.get_running_loop()
        return loop.create_task(coro)
    except RuntimeError:
        if MAIN_LOOP is not None and MAIN_LOOP.is_running():
            fut = asyncio.run_coroutine_threadsafe(coro, MAIN_LOOP)
            # Wrap Future isn't an asyncio.Task; caller inside async view always has running loop.
            return fut  # type: ignore[return-value]
        raise


async def _run_pipeline_task(
    run_id: str,
    target: str,
    mode: str,
    scope: List[str],
    out_of_scope: List[str],
    engagement_id: Optional[str],
    *,
    kind: str = "pipeline",
    prompt: str = "",
    engine: str = "claude",
    proxy: Optional[str] = None,
) -> None:
    store = ensure_platform_wiring()
    try:
        store.update_run(run_id, status="running", current_phase="RECON", progress=0.15)
        store.append_event(
            "pipeline.progress",
            run_id=run_id,
            engagement_id=engagement_id,
            source=kind,
            payload={"phase": "RECON", "progress": 0.15, "target": target, "mode": mode},
        )
        if target in _active_pipelines:
            _active_pipelines[target]["phase"] = "RECON"

        phase_delay = float(os.environ.get("HUNTER_PIPELINE_PHASE_DELAY_S", "0.35"))
        if phase_delay > 0:
            await asyncio.sleep(phase_delay)

        if not await GLOBAL_RUN_CONTROLLER.checkpoint(run_id):
            store.update_run(run_id, status="stopped", finished_at=time.time())
            if target in _active_pipelines:
                _active_pipelines[target]["status"] = "stopped"
            return

        from core.scope_guard import ScopeGuard

        guard = ScopeGuard(in_scope=scope or ([target] if target else []), out_of_scope=out_of_scope)
        store.update_run(run_id, status="running", current_phase="SCOPE_VERIFIED", progress=0.30)
        store.append_event(
            "pipeline.scope_verified",
            run_id=run_id,
            engagement_id=engagement_id,
            source="pipeline",
            payload={"in_scope": guard.in_scope, "out_of_scope": guard.out_of_scope},
        )
        if phase_delay > 0:
            await asyncio.sleep(min(phase_delay, 0.25))
        if not await GLOBAL_RUN_CONTROLLER.checkpoint(run_id):
            store.update_run(run_id, status="stopped", finished_at=time.time())
            if target in _active_pipelines:
                _active_pipelines[target]["status"] = "stopped"
            return

        discovered_assets: List[Dict[str, Any]] = []
        discovered_findings: List[Dict[str, Any]] = []
        scan_stats: Dict[str, Any] = {"assets": 0, "live_endpoints": 0, "findings": 0}

        if target:
            from core.global_state import GLOBAL_EVIDENCE_STORE
            from core.live_scanner import run_live_security_scan

            async def _phase_cb(phase_name: str, pct: float, detail: Dict[str, Any]) -> bool:
                store.update_run(run_id, status="running", current_phase=phase_name, progress=pct)
                store.append_event(
                    "pipeline.progress",
                    run_id=run_id,
                    engagement_id=engagement_id,
                    source=kind,
                    payload={"phase": phase_name, "progress": pct, "target": target, "mode": mode, **detail},
                )
                if target in _active_pipelines:
                    _active_pipelines[target]["phase"] = phase_name
                return await GLOBAL_RUN_CONTROLLER.checkpoint(run_id)

            scan_res = await run_live_security_scan(
                target=target,
                run_id=run_id,
                mode=mode,
                proxy=proxy,
                phase_cb=_phase_cb,
            )
            if scan_res.get("cancelled"):
                store.update_run(run_id, status="stopped", finished_at=time.time())
                if target in _active_pipelines:
                    _active_pipelines[target]["status"] = "stopped"
                return

            discovered_assets = list(scan_res.get("assets") or [])
            discovered_findings = list(scan_res.get("findings") or [])
            observations = list(scan_res.get("observations") or [])
            scan_stats = {
                "assets": len(discovered_assets),
                "live_endpoints": int(scan_res.get("live_count") or 0),
                "endpoints": int(scan_res.get("endpoints_count") or 0),
                "findings": len(discovered_findings),
            }

            # Persist observations & findings into EvidenceStore and emit live events
            for obs in observations:
                GLOBAL_EVIDENCE_STORE.add_evidence(
                    run_id=run_id,
                    source_worker=kind,
                    source_tool=str(obs.get("source_tool") or "native_scanner"),
                    evidence_type=str(obs.get("evidence_type") or "observation"),
                    content=str(obs.get("content") or ""),
                    confidence=float(obs.get("confidence") or 0.9),
                    metadata={
                        "target": str(obs.get("target") or target),
                        "title": str(obs.get("title") or "Recon Observation"),
                    },
                )

            for fd in discovered_findings:
                ev_type = "proof" if str(fd.get("severity") or "").upper() in {"CRITICAL", "HIGH", "MEDIUM"} else "anomaly"
                GLOBAL_EVIDENCE_STORE.add_evidence(
                    run_id=run_id,
                    source_worker=kind,
                    source_tool="native_security_audit",
                    evidence_type=ev_type,
                    content=str(fd.get("evidence") or ""),
                    confidence=float(fd.get("confidence") or 0.9),
                    metadata={
                        "target": str(fd.get("endpoint") or target),
                        "title": str(fd.get("title") or "Finding"),
                        "severity": str(fd.get("severity") or "INFO"),
                        "cvss_score": float(fd.get("cvss_score") or 0.0),
                        "vuln_class": str(fd.get("vuln_class") or "web"),
                    },
                )
                store.append_event(
                    "finding.discovered",
                    run_id=run_id,
                    engagement_id=engagement_id,
                    source=kind,
                    payload={
                        "title": fd.get("title"),
                        "severity": fd.get("severity"),
                        "endpoint": fd.get("endpoint"),
                        "vuln_class": fd.get("vuln_class"),
                    },
                )

            if discovered_assets:
                store.append_event(
                    "run.assets",
                    run_id=run_id,
                    engagement_id=engagement_id,
                    source=kind,
                    payload={
                        "target": target,
                        "assets_count": len(discovered_assets),
                        "live_endpoints": scan_stats["live_endpoints"],
                        "findings_count": len(discovered_findings),
                    },
                )

            # Persist session & report artifacts for /findings when live HTTP findings exist
            if scan_stats["live_endpoints"] > 0 and not target.lower().endswith((".example", ".invalid", ".test")):
                try:
                    sessions_dir = DATA_DIR / "sessions"
                    sessions_dir.mkdir(parents=True, exist_ok=True)
                    session_file = sessions_dir / f"{run_id}.json"
                    session_file.write_text(
                        json.dumps(
                            {
                                "id": run_id,
                                "target": target,
                                "mode": mode,
                                "status": "completed",
                                "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                                "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                                "findings": [
                                    {
                                        "id": fd.get("id"),
                                        "title": fd.get("title"),
                                        "description": (fd.get("poc_details") or {}).get("description", ""),
                                        "severity": str(fd.get("severity") or "info").lower(),
                                        "cvss_score": float(fd.get("cvss_score") or 0.0),
                                        "tool": "hunter_live_scanner",
                                        "evidence": fd.get("evidence", ""),
                                        "recommendation": "Review HTTP security configuration and verify finding reproduction.",
                                    }
                                    for fd in discovered_findings
                                ],
                            },
                            indent=2,
                            ensure_ascii=False,
                        ),
                        encoding="utf-8",
                    )
                    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
                    for idx, fd in enumerate(discovered_findings[:8]):
                        rep_file = REPORTS_DIR / f"{run_id}_f{idx + 1}.json"
                        rep_file.write_text(
                            json.dumps(
                                {
                                    "report_id": fd.get("id") or f"{run_id}-{idx + 1}",
                                    "title": fd.get("title", "Finding"),
                                    "severity": str(fd.get("severity") or "INFO").capitalize(),
                                    "vulnerability_type": fd.get("vuln_class", "web"),
                                    "target": fd.get("endpoint") or target,
                                    "platform": "HackerOne",
                                    "report_ready": str(fd.get("status", "")).upper() == "CONFIRMED",
                                    "confidence": float(fd.get("confidence") or 0.9),
                                    "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                                    "summary": (fd.get("poc_details") or {}).get("description", ""),
                                    "evidence": fd.get("evidence", ""),
                                    "remediation": "Harden server headers, TLS, access controls, and input output encoding.",
                                },
                                indent=2,
                                ensure_ascii=False,
                            ),
                            encoding="utf-8",
                        )
                except Exception as art_exc:
                    logger.debug("Artifact export note for %s: %s", run_id, art_exc)

            # Persist Lead Board candidates for discovered live endpoints
            try:
                from bughunter.tools.lead_board import add_lead

                lead_tgt = target.replace("https://", "").replace("http://", "").split("/", 1)[0]
                for a in discovered_assets:
                    if a.get("kind") == "ENDPOINT" and a.get("attributes", {}).get("live_url"):
                        add_lead(
                            lead_tgt,
                            skill="hunt-misc",
                            evidence=str(a["attributes"]["live_url"]),
                            signal=f"HTTP {a['attributes'].get('status_code', '')} live endpoint",
                            priority="med",
                        )
                        break
            except Exception:
                pass

        if not await GLOBAL_RUN_CONTROLLER.checkpoint(run_id):
            store.update_run(run_id, status="stopped", finished_at=time.time())
            if target in _active_pipelines:
                _active_pipelines[target]["status"] = "stopped"
            return

        existing_run = store.get_run(run_id) or {}
        merged_meta = dict(existing_run.get("meta") or {})
        merged_meta["discovered_assets"] = discovered_assets
        merged_meta["discovered_findings"] = discovered_findings
        merged_meta["scan_stats"] = scan_stats

        store.update_run(
            run_id,
            status="completed",
            current_phase="DONE",
            progress=1.0,
            meta=merged_meta,
            finished_at=time.time(),
        )
        store.append_event(
            "run.completed",
            run_id=run_id,
            engagement_id=engagement_id,
            source=kind,
            payload={
                "run_id": run_id,
                "target": target,
                "mode": mode,
                "assets_count": scan_stats["assets"],
                "live_endpoints": scan_stats["live_endpoints"],
                "findings_count": scan_stats["findings"],
            },
        )
        if target in _active_pipelines:
            _active_pipelines[target]["status"] = "completed"
            _active_pipelines[target]["phase"] = "DONE"
    except asyncio.CancelledError:
        store.update_run(run_id, status="stopped", finished_at=time.time())
        if target in _active_pipelines:
            _active_pipelines[target]["status"] = "stopped"
        raise
    except Exception as exc:
        logger.exception("Pipeline task %s failed", run_id)
        store.update_run(
            run_id,
            status="failed",
            error=str(exc),
            finished_at=time.time(),
        )
        store.append_event(
            "run.failed",
            run_id=run_id,
            engagement_id=engagement_id,
            source="pipeline",
            payload={"run_id": run_id, "error": str(exc)},
        )
        if target in _active_pipelines:
            _active_pipelines[target]["status"] = "failed"
            _active_pipelines[target]["error"] = str(exc)


async def start_platform_run(
    *,
    kind: str = "pipeline",
    target: str = "",
    engagement_id: Optional[str] = None,
    scope: Optional[List[str]] = None,
    out_of_scope: Optional[List[str]] = None,
    mode: str = "full",
    prompt: str = "",
    engine: str = "claude",
    model: str = "",
    coverage: float = 0.85,
    max_cycles: int = 10,
    force_fallback: bool = False,
    self_operate: bool = False,
    proxy: Optional[str] = None,
) -> Dict[str, Any]:
    """Start a unified managed platform run on the single ASGI event loop."""
    store = ensure_platform_wiring()
    clean_target = (target or "").strip()
    if not clean_target and engagement_id:
        eng = store.get_engagement(engagement_id)
        if eng:
            clean_target = eng.get("target", "")
    if not clean_target and kind != "engine":
        raise ValueError("target is required")

    if clean_target:
        from hunter_backend.apps.common import validate_scan_target

        ok_tgt, reason_tgt, _policy_tgt = validate_scan_target(
            clean_target,
            scope=scope,
            out_of_scope=out_of_scope,
            engagement_id=engagement_id,
            action_type=f"platform_{kind}",
        )
        if not ok_tgt:
            raise PermissionError(reason_tgt or "Target blocked by ScopeGuard policy")
    else:
        policy = check_target_policy(
            prompt,
            action_type=f"platform_{kind}",
            tool_name=engine if kind == "engine" else kind,
            scope=scope,
            out_of_scope=out_of_scope,
            engagement_id=engagement_id,
        )

    run_id = new_id("run")
    reg = register_managed_run(
        kind=kind,
        target=clean_target,
        run_id=run_id,
        engagement_id=engagement_id,
        in_scope=scope,
        out_of_scope=out_of_scope,
        status="running",
        current_phase="DISPATCH",
        meta={
            "mode": mode,
            "engine": engine,
            "model": model,
            "coverage": coverage,
            "max_cycles": max_cycles,
            "self_operate": self_operate,
            "proxy": proxy,
        },
    )
    eff_eid = reg["engagement_id"]

    if clean_target:
        _active_pipelines[clean_target] = {
            "run_id": run_id,
            "target": clean_target,
            "mode": mode,
            "status": "running",
            "phase": "DISPATCH",
            "started_at": time.time(),
        }

    task = asyncio.create_task(
        _run_pipeline_task(
            run_id=run_id,
            target=clean_target,
            mode=mode,
            scope=scope or ([clean_target] if clean_target else []),
            out_of_scope=out_of_scope or [],
            engagement_id=eff_eid,
            kind=kind,
            prompt=prompt,
            engine=engine,
            proxy=proxy,
        )
    )
    handle = reg["handle"]
    handle.task = task
    handle.state = "running"
    handle.started_at = time.time()
    task.add_done_callback(lambda t, rid=run_id: GLOBAL_RUN_CONTROLLER._on_task_done(rid, t))
    _active_mission_tasks[run_id] = task
    task.add_done_callback(lambda _t: _active_mission_tasks.pop(run_id, None))
    log_activity_event("platform", f"run.started:{kind}", clean_target or engine)
    return reg["run"]


def control_managed_run_sync(run_id: str, action: str) -> bool:
    """Thread-safe sync bridge for pause/resume/stop onto the managed task's event loop."""
    handle = GLOBAL_RUN_CONTROLLER.get(run_id)
    task = getattr(handle, "task", None) if handle is not None else None
    task_loop: Optional[asyncio.AbstractEventLoop] = None
    if task is not None:
        try:
            task_loop = task.get_loop()
        except Exception:
            task_loop = None

    def _run_sync_action() -> bool:
        if action == "pause":
            return GLOBAL_RUN_CONTROLLER.pause(run_id)
        if action == "resume":
            return GLOBAL_RUN_CONTROLLER.resume(run_id)
        if action == "stop":
            from asgiref.sync import async_to_sync

            async def _stop() -> bool:
                return await GLOBAL_RUN_CONTROLLER.stop(run_id, force=True)

            return async_to_sync(_stop)()
        return False

    if task_loop is not None and task_loop.is_running():
        try:
            running_loop = asyncio.get_running_loop()
        except RuntimeError:
            running_loop = None
        if running_loop is not task_loop:
            if action == "stop":
                fut = asyncio.run_coroutine_threadsafe(
                    GLOBAL_RUN_CONTROLLER.stop(run_id, force=True), task_loop
                )
                return bool(fut.result(timeout=3.0))
            import concurrent.futures

            res_fut: concurrent.futures.Future[bool] = concurrent.futures.Future()

            def _invoke() -> None:
                try:
                    val = (
                        GLOBAL_RUN_CONTROLLER.pause(run_id)
                        if action == "pause"
                        else GLOBAL_RUN_CONTROLLER.resume(run_id)
                    )
                    res_fut.set_result(bool(val))
                except Exception as exc:
                    res_fut.set_exception(exc)

            task_loop.call_soon_threadsafe(_invoke)
            return bool(res_fut.result(timeout=3.0))
    return _run_sync_action()


_ALLOWED_APPROVAL_RUN_KINDS = frozenset({"pipeline", "recon", "scan", "mission", "engine"})
_ALLOWED_APPROVAL_RUN_MODES = frozenset({"full", "recon", "quick", "passive", "active", "web", "vuln"})


async def execute_approved_action(
    approval: Dict[str, Any],
) -> Dict[str, Any]:
    """Execute or dispatch a digest-verified approved HITL action and emit telemetry."""
    if not verify_proposal_digest(approval):
        raise PermissionError("Approval proposal_digest verification failed; refusing execution")

    store = ensure_platform_wiring()
    action_type = str(approval.get("action_type") or "")
    target = str(approval.get("target") or "")
    run_id = approval.get("run_id")
    engagement_id = approval.get("engagement_id")
    payload = approval.get("payload") if isinstance(approval.get("payload"), dict) else {}

    result: Dict[str, Any] = {
        "executed": True,
        "action_type": action_type,
        "target": target,
        "approval_id": approval.get("approval_id"),
    }
    if action_type in {"platform_run", "scan", "mission", "pipeline"} and target:
        kind = str(payload.get("kind") or "pipeline").strip().lower()
        mode = str(payload.get("mode") or "full").strip().lower()
        if kind not in _ALLOWED_APPROVAL_RUN_KINDS:
            raise PermissionError(
                f"Disallowed approval payload kind {kind!r}; allowed: {sorted(_ALLOWED_APPROVAL_RUN_KINDS)}"
            )
        if mode not in _ALLOWED_APPROVAL_RUN_MODES:
            raise PermissionError(
                f"Disallowed approval payload mode {mode!r}; allowed: {sorted(_ALLOWED_APPROVAL_RUN_MODES)}"
            )
        started = await start_platform_run(
            kind=kind,
            target=target,
            engagement_id=engagement_id,
            mode=mode,
        )
        result["run_id"] = started.get("run_id")
    store.append_event(
        "approval.executed",
        run_id=run_id,
        engagement_id=engagement_id,
        source="approvals",
        payload=result,
    )
    return result


# ---------------------------------------------------------------------------
# Lazy service accessors (never import ui.web.*)
# ---------------------------------------------------------------------------


def get_copilot_service() -> CopilotService:
    """Return a CopilotService bound to the singleton PlatformStore."""
    return CopilotService(get_platform_store())


def get_burp_agent() -> Any:
    """Lazily initialize the BurpAgent singleton."""
    global _burp_agent_singleton
    with _SINGLETON_LOCK:
        if _burp_agent_singleton is None:
            from agents.burp_agent import BurpAgent

            _burp_agent_singleton = BurpAgent()
        return _burp_agent_singleton


def get_security_intelligence() -> Any:
    """Return SecurityIntelligence attached to BurpAgent."""
    return get_burp_agent().security_intelligence


def get_burp_gateway() -> Any:
    """Return GovernedToolGateway attached to BurpAgent."""
    return get_burp_agent().gateway


def get_static_reasoning_engine() -> Any:
    """Lazily return StaticSecurityReasoningEngine."""
    global _static_reasoning_engine
    with _SINGLETON_LOCK:
        if _static_reasoning_engine is None:
            from core.static_reasoning_engine import StaticSecurityReasoningEngine

            _static_reasoning_engine = StaticSecurityReasoningEngine()
        return _static_reasoning_engine


def get_tool_orchestrator() -> Any:
    """Lazily return the Phase 35 ToolOrchestrator."""
    global _tool_orchestrator
    with _SINGLETON_LOCK:
        if _tool_orchestrator is None:
            from core.orchestration.tool_orchestrator import ToolOrchestrator

            _tool_orchestrator = ToolOrchestrator()
        return _tool_orchestrator


def get_mcp_registry() -> Any:
    """Lazily return the UniversalMCPBridge."""
    global _mcp_registry
    with _SINGLETON_LOCK:
        if _mcp_registry is None:
            from core.arsenal.universal_mcp_bridge import UniversalMCPBridge

            _mcp_registry = UniversalMCPBridge()
        return _mcp_registry


def get_flag_service() -> Any:
    """Lazily return CTF FlagService."""
    global _flag_service
    with _SINGLETON_LOCK:
        if _flag_service is None:
            from flags.service import FlagService

            _flag_service = FlagService()
        return _flag_service


def get_extension_manager() -> Any:
    """Lazily return ExtensionRegistry."""
    global _extension_manager
    with _SINGLETON_LOCK:
        if _extension_manager is None:
            from extensions_ext import ExtensionRegistry

            _extension_manager = ExtensionRegistry()
        return _extension_manager


def get_scope_enforcer() -> Any:
    """Lazily return Phase G ScopeEnforcer bound to current scope guard."""
    global _scope_enforcer
    with _SINGLETON_LOCK:
        if _scope_enforcer is None:
            from core.scope_enforcer import ScopeEnforcer
            from core.scope_guard import ScopeGuard

            guard = ScopeGuard(
                in_scope=list(_SCOPE_STATE.get("in_scope") or []),
                out_of_scope=list(_SCOPE_STATE.get("out_of_scope") or []),
            )
            _scope_enforcer = ScopeEnforcer(guard)
        return _scope_enforcer


def refresh_scope_enforcer() -> Any:
    """Rebuild ScopeEnforcer after Phase G scope updates."""
    global _scope_enforcer
    with _SINGLETON_LOCK:
        from core.scope_enforcer import ScopeEnforcer
        from core.scope_guard import ScopeGuard

        guard = ScopeGuard(
            in_scope=list(_SCOPE_STATE.get("in_scope") or []),
            out_of_scope=list(_SCOPE_STATE.get("out_of_scope") or []),
        )
        _scope_enforcer = ScopeEnforcer(guard)
        return _scope_enforcer


def get_burp_bridge() -> Any:
    """Lazily return Phase G GLOBAL_BURP_ADAPTER."""
    global _ACTIVE_BURP_BRIDGE
    with _SINGLETON_LOCK:
        if _ACTIVE_BURP_BRIDGE is None:
            from core.burp_adapter import GLOBAL_BURP_ADAPTER

            _ACTIVE_BURP_BRIDGE = GLOBAL_BURP_ADAPTER
        return _ACTIVE_BURP_BRIDGE


def get_burp_sensor_bridge() -> Any:
    """Lazily return the ProxyMonitoringEngine sensor bridge."""
    global _burp_sensor_bridge
    with _SINGLETON_LOCK:
        if _burp_sensor_bridge is None:
            from core.integration import ProxyMonitoringEngine

            _burp_sensor_bridge = ProxyMonitoringEngine()
        return _burp_sensor_bridge


# ---------------------------------------------------------------------------
# Go Core (:7071) shared AsyncClient + ASGI lifespan
# ---------------------------------------------------------------------------


def get_go_client() -> httpx.AsyncClient:
    """Return the shared httpx.AsyncClient used for Go Core (:7071) proxy & telemetry."""
    global _GO_CLIENT
    if _GO_CLIENT is None or _GO_CLIENT.is_closed:
        from hunter_backend.auth import get_or_create_api_token

        _GO_CLIENT = httpx.AsyncClient(
            base_url=ARTEX_BASE_URL,
            timeout=httpx.Timeout(connect=2.5, read=20.0, write=10.0, pool=5.0),
            follow_redirects=False,
            headers={"Authorization": f"Bearer {get_or_create_api_token()}"},
        )
    return _GO_CLIENT


async def probe_artex_health() -> Dict[str, Any]:
    """Probe Go Core backend health without raising on offline daemon."""
    try:
        client = get_go_client()
        resp = await client.get(
            "/api/v1/health",
            timeout=httpx.Timeout(connect=0.25, read=1.5, write=1.5, pool=0.5),
        )
        body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {"raw": resp.text}
        return {
            "online": resp.status_code < 400,
            "status_code": resp.status_code,
            "url": ARTEX_BASE_URL,
            "health": body,
        }
    except Exception as exc:
        return {
            "online": False,
            "url": ARTEX_BASE_URL,
            "error": str(exc),
        }


async def fetch_go_json(path: str, timeout_s: float = 2.5) -> Optional[Dict[str, Any]]:
    """Best-effort JSON fetch from Go Core API."""
    clean = path if path.startswith("/") else f"/{path}"
    try:
        client = get_go_client()
        resp = await client.get(clean, timeout=timeout_s)
        if resp.status_code < 400:
            data = resp.json()
            return data if isinstance(data, dict) else {"data": data}
    except Exception:
        pass
    return None


def _get_learning_scheduler() -> Any:
    try:
        from core.learning.learning_server import get_scheduler

        return get_scheduler()
    except Exception:
        return None


async def startup_runtime() -> None:
    """Initialize wiring, reconcile stale runs, background workers, and Go HTTP client."""
    global MAIN_LOOP, _BURP_WORKER_TASK
    MAIN_LOOP = asyncio.get_running_loop()

    store = ensure_platform_wiring()
    try:
        active_ids = [
            item["run_id"]
            for item in GLOBAL_RUN_CONTROLLER.list_runs(active_only=True)
            if item.get("run_id")
        ]
        reconciled = store.reconcile_interrupted_runs(active_run_ids=active_ids)
        if reconciled:
            logger.info("Reconciled %d interrupted run(s) on startup", len(reconciled))
    except Exception as exc:
        logger.warning("Failed to reconcile interrupted runs: %s", exc)

    scheduler = _get_learning_scheduler()
    if scheduler is not None:
        try:
            start_fn = getattr(scheduler, "start", None)
            if callable(start_fn):
                res = start_fn()
                if asyncio.iscoroutine(res):
                    asyncio.create_task(res)
        except Exception as exc:
            logger.debug("LearningScheduler start skipped: %s", exc)

    try:
        burp = get_burp_agent()
        ai_pipe = getattr(burp, "ai_pipe", None)
        if ai_pipe is not None and hasattr(ai_pipe, "_queue"):
            q_loop = getattr(ai_pipe._queue, "_loop", None)
            if q_loop is not None and q_loop is not MAIN_LOOP:
                ai_pipe._queue = asyncio.Queue(maxsize=getattr(ai_pipe._queue, "maxsize", 500) or 500)
        start_worker = getattr(ai_pipe, "start_worker", None)
        if callable(start_worker) and (_BURP_WORKER_TASK is None or _BURP_WORKER_TASK.done()):
            res = start_worker()
            if asyncio.iscoroutine(res):
                _BURP_WORKER_TASK = asyncio.create_task(res)
    except Exception as exc:
        logger.debug("BurpAgent ai_pipe worker start skipped: %s", exc)

    get_go_client()
    log_activity_event("system", "asgi.startup", "HunterAI Django ASGI runtime started")


async def shutdown_runtime() -> None:
    """Stop active tasks, run controller, scheduler, Burp workers, and Go HTTP client."""
    global _GO_CLIENT, _BURP_WORKER_TASK

    if _BURP_WORKER_TASK is not None and not _BURP_WORKER_TASK.done():
        _BURP_WORKER_TASK.cancel()
        try:
            await _BURP_WORKER_TASK
        except (asyncio.CancelledError, Exception):
            pass
    _BURP_WORKER_TASK = None

    for task in list(_active_mission_tasks.values()):
        if not task.done():
            task.cancel()
    _active_mission_tasks.clear()

    try:
        GLOBAL_RUN_CONTROLLER.stop_all()
    except Exception as exc:
        logger.debug("GLOBAL_RUN_CONTROLLER.stop_all error: %s", exc)

    scheduler = _get_learning_scheduler()
    if scheduler is not None:
        try:
            stop_fn = getattr(scheduler, "stop", None)
            if callable(stop_fn):
                res = stop_fn()
                if asyncio.iscoroutine(res):
                    await res
        except Exception as exc:
            logger.debug("LearningScheduler stop error: %s", exc)

    try:
        if _burp_agent_singleton is not None:
            ai_pipe = getattr(_burp_agent_singleton, "ai_pipe", None)
            stop_worker = getattr(ai_pipe, "stop_worker", None)
            if callable(stop_worker):
                res = stop_worker()
                if asyncio.iscoroutine(res):
                    await res
    except Exception:
        pass

    if _GO_CLIENT is not None and not _GO_CLIENT.is_closed:
        try:
            await _GO_CLIENT.aclose()
        except Exception:
            pass
    _GO_CLIENT = None
