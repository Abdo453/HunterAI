"""Unified Platform Hub API (`/api/platform/*` + `/ws/platform`).

Provides:
- Context management (`GET/PUT /api/platform/context`) and consolidated
  bootstrap state (`GET /api/platform/overview`)
- Engagement registry bridging local SQLite/files and Go Core (:7071)
- Managed run lifecycle (`omni | pipeline | mission | engine`) registered in
  `GLOBAL_RUN_CONTROLLER` + `PlatformStore`
- Ordered replayable event streams via SSE (`/api/platform/stream`) and
  WebSocket (`/ws/platform`) with `since_seq` / `Last-Event-ID` & heartbeats
- Approval queue & ScopeGuard/PolicyEngine-gated execution
- Cross-domain search across engagements, runs, findings, assets, leads,
  conversations, tools, and central skills
- Truthful async httpx bridge to ARTEX-Pro Go Core (`127.0.0.1:7071/api/v1/*`)
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, List, Optional, Set, Tuple

import httpx
from fastapi import APIRouter, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from core.copilot_service import (
    collect_live_context,
    detect_live_providers,
    evaluate_action_policy,
    is_tcp_reachable,
)
from core.platform_store import PlatformStore, get_platform_store, new_id, redact_payload
from core.run_control import GLOBAL_RUN_CONTROLLER, RunHandle, RunState

logger = logging.getLogger("hunter_ai.platform_hub")

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
GO_CORE_BASE_URL = os.getenv("ARTEX_GO_URL", "http://127.0.0.1:7071").rstrip("/")

router = APIRouter(tags=["platform_hub"])


# ── In-Process Real-Time Event Bus ────────────────────────────────────────────

class PlatformEventBus:
    """Thread-safe async pubsub fan-out wired to PlatformStore.append_event."""

    def __init__(self) -> None:
        self._subscribers: Set[Tuple[asyncio.AbstractEventLoop, asyncio.Queue]] = set()
        self._attached_store: Optional[PlatformStore] = None

    def attach(self, store: PlatformStore) -> None:
        if self._attached_store is store:
            return
        store.register_event_listener(self.publish_from_any_thread)
        self._attached_store = store

    def subscribe(self) -> Tuple[asyncio.AbstractEventLoop, asyncio.Queue]:
        loop = asyncio.get_running_loop()
        q: asyncio.Queue = asyncio.Queue(maxsize=512)
        entry = (loop, q)
        self._subscribers.add(entry)
        return entry

    def unsubscribe(self, entry: Tuple[asyncio.AbstractEventLoop, asyncio.Queue]) -> None:
        self._subscribers.discard(entry)

    def publish_from_any_thread(self, event: Dict[str, Any]) -> None:
        for loop, q in list(self._subscribers):
            if loop.is_closed():
                self._subscribers.discard((loop, q))
                continue

            def _put(queue: asyncio.Queue = q, item: Dict[str, Any] = event) -> None:
                try:
                    if queue.full():
                        queue.get_nowait()
                    queue.put_nowait(item)
                except Exception:
                    pass

            try:
                loop.call_soon_threadsafe(_put)
            except Exception:
                pass


EVENT_BUS = PlatformEventBus()
_SYNC_HOOK_INSTALLED = False
_PREV_RUN_STATE_HOOK = None


def ensure_platform_wiring(store: Optional[PlatformStore] = None) -> PlatformStore:
    """Attach event bus and sync GLOBAL_RUN_CONTROLLER transitions into PlatformStore."""
    global _SYNC_HOOK_INSTALLED, _PREV_RUN_STATE_HOOK
    st = store or get_platform_store()
    EVENT_BUS.attach(st)

    if not _SYNC_HOOK_INSTALLED:
        _PREV_RUN_STATE_HOOK = GLOBAL_RUN_CONTROLLER.on_state_change

        def _on_run_state_change(handle: RunHandle) -> None:
            if _PREV_RUN_STATE_HOOK is not None:
                try:
                    _PREV_RUN_STATE_HOOK(handle)
                except Exception:
                    pass
            try:
                meta = dict(handle.meta or {})
                target = str(meta.get("target") or "")
                eng_id = meta.get("engagement_id")
                existing = st.get_run(handle.run_id)
                if existing:
                    st.update_run(
                        handle.run_id,
                        status=handle.state,
                        error=handle.error or "",
                        started_at=handle.started_at,
                        finished_at=handle.finished_at,
                        meta=meta,
                    )
                else:
                    st.upsert_run(
                        run_id=handle.run_id,
                        kind=handle.kind,
                        target=target,
                        engagement_id=eng_id,
                        status=handle.state,
                        meta=meta,
                        error=handle.error or "",
                        started_at=handle.started_at,
                        finished_at=handle.finished_at,
                    )
                st.append_event(
                    f"RUN_{handle.state.upper()}",
                    run_id=handle.run_id,
                    engagement_id=eng_id,
                    source="run_controller",
                    payload={
                        "run_id": handle.run_id,
                        "kind": handle.kind,
                        "target": target,
                        "state": handle.state,
                        "error": handle.error,
                    },
                )
            except Exception as exc:
                logger.debug("RunController -> PlatformStore sync error: %s", exc)

        GLOBAL_RUN_CONTROLLER.on_state_change = _on_run_state_change
        _SYNC_HOOK_INSTALLED = True

    return st


def register_managed_run(
    run_id: str,
    task: Optional[asyncio.Task],
    *,
    kind: str,
    target: str = "",
    engagement_id: Optional[str] = None,
    meta: Optional[Dict[str, Any]] = None,
    current_phase: str = "INIT",
) -> RunHandle:
    """Register a background task in both GLOBAL_RUN_CONTROLLER and PlatformStore."""
    store = ensure_platform_wiring()
    merged_meta = dict(meta or {})
    if target and "target" not in merged_meta:
        merged_meta["target"] = target
    if engagement_id and "engagement_id" not in merged_meta:
        merged_meta["engagement_id"] = engagement_id

    store.upsert_run(
        run_id=run_id,
        kind=kind,
        target=target,
        engagement_id=engagement_id,
        status="running" if task is not None else "pending",
        current_phase=current_phase,
        meta=merged_meta,
    )
    handle = GLOBAL_RUN_CONTROLLER.register(run_id, task, kind=kind, meta=merged_meta)
    return handle


# ── Helpers: Go Core Bridge & Control Settings ────────────────────────────────

async def _probe_artex_health() -> Dict[str, Any]:
    url = f"{GO_CORE_BASE_URL}/api/v1/health"
    try:
        async with httpx.AsyncClient(timeout=1.5, trust_env=False) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                return {
                    "online": True,
                    "status": "healthy",
                    "base_url": f"{GO_CORE_BASE_URL}/api/v1",
                    "upstream": resp.json(),
                }
            return {
                "online": False,
                "status": "degraded",
                "base_url": f"{GO_CORE_BASE_URL}/api/v1",
                "http_status": resp.status_code,
                "error": f"Go Core returned HTTP {resp.status_code}",
            }
    except Exception as exc:
        return {
            "online": False,
            "status": "offline",
            "base_url": f"{GO_CORE_BASE_URL}/api/v1",
            "error": str(exc),
        }


async def _fetch_go_json(path: str, timeout: float = 1.5) -> Tuple[bool, Any, str]:
    url = f"{GO_CORE_BASE_URL}{path}"
    try:
        async with httpx.AsyncClient(timeout=timeout, trust_env=False) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                return True, resp.json(), ""
            return False, None, f"HTTP {resp.status_code}"
    except Exception as exc:
        return False, None, str(exc)


def _read_control_settings(store: PlatformStore) -> Dict[str, Any]:
    saved = store.get_all_settings()
    defaults = {
        "upstream_proxy": "http://127.0.0.1:8080",
        "burp_agent_port": 8085,
        "max_concurrent_agents": 5,
        "safe_boundaries_enforced": True,
        "llm_policy": os.getenv("HUNTER_LLM_POLICY", "cloud_first"),
        "default_model": "auto",
        "rate_limit_rps": 2.0,
    }
    defaults.update(saved)
    return defaults


def _load_local_engagements_merged(store: PlatformStore) -> List[Dict[str, Any]]:
    by_id: Dict[str, Dict[str, Any]] = {}
    for eng in store.list_engagements(limit=200):
        by_id[eng["engagement_id"]] = eng

    # Include authorized_targets.json entries not already imported
    auth_file = _REPO_ROOT / "data" / "authorized_targets.json"
    if auth_file.is_file():
        try:
            items = json.loads(auth_file.read_text(encoding="utf-8"))
            if isinstance(items, list):
                for item in items:
                    eid = str(item.get("id") or "")
                    if eid and eid not in by_id:
                        by_id[eid] = {
                            "engagement_id": eid,
                            "name": item.get("name") or item.get("url") or eid,
                            "target": item.get("url") or "",
                            "in_scope": item.get("in_scope") or [],
                            "out_of_scope": item.get("out_of_scope") or [],
                            "status": str(item.get("status") or "authorized").lower(),
                            "source": "authorized_targets.json",
                            "created_at": item.get("created_at"),
                        }
        except Exception:
            pass
    return list(by_id.values())


# ── Request Models ────────────────────────────────────────────────────────────

class ContextUpdateRequest(BaseModel):
    active_engagement_id: Optional[str] = None
    active_run_id: Optional[str] = None
    active_conversation_id: Optional[str] = None
    extra: Optional[Dict[str, Any]] = None


class EngagementCreateRequest(BaseModel):
    name: Optional[str] = None
    target: str = Field(..., min_length=1)
    in_scope: Optional[List[str]] = None
    out_of_scope: Optional[List[str]] = None
    status: str = "authorized"
    set_active: bool = True
    metadata: Optional[Dict[str, Any]] = None


class RunStartRequest(BaseModel):
    kind: str = Field(default="pipeline", description="omni | pipeline | mission | engine")
    target: str = ""
    engagement_id: Optional[str] = None
    scope: Optional[List[str]] = None
    out_of_scope: Optional[List[str]] = None
    mode: str = "full"
    prompt: str = ""
    engine: str = "claude"
    model: str = ""
    coverage: float = Field(default=0.85, ge=0.0, le=1.0)
    max_cycles: int = Field(default=10, ge=1, le=50)
    force_fallback: bool = False
    self_operate: bool = False
    proxy: Optional[str] = None


class ApprovalDecideRequest(BaseModel):
    decision: str = Field(..., description="approved | rejected")
    note: str = ""
    decided_by: str = "operator"


# ── Context & Consolidated Overview ───────────────────────────────────────────

@router.get("/api/platform/context")
async def get_platform_context():
    store = ensure_platform_wiring()
    return {"status": "ok", "context": store.get_context()}


@router.put("/api/platform/context")
async def put_platform_context(req: ContextUpdateRequest):
    store = ensure_platform_wiring()
    fields = req.model_fields_set
    kwargs: Dict[str, Any] = {}
    if "active_engagement_id" in fields:
        kwargs["active_engagement_id"] = req.active_engagement_id
    if "active_run_id" in fields:
        kwargs["active_run_id"] = req.active_run_id
    if "active_conversation_id" in fields:
        kwargs["active_conversation_id"] = req.active_conversation_id
    if "extra" in fields:
        kwargs["extra"] = req.extra
    ctx = store.update_context(**kwargs)
    return {"status": "ok", "context": ctx}


@router.get("/api/platform/overview")
async def get_platform_overview():
    store = ensure_platform_wiring()
    live_ctx = await asyncio.to_thread(collect_live_context, store)
    artex_health, providers = await asyncio.gather(
        _probe_artex_health(),
        asyncio.to_thread(detect_live_providers),
    )

    burp_proxy_online = is_tcp_reachable("127.0.0.1", 8080, timeout=0.08)
    burp_agent_online = is_tcp_reachable("127.0.0.1", 8085, timeout=0.08)
    engagements = _load_local_engagements_merged(store)
    runs = live_ctx.get("runs", [])
    approvals = store.list_approvals(limit=50)
    pending_approvals = [a for a in approvals if a.get("status") == "pending"]
    conversations = store.list_conversations(limit=30)
    notifications = store.list_notifications(limit=30)
    unread_count = sum(1 for n in notifications if not n.get("read"))

    return {
        "status": "ok",
        "context": store.get_context(),
        "engagements": engagements,
        "runs": runs,
        "approvals": {
            "pending": pending_approvals,
            "recent": approvals[:15],
            "pending_count": len(pending_approvals),
        },
        "conversations": conversations,
        "notifications": notifications,
        "settings": _read_control_settings(store),
        "services": {
            "artex_go_core": artex_health,
            "ollama": {"online": providers["ollama_reachable"], "host": providers["ollama_host"]},
            "lm_studio": {"online": providers["lm_studio_reachable"], "host": providers["lm_studio_host"]},
            "cloud_providers": providers["cloud"],
            "burp_proxy": {"online": burp_proxy_online, "host": "127.0.0.1:8080"},
            "burp_agent": {"online": burp_agent_online, "host": "127.0.0.1:8085"},
        },
        "counts": {
            "engagements": len(engagements),
            "runs": len(runs),
            "active_runs": live_ctx.get("active_runs_count", 0),
            "pending_approvals": len(pending_approvals),
            "findings": len(live_ctx.get("findings", [])),
            "assets": len(live_ctx.get("assets", [])),
            "leads": len(live_ctx.get("leads", [])),
            "conversations": len(conversations),
            "unread_notifications": unread_count,
            "tools_installed": len(live_ctx.get("tools_installed", [])),
            "agents": live_ctx.get("agents_count", 0),
        },
        "latest_seq": store.latest_seq(),
    }


# ── Engagements Bridge ────────────────────────────────────────────────────────

@router.get("/api/platform/engagements")
async def list_platform_engagements():
    store = ensure_platform_wiring()
    local_list = _load_local_engagements_merged(store)
    go_ok, go_data, go_err = await _fetch_go_json("/api/v1/engagements")

    merged = list(local_list)
    seen_ids = {e["engagement_id"] for e in merged}
    go_count = 0
    if go_ok and isinstance(go_data, list):
        go_count = len(go_data)
        for ge in go_data:
            gid = str(ge.get("id") or ge.get("code") or "")
            if not gid or gid in seen_ids:
                continue
            merged.append({
                "engagement_id": gid,
                "name": ge.get("code") or ge.get("target_url") or gid,
                "target": ge.get("target_url") or "",
                "in_scope": [s.strip() for s in str(ge.get("authorized_scope") or "").split(",") if s.strip()],
                "out_of_scope": [],
                "status": str(ge.get("status") or "active").lower(),
                "source": "artex_go",
                "created_at": ge.get("created_at"),
            })

    return {
        "status": "ok",
        "count": len(merged),
        "engagements": merged,
        "go_core": {
            "online": go_ok,
            "count": go_count,
            "error": None if go_ok else go_err,
        },
    }


@router.post("/api/platform/engagements")
async def create_platform_engagement(req: EngagementCreateRequest):
    store = ensure_platform_wiring()
    target = req.target.strip()
    in_scope = req.in_scope if req.in_scope is not None else [target]
    out_of_scope = req.out_of_scope or []

    # Check non-overridable invariants (unless explicit IP allowlisted)
    policy_check = evaluate_action_policy(
        action_type="ENGAGEMENT_SCOPE",
        target=target,
        tool_name="scope_guard",
        in_scope=in_scope,
        out_of_scope=out_of_scope,
        allow_active_tests=True,
    )
    if not policy_check["allowed"]:
        raise HTTPException(status_code=403, detail=policy_check["reason"])

    eng = store.upsert_engagement(
        target=target,
        name=req.name or target,
        in_scope=in_scope,
        out_of_scope=out_of_scope,
        status=req.status,
        source="local",
        metadata=req.metadata or {},
    )
    store.append_event(
        "ENGAGEMENT_CREATED",
        engagement_id=eng["engagement_id"],
        source="platform_hub",
        payload={"engagement_id": eng["engagement_id"], "target": eng["target"], "in_scope": eng["in_scope"]},
    )
    if req.set_active:
        store.update_context(active_engagement_id=eng["engagement_id"])

    return {"status": "ok", "engagement": eng}


@router.get("/api/platform/engagements/{engagement_id}")
async def get_platform_engagement(engagement_id: str):
    store = ensure_platform_wiring()
    eng = store.get_engagement(engagement_id)
    if not eng:
        for item in _load_local_engagements_merged(store):
            if item["engagement_id"] == engagement_id:
                eng = item
                break

    go_ok, go_engs, go_err = await _fetch_go_json("/api/v1/engagements")
    if not eng and go_ok and isinstance(go_engs, list):
        for ge in go_engs:
            gid = str(ge.get("id") or ge.get("code") or "")
            if gid == engagement_id:
                eng = {
                    "engagement_id": gid,
                    "name": ge.get("code") or ge.get("target_url") or gid,
                    "target": ge.get("target_url") or "",
                    "in_scope": [s.strip() for s in str(ge.get("authorized_scope") or "").split(",") if s.strip()],
                    "out_of_scope": [],
                    "status": str(ge.get("status") or "active").lower(),
                    "source": "artex_go",
                    "created_at": ge.get("created_at"),
                }
                break

    if not eng:
        raise HTTPException(status_code=404, detail=f"Engagement '{engagement_id}' not found")

    runs = store.list_runs(engagement_id=engagement_id, limit=50)
    approvals = store.list_approvals(engagement_id=engagement_id, limit=50)
    events = store.list_events(engagement_id=engagement_id, limit=100)
    live_ctx = await asyncio.to_thread(collect_live_context, store, engagement_id=engagement_id)

    go_assets: List[Any] = []
    go_findings: List[Any] = []
    if go_ok:
        ok_a, assets_data, _ = await _fetch_go_json(f"/api/v1/assets?target={eng.get('target', '')}")
        if ok_a and isinstance(assets_data, list):
            go_assets = assets_data
        ok_f, findings_data, _ = await _fetch_go_json("/api/v1/findings")
        if ok_f and isinstance(findings_data, list):
            go_findings = findings_data

    return {
        "status": "ok",
        "engagement": eng,
        "runs": runs,
        "approvals": approvals,
        "events": events,
        "assets": live_ctx.get("assets", []) + go_assets,
        "findings": live_ctx.get("findings", []) + go_findings,
        "leads": live_ctx.get("leads", []),
        "go_core": {"online": go_ok, "error": None if go_ok else go_err},
    }


# ── Runs Lifecycle ────────────────────────────────────────────────────────────

async def start_platform_run(req: RunStartRequest) -> Dict[str, Any]:
    """Start and register a managed run in GLOBAL_RUN_CONTROLLER and PlatformStore."""
    store = ensure_platform_wiring()
    kind = (req.kind or "pipeline").strip().lower()
    if kind not in ("omni", "pipeline", "mission", "engine"):
        raise HTTPException(status_code=400, detail=f"Unsupported run kind '{kind}'. Must be omni|pipeline|mission|engine.")

    target = req.target.strip()
    if kind != "engine" and not target:
        raise HTTPException(status_code=400, detail="target is required")

    if kind == "engine":
        from engines.registry import DRIVERS

        if not req.prompt.strip():
            raise HTTPException(status_code=400, detail="prompt is required for engine runs")
        if req.engine not in DRIVERS:
            raise HTTPException(status_code=404, detail=f"Unknown engine '{req.engine}'. Available: {sorted(DRIVERS)}")

    # Resolve engagement & scope
    eng = store.get_engagement(req.engagement_id) if req.engagement_id else None
    in_scope = list(req.scope) if req.scope is not None else list((eng or {}).get("in_scope") or ([target] if target else []))
    out_of_scope = list(req.out_of_scope) if req.out_of_scope is not None else list((eng or {}).get("out_of_scope") or [])

    if target:
        policy = evaluate_action_policy(
            action_type="START_RUN",
            target=target,
            tool_name=kind,
            command_args=req.prompt or req.mode,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            allow_active_tests=True,
        )
        if not policy["allowed"]:
            raise HTTPException(status_code=403, detail=policy["reason"])

    if not eng and target:
        eng = store.upsert_engagement(
            target=target,
            name=target,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            source="run_start",
        )
    eng_id = eng["engagement_id"] if eng else req.engagement_id

    run_id = new_id(f"run_{kind[:4]}")
    task_id = new_id("task")

    async def _runner_coro() -> Dict[str, Any]:
        store.update_run(run_id, status="running", current_phase="RUNNING", started_at=time.time())
        store.append_event(
            "RUN_STARTED",
            run_id=run_id,
            engagement_id=eng_id,
            task_id=task_id,
            source="platform_hub",
            payload={"kind": kind, "target": target, "mode": req.mode},
        )
        try:
            if not await GLOBAL_RUN_CONTROLLER.checkpoint(run_id):
                store.update_run(run_id, status="stopped", finished_at=time.time())
                return {"status": "stopped"}

            if kind == "pipeline":
                from core.pipeline_runner import ReconPipelineRunner
                from core.scope_guard import ScopeGuard

                async def _pipe_cb(ev: Dict[str, Any]) -> None:
                    await GLOBAL_RUN_CONTROLLER.checkpoint(run_id)
                    ev_name = str(ev.get("event") or "PIPELINE_EVENT").upper()
                    store.append_event(
                        ev_name,
                        run_id=run_id,
                        engagement_id=eng_id,
                        task_id=task_id,
                        source="pipeline_runner",
                        payload=ev,
                    )
                    if ev.get("name"):
                        store.update_run(run_id, current_phase=str(ev["name"]))

                guard = ScopeGuard(in_scope=in_scope or [target], out_of_scope=out_of_scope)
                runner = ReconPipelineRunner(target, scope_guard=guard, progress_cb=_pipe_cb, session_id=run_id)
                res = await runner.run()
                store.update_run(run_id, status="completed", current_phase="DONE", progress=100.0, finished_at=time.time(), meta={"result": res})
                return res

            if kind == "mission":
                from agents.autonomous_mission_agent import AutonomousMissionAgent
                from agents.base_agent import AgentTask
                from tools.tool_manager import ToolManager

                async def _mission_cb(ev: Dict[str, Any]) -> None:
                    await GLOBAL_RUN_CONTROLLER.checkpoint(run_id)
                    store.append_event(
                        str(ev.get("event") or "MISSION_EVENT").upper(),
                        run_id=run_id,
                        engagement_id=eng_id,
                        task_id=task_id,
                        agent_id="autonomous_mission_agent",
                        source="mission_agent",
                        payload=ev,
                    )

                agent = AutonomousMissionAgent(tool_manager=ToolManager(), progress_callback=_mission_cb)
                agent_task = AgentTask(target=target, mode=req.mode, session_id=run_id)
                res = await agent.run(agent_task)
                store.update_run(
                    run_id,
                    status="completed" if res.success else "failed",
                    current_phase="DONE",
                    progress=100.0,
                    finished_at=time.time(),
                    meta={"findings_count": len(res.findings)},
                )
                return {"success": res.success, "findings_count": len(res.findings)}

            if kind == "omni":
                from core.engine.omni_hunter_engine import AssessmentConfig, OmniHunterEngine

                clean_domain = target.replace("https://", "").replace("http://", "").split("/")[0]
                cfg = AssessmentConfig(
                    target_url=target if target.startswith("http") else f"https://{target}",
                    scope_domains=in_scope or [clean_domain],
                    out_of_scope_domains=out_of_scope,
                    coverage_threshold=req.coverage,
                    max_cycles=req.max_cycles,
                    force_tool_fallback=req.force_fallback,
                    self_operate=req.self_operate,
                    proxy=req.proxy,
                    engagement_id=eng_id or new_id("eng"),
                    authorized_by="Platform Hub Operator",
                )
                engine = OmniHunterEngine(cfg)
                res = await asyncio.to_thread(engine.run)
                store.update_run(
                    run_id,
                    status="completed",
                    current_phase=res.phase_reached.value,
                    progress=round(float(res.coverage_pct), 1),
                    finished_at=time.time(),
                    meta={
                        "confirmed_findings_count": len(res.confirmed_findings),
                        "coverage_pct": res.coverage_pct,
                    },
                )
                return {"engagement_id": res.engagement_id, "confirmed_findings": len(res.confirmed_findings)}

            # kind == "engine"
            from agents.base_agent import AgentTask
            from core.scope_guard import ScopeGuard
            from engines.worker import EngineWorker, EngineWorkerConfig

            guard = ScopeGuard(in_scope=in_scope, out_of_scope=out_of_scope)
            cfg = EngineWorkerConfig(engine=req.engine, model=req.model)
            worker = EngineWorker(cfg, scope_guard=guard)
            res = await worker.run(AgentTask(target=target, mode="engine", session_id=run_id, extra={"prompt": req.prompt}))
            store.update_run(
                run_id,
                status="completed" if res.success else "failed",
                current_phase="DONE",
                progress=100.0,
                finished_at=time.time(),
                meta={"output": (res.raw_output or {}).get("text", "")[:1000]},
            )
            return {"success": res.success}
        except asyncio.CancelledError:
            store.update_run(run_id, status="stopped", finished_at=time.time())
            store.append_event("RUN_STOPPED", run_id=run_id, engagement_id=eng_id, task_id=task_id, source="platform_hub", payload={"reason": "cancelled"})
            raise
        except Exception as exc:
            store.update_run(run_id, status="failed", error=str(exc), finished_at=time.time())
            store.append_event("RUN_FAILED", run_id=run_id, engagement_id=eng_id, task_id=task_id, source="platform_hub", payload={"error": str(exc)})
            logger.exception("Managed run %s failed", run_id)
            return {"error": str(exc)}

    async_task = asyncio.create_task(_runner_coro(), name=f"platform_run:{run_id}")
    register_managed_run(
        run_id,
        async_task,
        kind=kind,
        target=target,
        engagement_id=eng_id,
        meta={"mode": req.mode, "task_id": task_id, "in_scope": in_scope},
    )
    store.update_context(active_engagement_id=eng_id, active_run_id=run_id)
    run_rec = store.get_run(run_id)
    return {"status": "started", "run": run_rec}


@router.get("/api/platform/runs")
async def list_platform_runs(
    kind: Optional[str] = None,
    engagement_id: Optional[str] = None,
    status: Optional[str] = None,
    active_only: bool = False,
    limit: int = 100,
):
    store = ensure_platform_wiring()
    rows = store.list_runs(
        kind=kind,
        engagement_id=engagement_id,
        status=status,
        active_only=active_only,
        limit=limit,
    )
    by_id = {r["run_id"]: r for r in rows}

    for live in GLOBAL_RUN_CONTROLLER.list_runs(kind=kind, active_only=active_only, limit=limit):
        rid = live["run_id"]
        if rid in by_id:
            by_id[rid]["status"] = live["state"]
            by_id[rid]["live_managed"] = True
        else:
            by_id[rid] = {
                "run_id": rid,
                "kind": live.get("kind", "generic"),
                "target": (live.get("meta") or {}).get("target", ""),
                "engagement_id": (live.get("meta") or {}).get("engagement_id"),
                "status": live.get("state", "running"),
                "meta": live.get("meta") or {},
                "started_at": live.get("started_at"),
                "finished_at": live.get("finished_at"),
                "created_at": live.get("created_at"),
                "live_managed": True,
            }

    merged = sorted(by_id.values(), key=lambda x: float(x.get("created_at") or 0.0), reverse=True)[:limit]
    return {"status": "ok", "count": len(merged), "runs": merged}


@router.post("/api/platform/runs/start")
async def api_platform_start_run(req: RunStartRequest):
    return await start_platform_run(req)


@router.post("/api/platform/runs/{run_id}/pause")
async def api_platform_pause_run(run_id: str):
    store = ensure_platform_wiring()
    ok = GLOBAL_RUN_CONTROLLER.pause(run_id)
    if not ok:
        existing = store.get_run(run_id)
        if not existing:
            raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")
        raise HTTPException(status_code=409, detail=f"Run '{run_id}' cannot be paused in state '{existing['status']}'")
    store.update_run(run_id, status="paused")
    return {"status": "ok", "run_id": run_id, "state": "paused"}


@router.post("/api/platform/runs/{run_id}/resume")
async def api_platform_resume_run(run_id: str):
    store = ensure_platform_wiring()
    ok = GLOBAL_RUN_CONTROLLER.resume(run_id)
    if not ok:
        existing = store.get_run(run_id)
        if not existing:
            raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")
        raise HTTPException(status_code=409, detail=f"Run '{run_id}' cannot be resumed in state '{existing['status']}'")
    store.update_run(run_id, status="running")
    return {"status": "ok", "run_id": run_id, "state": "running"}


@router.post("/api/platform/runs/{run_id}/stop")
async def api_platform_stop_run(run_id: str):
    store = ensure_platform_wiring()
    ok = await GLOBAL_RUN_CONTROLLER.stop(run_id)
    if ok:
        store.update_run(run_id, status="stopped", finished_at=time.time())
        return {"status": "ok", "run_id": run_id, "state": "stopped"}

    existing = store.get_run(run_id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")
    if existing["status"] in ("pending", "running", "paused", "stopping"):
        store.update_run(run_id, status="stopped", finished_at=time.time())
        store.append_event(
            "RUN_STOPPED",
            run_id=run_id,
            engagement_id=existing.get("engagement_id"),
            source="platform_hub",
            payload={"reason": "stopped_from_store"},
        )
        return {"status": "ok", "run_id": run_id, "state": "stopped"}
    raise HTTPException(status_code=409, detail=f"Run '{run_id}' is already in terminal state '{existing['status']}'")


# ── Replayable Event Streams (SSE + WebSocket) ────────────────────────────────

def _matches_filters(ev: Dict[str, Any], run_id: Optional[str], engagement_id: Optional[str]) -> bool:
    if run_id and ev.get("run_id") != run_id:
        return False
    if engagement_id and ev.get("engagement_id") != engagement_id:
        return False
    return True


def _format_sse_event(ev: Dict[str, Any]) -> str:
    seq = ev.get("seq", 0)
    ev_type = ev.get("event_type") or "message"
    return f"id: {seq}\nevent: {ev_type}\ndata: {json.dumps(ev, ensure_ascii=False, default=str)}\n\n"


@router.get("/api/platform/stream")
async def platform_sse_stream(
    request: Request,
    since_seq: Optional[int] = None,
    run_id: Optional[str] = None,
    engagement_id: Optional[str] = None,
    heartbeat_s: float = 15.0,
    once: bool = False,
):
    store = ensure_platform_wiring()
    last_ev_hdr = request.headers.get("last-event-id")
    if since_seq is not None:
        cursor = max(0, int(since_seq))
    elif last_ev_hdr is not None and str(last_ev_hdr).strip().isdigit():
        cursor = max(0, int(str(last_ev_hdr).strip()))
    else:
        cursor = max(0, store.latest_seq() - 50)

    hb = max(1.0, min(float(heartbeat_s), 60.0))

    async def _gen() -> AsyncGenerator[str, None]:
        sub = EVENT_BUS.subscribe()
        last_sent = cursor
        try:
            # Initial replay from durable SQLite event log
            missed = store.list_events(since_seq=last_sent, run_id=run_id, engagement_id=engagement_id, limit=250)
            for ev in missed:
                seq = int(ev["seq"])
                if seq > last_sent:
                    last_sent = seq
                    yield _format_sse_event(ev)

            if once:
                if not missed:
                    yield f": heartbeat {int(time.time())}\n\n"
                return

            while True:
                if await request.is_disconnected():
                    break
                try:
                    ev = await asyncio.wait_for(sub[1].get(), timeout=hb)
                    seq = int(ev.get("seq") or 0)
                    if seq <= last_sent:
                        continue
                    if _matches_filters(ev, run_id, engagement_id):
                        last_sent = seq
                        yield _format_sse_event(ev)
                except asyncio.TimeoutError:
                    yield f": heartbeat {int(time.time())}\n\n"
        finally:
            EVENT_BUS.unsubscribe(sub)

    return StreamingResponse(
        _gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.websocket("/ws/platform")
async def platform_websocket(ws: WebSocket):
    await ws.accept()
    store = ensure_platform_wiring()
    qp = ws.query_params
    run_id = qp.get("run_id") or None
    engagement_id = qp.get("engagement_id") or None
    raw_since = qp.get("since_seq")
    last_sent = max(0, int(raw_since)) if (raw_since is not None and str(raw_since).isdigit()) else max(0, store.latest_seq() - 50)

    sub = EVENT_BUS.subscribe()
    try:
        # Initial replay
        missed = store.list_events(since_seq=last_sent, run_id=run_id, engagement_id=engagement_id, limit=250)
        for ev in missed:
            seq = int(ev["seq"])
            if seq > last_sent:
                last_sent = seq
                await ws.send_text(json.dumps({"event": "platform_event", "data": ev}, ensure_ascii=False, default=str))

        await ws.send_text(json.dumps({"event": "connected", "latest_seq": last_sent}))

        async def _recv_loop() -> None:
            nonlocal last_sent, run_id, engagement_id
            while True:
                txt = await ws.receive_text()
                if txt == "ping":
                    await ws.send_text(json.dumps({"event": "pong", "ts": time.time()}))
                    continue
                try:
                    msg = json.loads(txt)
                except Exception:
                    continue
                if msg.get("type") == "ping" or msg.get("action") == "ping":
                    await ws.send_text(json.dumps({"event": "pong", "ts": time.time()}))
                elif "since_seq" in msg:
                    run_id = msg.get("run_id") or run_id
                    engagement_id = msg.get("engagement_id") or engagement_id
                    req_since = max(0, int(msg["since_seq"]))
                    replay = store.list_events(since_seq=req_since, run_id=run_id, engagement_id=engagement_id, limit=250)
                    for ev in replay:
                        seq = int(ev["seq"])
                        if seq > last_sent:
                            last_sent = seq
                        await ws.send_text(json.dumps({"event": "platform_event", "data": ev}, ensure_ascii=False, default=str))

        async def _push_loop() -> None:
            nonlocal last_sent
            while True:
                try:
                    ev = await asyncio.wait_for(sub[1].get(), timeout=15.0)
                    seq = int(ev.get("seq") or 0)
                    if seq <= last_sent:
                        continue
                    if _matches_filters(ev, run_id, engagement_id):
                        last_sent = seq
                        await ws.send_text(json.dumps({"event": "platform_event", "data": ev}, ensure_ascii=False, default=str))
                except asyncio.TimeoutError:
                    await ws.send_text(json.dumps({"event": "heartbeat", "ts": time.time(), "latest_seq": last_sent}))

        recv_task = asyncio.create_task(_recv_loop())
        push_task = asyncio.create_task(_push_loop())
        done, pending = await asyncio.wait({recv_task, push_task}, return_when=asyncio.FIRST_COMPLETED)
        for p in pending:
            p.cancel()
        for d in done:
            d.exception()
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.debug("WebSocket /ws/platform closed: %s", exc)
    finally:
        EVENT_BUS.unsubscribe(sub)


# ── Approvals Queue & Policy-Gated Execution ──────────────────────────────────

@router.get("/api/platform/approvals")
async def list_platform_approvals(
    status: Optional[str] = None,
    engagement_id: Optional[str] = None,
    run_id: Optional[str] = None,
    limit: int = 100,
):
    store = ensure_platform_wiring()
    items = store.list_approvals(status=status, engagement_id=engagement_id, run_id=run_id, limit=limit)
    return {"status": "ok", "count": len(items), "approvals": items}


@router.post("/api/platform/approvals/{approval_id}/decide")
async def decide_platform_approval(approval_id: str, req: ApprovalDecideRequest):
    store = ensure_platform_wiring()
    existing = store.get_approval(approval_id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"Approval '{approval_id}' not found")
    if existing["status"] != "pending":
        raise HTTPException(status_code=409, detail=f"Approval '{approval_id}' is already '{existing['status']}'")

    norm = req.decision.strip().lower()
    if norm not in ("approve", "approved", "allow", "allowed", "reject", "rejected", "deny", "denied"):
        raise HTTPException(status_code=400, detail="decision must be 'approved' or 'rejected'")
    is_approve = norm in ("approve", "approved", "allow", "allowed")

    if not is_approve:
        decided = store.decide_approval(approval_id, "rejected", decided_by=req.decided_by, note=req.note)
        if existing.get("task_id"):
            try:
                from core.global_state import GLOBAL_COORDINATOR

                GLOBAL_COORDINATOR.approve_task(existing["task_id"], False)
            except Exception:
                pass
        return {"status": "ok", "approval": decided, "executed": False}

    # Re-validate ScopeGuard + PolicyEngine before accepting approval
    eng = store.get_engagement(existing["engagement_id"]) if existing.get("engagement_id") else None
    in_scope = list((eng or {}).get("in_scope") or ([existing["target"]] if existing.get("target") else []))
    out_of_scope = list((eng or {}).get("out_of_scope") or [])

    policy = evaluate_action_policy(
        action_type=existing["action_type"],
        target=existing.get("target") or "",
        tool_name=existing.get("tool_name") or "",
        command_args=existing.get("command_args") or "",
        in_scope=in_scope,
        out_of_scope=out_of_scope,
        allow_active_tests=True,
        rationale=existing.get("rationale") or "",
    )
    if not policy["allowed"]:
        rejected = store.decide_approval(
            approval_id,
            "rejected",
            decided_by="policy_guard",
            note=f"Blocked on approval check: {policy['reason']}",
        )
        raise HTTPException(status_code=403, detail={"reason": policy["reason"], "policy": policy, "approval": rejected})

    decided = store.decide_approval(approval_id, "approved", decided_by=req.decided_by, note=req.note)

    if existing.get("task_id"):
        try:
            from core.global_state import GLOBAL_COORDINATOR

            GLOBAL_COORDINATOR.approve_task(existing["task_id"], True)
        except Exception:
            pass

    execution_outcome: Dict[str, Any] = {"executed": False, "status": "approved_only"}
    act_type = (existing.get("action_type") or "").upper()
    target = existing.get("target") or ""
    tool_name = existing.get("tool_name") or ""

    if act_type == "START_RUN" and target:
        run_res = await start_platform_run(
            RunStartRequest(
                kind=tool_name if tool_name in ("omni", "pipeline", "mission", "engine") else "pipeline",
                target=target,
                engagement_id=existing.get("engagement_id"),
                scope=in_scope,
                out_of_scope=out_of_scope,
            )
        )
        execution_outcome = {"executed": True, "kind": "run_started", "run": run_res.get("run")}
    elif act_type in ("RUN_TOOL", "GOVERNED_PROPOSAL", "EXPLOIT_POC") and tool_name:
        try:
            from core.gateway.schemas import ActionProposal
            from core.gateway.tool_gateway import GovernedToolGateway
            from core.gateway.policy_engine import PolicyEngine
            from core.copilot_service import _StrictScopeGuardAdapter

            adapter = _StrictScopeGuardAdapter(in_scope=in_scope, out_of_scope=out_of_scope, allow_active_tests=True)
            gateway = GovernedToolGateway(policy_engine=PolicyEngine(scope_guard=adapter, full_permissions=False))
            prop = ActionProposal(
                target=target,
                tool_name=tool_name,
                command_args=policy.get("sanitized_args") or "",
                action_type=act_type,
                rationale=existing.get("rationale") or "",
            )
            res = await gateway.execute_proposal(prop)
            execution_outcome = {
                "executed": not res.blocked,
                "success": res.success,
                "blocked": res.blocked,
                "returncode": res.returncode,
                "error": res.error,
                "stdout_excerpt": (res.raw_stdout or "")[:800],
            }
        except Exception as exc:
            execution_outcome = {"executed": False, "error": str(exc)}

    store.append_event(
        "APPROVAL_EXECUTED",
        run_id=existing.get("run_id"),
        engagement_id=existing.get("engagement_id"),
        task_id=existing.get("task_id"),
        source="platform_hub",
        payload={"approval_id": approval_id, "outcome": execution_outcome},
    )
    return {"status": "ok", "approval": decided, "execution": execution_outcome}


# ── Cross-Platform Global Search ──────────────────────────────────────────────

@router.get("/api/platform/search")
async def search_platform(q: str = "", limit: int = 30):
    store = ensure_platform_wiring()
    query = (q or "").strip()
    if not query:
        return {"status": "ok", "query": "", "total": 0, "results": [], "groups": {}}

    ql = query.lower()
    max_per_group = max(5, min(limit, 50))
    groups: Dict[str, List[Dict[str, Any]]] = {
        "engagements": [],
        "runs": [],
        "findings": [],
        "assets": [],
        "leads": [],
        "conversations": [],
        "tools": [],
        "central_skills": [],
    }

    # 1. Engagements
    for e in _load_local_engagements_merged(store):
        hay = f"{e.get('engagement_id','')} {e.get('name','')} {e.get('target','')} {' '.join(e.get('in_scope') or [])}".lower()
        if ql in hay:
            groups["engagements"].append({
                "kind": "engagement",
                "id": e["engagement_id"],
                "title": e.get("name") or e["engagement_id"],
                "subtitle": e.get("target") or "",
                "ref": {"kind": "engagement", "id": e["engagement_id"], "label": e.get("name") or e["engagement_id"], "section": "targets"},
            })

    # 2. Runs
    for r in store.list_runs(limit=100):
        hay = f"{r.get('run_id','')} {r.get('kind','')} {r.get('target','')} {r.get('status','')}".lower()
        if ql in hay:
            groups["runs"].append({
                "kind": "run",
                "id": r["run_id"],
                "title": f"{r.get('kind')} · {r.get('target') or r['run_id']}",
                "subtitle": f"{r.get('status')} ({r.get('current_phase')})",
                "ref": {"kind": "run", "id": r["run_id"], "label": r["run_id"], "section": "runs"},
            })

    # 3. Findings (reports + evidence)
    reports_dir = _REPO_ROOT / "data" / "reports"
    if reports_dir.is_dir():
        for p in sorted(reports_dir.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True)[:100]:
            try:
                d = json.loads(p.read_text(encoding="utf-8"))
                hay = f"{p.stem} {d.get('title','')} {d.get('target','')} {d.get('vulnerability_type','')} {d.get('severity','')}".lower()
                if ql in hay:
                    fid = str(d.get("report_id") or p.stem)
                    groups["findings"].append({
                        "kind": "finding",
                        "id": fid,
                        "title": str(d.get("title") or p.stem),
                        "subtitle": f"[{d.get('severity', 'Info')}] {d.get('target', '')}",
                        "ref": {"kind": "finding", "id": fid, "label": str(d.get("title") or fid), "section": "results"},
                    })
            except Exception:
                continue

    # 4. Assets (BurpGateway AttackSurfaceGraph)
    try:
        from ui.web.app import get_burp_gateway

        gw = get_burp_gateway()
        if gw and getattr(gw, "attack_surface_graph", None):
            for nid, node in gw.attack_surface_graph.nodes.items():
                hay = f"{nid} {getattr(node, 'name', '')} {getattr(node, 'node_type', '')}".lower()
                if ql in hay:
                    groups["assets"].append({
                        "kind": "asset",
                        "id": nid,
                        "title": getattr(node, "name", nid),
                        "subtitle": str(getattr(node, "node_type", "ASSET")),
                        "ref": {"kind": "asset", "id": nid, "label": getattr(node, "name", nid), "section": "assets"},
                    })
    except Exception:
        pass

    # 5. Leads
    leads_dir = _REPO_ROOT / "memory" / "leads"
    if leads_dir.is_dir():
        try:
            from bughunter.tools.lead_board import load_ledger

            for lp in leads_dir.glob("*.jsonl"):
                for ld in load_ledger(lp.stem):
                    hay = f"{ld.get('id','')} {ld.get('skill','')} {ld.get('evidence','')} {ld.get('signal','')} {lp.stem}".lower()
                    if ql in hay:
                        lid = str(ld.get("id") or ld.get("lead_id") or ld.get("skill"))
                        groups["leads"].append({
                            "kind": "lead",
                            "id": lid,
                            "title": f"{ld.get('skill')} ({ld.get('status', 'new')})",
                            "subtitle": f"{lp.stem} · {str(ld.get('evidence', ''))[:80]}",
                            "ref": {"kind": "lead", "id": lid, "label": str(ld.get("skill")), "section": "redteam"},
                        })
        except Exception:
            pass

    # 6. Conversations
    for c in store.search_conversations(query, limit=max_per_group):
        groups["conversations"].append({
            "kind": "conversation",
            "id": c["conversation_id"],
            "title": c.get("title") or c["conversation_id"],
            "subtitle": f"mode={c.get('mode')} · model={c.get('model')}",
            "ref": {"kind": "conversation", "id": c["conversation_id"], "label": c.get("title") or c["conversation_id"], "section": "copilot"},
        })

    # 7. Tools
    try:
        from tools.tool_manager import ToolManager

        tm = ToolManager()
        for tname in sorted(tm.INSTALL_MAP.keys()):
            if ql in tname.lower():
                groups["tools"].append({
                    "kind": "tool",
                    "id": tname,
                    "title": tname,
                    "subtitle": "Installed" if tm.is_available(tname) else "Not installed",
                    "ref": {"kind": "tool", "id": tname, "label": tname, "section": "tools"},
                })
    except Exception:
        pass

    # 8. Central Skills
    manifest_file = _REPO_ROOT / ".opencode" / "skills" / "MANIFEST.json"
    if manifest_file.is_file():
        try:
            m = json.loads(manifest_file.read_text(encoding="utf-8"))
            for sk in m.get("skills", []):
                sname = str(sk.get("name") or "")
                sdesc = str(sk.get("description") or "")
                if ql in sname.lower() or ql in sdesc.lower():
                    groups["central_skills"].append({
                        "kind": "skill",
                        "id": sname,
                        "title": sname,
                        "subtitle": sdesc[:120],
                        "ref": {"kind": "skill", "id": sname, "label": sname, "section": "skills"},
                    })
        except Exception:
            pass
    try:
        from core.skills.skill_matrix_viewer import SkillMatrixViewer

        for sk in SkillMatrixViewer.list_all_skills():
            sname = str(sk.get("name") or "")
            sdesc = str(sk.get("description") or "")
            if ql in sname.lower() or ql in sdesc.lower() or ql in str(sk.get("category", "")).lower():
                if not any(x["id"] == sname for x in groups["central_skills"]):
                    groups["central_skills"].append({
                        "kind": "skill",
                        "id": sname,
                        "title": sname,
                        "subtitle": f"[{sk.get('layer', 'skill')}] {sdesc[:100]}",
                        "ref": {"kind": "skill", "id": sname, "label": sname, "section": "skills"},
                    })
    except Exception:
        pass

    for k in groups:
        groups[k] = groups[k][:max_per_group]

    flat: List[Dict[str, Any]] = []
    for lst in groups.values():
        flat.extend(lst)

    return {
        "status": "ok",
        "query": query,
        "total": len(flat),
        "results": flat[:limit],
        "groups": groups,
    }


# ── Notifications ─────────────────────────────────────────────────────────────

@router.get("/api/platform/notifications")
async def list_notifications(unread_only: bool = False, limit: int = 50):
    store = ensure_platform_wiring()
    items = store.list_notifications(unread_only=unread_only, limit=limit)
    return {"status": "ok", "count": len(items), "notifications": items}


@router.post("/api/platform/notifications/{notification_id}/read")
async def mark_notification_read(notification_id: str):
    store = ensure_platform_wiring()
    ok = store.mark_notification_read(notification_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Notification not found")
    return {"status": "ok", "notification_id": notification_id, "read": True}


# ── ARTEX-Pro Go Core Bridge (`/api/platform/artex/*`) ────────────────────────

@router.get("/api/platform/artex/health")
async def artex_go_health():
    """Truthful async health check for ARTEX-Pro Go Core on 127.0.0.1:7071."""
    return await _probe_artex_health()


@router.api_route("/api/platform/artex/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def artex_go_proxy(path: str, request: Request):
    """Async httpx proxy to Go Core `127.0.0.1:7071/api/v1/{path}`."""
    clean = path.lstrip("/")
    if ".." in clean.split("/"):
        raise HTTPException(status_code=400, detail="Invalid upstream path")
    target_url = f"{GO_CORE_BASE_URL}/api/v1/{clean}"
    body = await request.body()
    headers = {}
    if request.headers.get("content-type"):
        headers["Content-Type"] = request.headers["content-type"]

    try:
        async with httpx.AsyncClient(timeout=8.0, trust_env=False) as client:
            resp = await client.request(
                method=request.method,
                url=target_url,
                params=dict(request.query_params),
                content=body if body else None,
                headers=headers,
            )
            try:
                data = resp.json()
            except Exception:
                data = {"raw": resp.text}
            return JSONResponse(status_code=resp.status_code, content={"online": True, "data": data})
    except Exception as exc:
        return JSONResponse(
            status_code=503,
            content={
                "online": False,
                "status": "offline",
                "upstream_url": target_url,
                "error": str(exc),
            },
        )
