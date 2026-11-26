"""Operational runs, budgets, engines, pipelines, missions, omni, reports, and outputs."""

from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from django.http import HttpRequest, HttpResponse, JsonResponse
from django.views.decorators.http import require_GET, require_http_methods
from pydantic import BaseModel, Field
from rest_framework.response import Response
from rest_framework.views import APIView

from agents.base_agent import AgentTask
from core.cost_budget import GLOBAL_COST_CONTROLLER, Budget
from core.global_state import GLOBAL_COORDINATOR, GLOBAL_EVIDENCE_STORE
from core.platform_store import new_id
from core.run_control import GLOBAL_RUN_CONTROLLER
from core.scope_guard import ScopeGuard
from engines.registry import DRIVERS
from engines.selfcheck import run_selfcheck
from engines.worker import EngineWorker, EngineWorkerConfig
from hunter_backend.apps.common import (
    django_err,
    django_json,
    drf_validation_response,
    err_json,
    ok_json,
    parse_json_body,
    parse_query_bool,
    parse_query_float,
    parse_query_int,
    safe_resolve_path,
    validate_http_url_ssrf_and_scope,
    validate_model,
    validate_scan_target,
)
from hunter_backend.runtime import (
    BASE_DIR,
    DATA_DIR,
    REPORTS_DIR,
    RUNS_DIR,
    SNAPSHOTS_DIR,
    _ACTIVE_MASTER_MISSIONS,
    _OMNI_RUNS,
    _active_mission_tasks,
    _active_pipelines,
    ensure_platform_wiring,
    log_activity_event,
    register_managed_run,
    start_platform_run,
)

logger = logging.getLogger("hunter_backend.apps.operations_api")

TOOL_OUTPUTS_DIR = DATA_DIR / "tool_outputs"
_SAFE_ID_RE = re.compile(r"^[a-zA-Z0-9._-]{1,128}$")


class BudgetUpdate(BaseModel):
    per_run_usd: Optional[float] = Field(default=None, ge=0)
    per_solver_usd: Optional[float] = Field(default=None, ge=0)
    per_day_usd: Optional[float] = Field(default=None, ge=0)


class SelfCheckRequest(BaseModel):
    engines: Optional[list] = None
    profiles: Optional[list] = None


class EngineRunRequest(BaseModel):
    engine: str = "claude"
    target: str = ""
    prompt: str
    model: str = ""
    permission_mode: str = ""
    sandbox_mode: str = ""
    web_access: bool = True
    timeout_s: float = Field(default=1800.0, le=7200.0)
    resume_session: str = ""
    credential_env: Dict[str, str] = Field(default_factory=dict)
    in_scope: list = Field(default_factory=list)
    out_of_scope: list = Field(default_factory=list)


class MasterLaunchRequest(BaseModel):
    target: str
    platform: str = "hackerone"
    proxy: Optional[str] = None
    burp_file: Optional[str] = None
    resume: Optional[str] = None
    coverage: float = Field(default=0.85, ge=0.0, le=1.0)
    max_cycles: int = Field(default=10, ge=1, le=50)
    force_fallback: bool = False
    self_operate: bool = True
    output_dir: str = "data/reports"
    scope: Optional[List[str]] = None
    out_of_scope: Optional[List[str]] = None


class BurpInspectRequest(BaseModel):
    source: str = "live"
    content_text: Optional[str] = None
    target: Optional[str] = None
    port: int = 8085
    min_risk: float = 6.0


class BrowserExploreRequest(BaseModel):
    target_url: str
    proxy: Optional[str] = None
    headless: bool = True
    max_pages: int = Field(default=5, ge=1, le=25)


class CommandSynthesizeRequest(BaseModel):
    tool_name: str
    target: str
    waf_name: Optional[str] = None
    ports: List[int] = Field(default_factory=lambda: [80, 443])
    tech_stack: List[str] = Field(default_factory=lambda: ["generic"])
    proxy: Optional[str] = None
    is_root: Optional[bool] = None


class EliteSkillRequest(BaseModel):
    skill_name: str
    target_url: str
    param_name: str = ""


def _serialize_event(ev: Any) -> Dict[str, Any]:
    if isinstance(ev, dict):
        return {
            "event_id": ev.get("event_id"),
            "run_id": ev.get("run_id"),
            "event_type": ev.get("event_type"),
            "timestamp": ev.get("timestamp"),
            "payload": dict(ev.get("payload") or {}),
        }
    return {
        "event_id": ev.event_id,
        "run_id": ev.run_id,
        "event_type": ev.event_type,
        "timestamp": ev.timestamp,
        "payload": dict(ev.payload or {}),
    }


def _serialize_evidence(rec: Any) -> Dict[str, Any]:
    return {
        "evidence_id": rec.evidence_id,
        "run_id": rec.run_id,
        "source_worker": rec.source_worker,
        "source_tool": rec.source_tool,
        "evidence_type": rec.evidence_type,
        "sanitized_content": rec.sanitized_content,
        "content_hash": rec.content_hash,
        "provenance": rec.provenance,
        "confidence": rec.confidence,
        "verification_status": rec.verification_status,
        "created_at": rec.created_at,
        "metadata": dict(rec.metadata or {}),
    }


# ---------------------------------------------------------------------------
# /api/runs/* & /api/budget
# ---------------------------------------------------------------------------


class RunsListView(APIView):
    """GET /api/runs."""

    def get(self, request: Any) -> Any:
        runs = GLOBAL_RUN_CONTROLLER.list_runs(
            kind=request.GET.get("kind") or None,
            active_only=parse_query_bool(request.GET.get("active_only"), False),
            limit=parse_query_int(request.GET.get("limit"), 100),
        )
        return ok_json({"runs": runs})


class RunControlActionView(APIView):
    """POST /api/runs/<run_id>/{pause|resume|stop}."""

    action: str = "pause"

    def post(self, request: Any, run_id: str) -> Any:
        from hunter_backend.runtime import control_managed_run_sync

        store = rt.ensure_platform_wiring()
        if self.action == "pause":
            if not control_managed_run_sync(run_id, "pause"):
                return err_json("Run not found or cannot be paused", status=404)
            store.update_run(run_id, status="paused")
            return ok_json({"run_id": run_id, "state": "paused"})

        if self.action == "resume":
            if not control_managed_run_sync(run_id, "resume"):
                return err_json("Run not found or not paused", status=404)
            store.update_run(run_id, status="running")
            return ok_json({"run_id": run_id, "state": "running"})

        if not control_managed_run_sync(run_id, "stop"):
            return err_json("Run not found or already completed", status=404)
        store.update_run(run_id, status="stopped", finished_at=time.time())
        return ok_json({"run_id": run_id, "state": "stopped"})


class RunEventsView(APIView):
    """GET /api/runs/<run_id>/events."""

    def get(self, request: Any, run_id: str) -> Any:
        events = GLOBAL_COORDINATOR.events(run_id)
        if not events:
            return err_json("Run not found or has no recorded events", status=404)
        return ok_json(
            {
                "run_id": run_id,
                "count": len(events),
                "events": [_serialize_event(e) for e in events],
            }
        )


class RunEvidenceView(APIView):
    """GET /api/runs/<run_id>/evidence."""

    def get(self, request: Any, run_id: str) -> Any:
        raw_conf = request.GET.get("min_confidence")
        min_conf = parse_query_float(raw_conf, 0.0) if raw_conf not in (None, "") else None
        evidence = GLOBAL_EVIDENCE_STORE.list_evidence(
            run_id=run_id, min_confidence=min_conf
        )
        return ok_json(
            {
                "run_id": run_id,
                "count": len(evidence),
                "evidence": [_serialize_evidence(e) for e in evidence],
            }
        )


class RunFindingsView(APIView):
    """GET /api/runs/<run_id>/findings."""

    def get(self, request: Any, run_id: str) -> Any:
        evidence = GLOBAL_EVIDENCE_STORE.list_evidence(run_id=run_id)
        findings: List[Dict[str, Any]] = []
        rejected: List[Dict[str, Any]] = []
        for rec in evidence:
            item = {
                "evidence_id": rec.evidence_id,
                "title": f"{rec.evidence_type} on {rec.source_tool or 'unknown'}",
                "affected_asset": rec.metadata.get("target", ""),
                "category": rec.evidence_type,
                "confidence": rec.confidence,
                "verification_status": rec.verification_status,
                "evidence": rec.sanitized_content[:500],
                "provenance": rec.provenance,
            }
            if rec.verification_status == "contradicted":
                rejected.append(item)
            elif rec.evidence_type == "proof":
                findings.append(item)
            elif rec.evidence_type == "anomaly" and rec.confidence >= 0.7:
                findings.append({**item, "needs_verification": True})

        return ok_json(
            {
                "run_id": run_id,
                "findings_count": len(findings),
                "findings": findings,
                "rejected_count": len(rejected),
                "rejected": rejected,
            }
        )


class BudgetView(APIView):
    """GET / POST /api/budget."""

    def get(self, request: Any) -> Any:
        return ok_json(GLOBAL_COST_CONTROLLER.snapshot())

    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        req, verr = validate_model(BudgetUpdate, data, error_status=422)
        if verr is not None:
            return drf_validation_response(verr)
        assert req is not None
        GLOBAL_COST_CONTROLLER.budget = Budget(
            per_run_usd=req.per_run_usd,
            per_solver_usd=req.per_solver_usd,
            per_day_usd=req.per_day_usd,
        )
        return ok_json(GLOBAL_COST_CONTROLLER.snapshot())


# ---------------------------------------------------------------------------
# /api/engines*
# ---------------------------------------------------------------------------


class EnginesListView(APIView):
    """GET /api/engines."""

    def get(self, request: Any) -> Any:
        items = []
        for name, drv in DRIVERS.items():
            items.append(
                {
                    "engine": name,
                    "display_name": drv.display_name or name,
                    "capabilities": drv.capabilities,
                    "secure_prompt_transport": drv.secure_prompt_transport,
                    "supports_resume": drv.supports_resume,
                    "supports_streaming": drv.supports_streaming,
                }
            )
        return ok_json({"engines": items})


@require_http_methods(["POST"])
async def engines_selfcheck_view(request: HttpRequest) -> JsonResponse:
    """POST /api/engines/selfcheck."""
    data, err = parse_json_body(request)
    if err is not None:
        return err
    req, verr = validate_model(SelfCheckRequest, data, error_status=422)
    if verr is not None:
        return verr
    assert req is not None
    if req.engines is not None and len(req.engines) == 0 and not req.profiles:
        from engines.selfcheck import SelfCheckReport

        return django_json(SelfCheckReport().to_dict())
    report = await run_selfcheck(engine_names=req.engines, profiles=req.profiles)
    return django_json(report.to_dict())


@require_http_methods(["POST"])
async def engines_run_view(request: HttpRequest) -> JsonResponse:
    """POST /api/engines/run (422 when required fields like prompt are missing)."""
    data, err = parse_json_body(request)
    if err is not None:
        return err
    req, verr = validate_model(EngineRunRequest, data, error_status=422)
    if verr is not None:
        return verr
    assert req is not None

    if not req.prompt.strip():
        return django_err("prompt is required", status=400)
    if req.engine not in DRIVERS:
        return django_err(
            f"Unknown engine: {req.engine}. Available = {sorted(DRIVERS)}",
            status=404,
        )

    cfg = EngineWorkerConfig(
        engine=req.engine,
        model=req.model,
        permission_mode=req.permission_mode,
        sandbox_mode=req.sandbox_mode,
        web_access=req.web_access,
        timeout_s=req.timeout_s,
        credential_env=req.credential_env,
    )

    guard: Optional[ScopeGuard] = None
    if req.target:
        from core.security_mode import web_governance_enforced

        if not (req.in_scope or req.out_of_scope) and web_governance_enforced():
            return django_err(
                "Explicit in_scope/out_of_scope is required when running against a target (fail-closed).",
                status=400,
            )
        ok, reason, policy = validate_scan_target(
            req.target,
            scope=req.in_scope or None,
            out_of_scope=req.out_of_scope or None,
            action_type="engines_run",
        )
        if not ok:
            return django_err(reason, status=403, extra={"policy": policy, "status": "BLOCKED_SCOPE"})
        if req.in_scope or req.out_of_scope:
            try:
                guard = ScopeGuard(
                    in_scope=req.in_scope or [req.target],
                    out_of_scope=req.out_of_scope,
                )
            except Exception as exc:
                return django_err(f"Invalid scope: {exc}", status=400)
    elif req.in_scope or req.out_of_scope:
        try:
            guard = ScopeGuard(
                in_scope=req.in_scope,
                out_of_scope=req.out_of_scope,
            )
        except Exception as exc:
            return django_err(f"Invalid scope: {exc}", status=400)

    worker = EngineWorker(cfg, scope_guard=guard)
    task = AgentTask(target=req.target, mode="engine", extra={"prompt": req.prompt})
    if req.resume_session:
        worker._sessions[req.target] = req.resume_session

    try:
        result = await worker.run(task)
    except Exception as exc:
        logger.exception("engine run failed")
        return django_err(str(exc), status=500)

    return django_json(
        {
            "success": result.success,
            "agent": result.agent_name,
            "target": result.target,
            "output": result.raw_output.get("text", ""),
            "session_id": result.raw_output.get("session_id", ""),
            "evidence_file": result.raw_output.get("evidence_file", ""),
            "duration_s": result.raw_output.get("duration_s", ""),
            "errors": result.errors,
            "findings": result.findings,
        }
    )


# ---------------------------------------------------------------------------
# Pipelines, Hunter, Missions, Omni, Enhanced Control
# ---------------------------------------------------------------------------


@require_http_methods(["POST"])
async def pipeline_start_view(request: HttpRequest) -> JsonResponse:
    """POST /api/pipeline/start."""
    data, err = parse_json_body(request)
    if err is not None:
        return err
    target = str(data.get("target") or "").strip()
    mode = str(data.get("mode") or "full").strip()
    ok, reason, policy = validate_scan_target(
        target,
        scope=data.get("scope") or data.get("in_scope"),
        out_of_scope=data.get("out_of_scope"),
        engagement_id=data.get("engagement_id"),
        action_type="pipeline_start",
    )
    if not ok:
        return django_err(reason, status=403, extra={"policy": policy, "status": "BLOCKED_SCOPE"})

    run = await start_platform_run(
        kind="pipeline",
        target=target,
        engagement_id=data.get("engagement_id"),
        scope=data.get("scope") or data.get("in_scope"),
        out_of_scope=data.get("out_of_scope"),
        mode=mode,
    )
    return django_json({"status": "started", "run_id": run["run_id"], "run": run})


class PipelineGraphView(APIView):
    """GET /api/pipeline/graph."""

    def get(self, request: Any) -> Any:
        try:
            from core.reasoning.attack_surface_graph import AttackSurfaceGraph

            graph = AttackSurfaceGraph()
            return ok_json({"graph": graph.to_dict(), "active_pipelines": _active_pipelines})
        except Exception as exc:
            return ok_json({"graph": {}, "active_pipelines": _active_pipelines, "error": str(exc)})


@require_http_methods(["POST"])
async def vram_pipeline_execute_view(request: HttpRequest) -> JsonResponse:
    """POST /api/pipeline/vram/execute."""
    data, err = parse_json_body(request)
    if err is not None:
        return err
    target = str(data.get("target_url") or data.get("target") or "").strip()
    if not target:
        return django_err("target_url is required", status=400)
    ok, reason, policy = validate_scan_target(
        target,
        scope=data.get("scope") or data.get("in_scope"),
        out_of_scope=data.get("out_of_scope"),
        engagement_id=data.get("engagement_id"),
        action_type="vram_pipeline",
    )
    if not ok:
        return django_err(reason, status=403, extra={"policy": policy})
    try:
        from core.pipeline.vram_sequential_pipeline import vram_pipeline

        res = await vram_pipeline.execute_pipeline(target)
        res_dict = dataclasses.asdict(res) if dataclasses.is_dataclass(res) else (res if isinstance(res, dict) else {"raw": str(res)})
        findings_raw = res_dict.get("findings") or []
        norm_findings: List[Dict[str, Any]] = []
        for f in findings_raw:
            fd = dataclasses.asdict(f) if dataclasses.is_dataclass(f) else (dict(f) if isinstance(f, dict) else {"raw": str(f)})
            if "cwe_id" in fd and "cwe" not in fd:
                fd["cwe"] = fd["cwe_id"]
            norm_findings.append(fd)
        return django_json(
            {
                "ok": True,
                "status": "completed",
                "target": res_dict.get("target", target),
                "findings_count": int(res_dict.get("findings_count", len(norm_findings))),
                "findings": norm_findings,
                "result": res_dict,
            }
        )
    except Exception as exc:
        return django_json({"ok": False, "error": str(exc)}, status=500)


class VramPipelineStatusView(APIView):
    """GET /api/pipeline/vram/status."""

    def get(self, request: Any) -> Any:
        try:
            from core.pipeline.vram_sequential_pipeline import vram_pipeline

            active = getattr(getattr(vram_pipeline, "vram_mgr", None), "active_model", None)
        except Exception:
            active = None
        stages = [
            {"id": 1, "name": "Recon"},
            {"id": 2, "name": "Decompile"},
            {"id": 3, "name": "Hypothesize"},
            {"id": 4, "name": "Execute"},
            {"id": 5, "name": "Triage"},
        ]
        return ok_json({"active_model_in_vram": active, "pipeline_stages": stages, "status": "ready"})


@require_http_methods(["POST"])
async def hunter_start_view(request: HttpRequest) -> JsonResponse:
    """POST /api/hunter/start — wired through register_managed_run + ScopeGuard."""
    data, err = parse_json_body(request)
    if err is not None:
        return err
    target = str(data.get("target") or "").strip()
    scope = data.get("scope") or data.get("in_scope")
    out_of_scope = data.get("out_of_scope")
    engagement_id = data.get("engagement_id")
    mode = str(data.get("mode") or "autonomous").strip()

    ok, reason, policy = validate_scan_target(
        target,
        scope=scope,
        out_of_scope=out_of_scope,
        engagement_id=engagement_id,
        action_type="hunter_start",
    )
    if not ok:
        return django_err(reason, status=403, extra={"policy": policy, "status": "BLOCKED_SCOPE"})

    run_id = new_id("hunter")
    reg = register_managed_run(
        kind="hunter",
        target=target,
        run_id=run_id,
        engagement_id=engagement_id,
        in_scope=scope if isinstance(scope, list) else ([scope] if scope else [target]),
        out_of_scope=out_of_scope if isinstance(out_of_scope, list) else [],
        status="running",
        current_phase="HUNTER_INIT",
        meta={"mode": mode},
    )
    store = ensure_platform_wiring()

    async def _run_hunter() -> None:
        try:
            from core.autonomous_hunter import AutonomousHunter

            hunter = AutonomousHunter(target=target, mode=mode)
            run_fn = getattr(hunter, "run", None) or getattr(hunter, "execute", None)
            if callable(run_fn):
                res = run_fn()
                if asyncio.iscoroutine(res):
                    await res
            store.update_run(run_id, status="completed", current_phase="DONE", progress=1.0, finished_at=time.time())
        except asyncio.CancelledError:
            store.update_run(run_id, status="stopped", finished_at=time.time())
            raise
        except Exception as exc:
            logger.exception("AutonomousHunter %s failed", run_id)
            store.update_run(run_id, status="failed", error=str(exc), finished_at=time.time())

    task = asyncio.create_task(_run_hunter())
    reg["handle"].task = task
    _active_mission_tasks[run_id] = task
    task.add_done_callback(lambda _t: _active_mission_tasks.pop(run_id, None))
    log_activity_event("hunter", "hunter.started", target)
    return django_json({"status": "started", "run_id": run_id, "target": target, "run": reg["run"]})


class HunterContractsView(APIView):
    """GET /api/hunter/contracts."""

    def get(self, request: Any) -> Any:
        try:
            from hunter_ai.agents.recon_contract_agent import ReconContractAgent
            from hunter_ai.agents.report_contract_agent import ReportContractAgent
            from hunter_ai.agents.web_contract_agent import WebContractAgent
            from hunter_ai.brain.agent_manager import HunterAgentManager

            mgr = HunterAgentManager()
            for agent in (ReconContractAgent(), WebContractAgent(), ReportContractAgent()):
                mgr.register_agent(agent)
            contracts = [c.to_dict() if hasattr(c, "to_dict") else {"name": getattr(c, "name", str(c))} for c in mgr.list_contracts()]
            return ok_json({"registered_agents_count": len(contracts), "contracts": contracts})
        except Exception as exc:
            return ok_json({"registered_agents_count": 0, "contracts": [], "error": str(exc)})


@require_http_methods(["POST"])
async def hunter_mission_execute_view(request: HttpRequest) -> JsonResponse:
    """POST /api/hunter/mission/execute."""
    data, err = parse_json_body(request)
    if err is not None:
        return err
    target = str(data.get("target_url") or data.get("target") or "").strip()
    if not target:
        return django_err("target is required", status=400)
    ok, reason, policy = validate_scan_target(
        target,
        scope=data.get("scope") or data.get("in_scope"),
        out_of_scope=data.get("out_of_scope"),
        engagement_id=data.get("engagement_id"),
        action_type="hunter_mission",
    )
    if not ok:
        return django_err(reason, status=403, extra={"policy": policy})
    try:
        from hunter_ai.agents.recon_contract_agent import ReconContractAgent
        from hunter_ai.agents.report_contract_agent import ReportContractAgent
        from hunter_ai.agents.web_contract_agent import WebContractAgent
        from hunter_ai.brain.agent_manager import HunterAgentManager

        mgr = HunterAgentManager()
        for agent in (ReconContractAgent(), WebContractAgent(), ReportContractAgent()):
            mgr.register_agent(agent)
        mission_res = await mgr.execute_mission(target)
        job_id = str(data.get("job_id") or mission_res.get("job_id") or new_id("job"))
        _active_pipelines[job_id] = mission_res
        return django_json({"ok": True, "status": "completed", "job_id": job_id, "mission": mission_res, **mission_res})
    except Exception as exc:
        return django_json({"ok": False, "error": str(exc)}, status=500)


class HunterBlackboardView(APIView):
    """GET /api/hunter/blackboard/<job_id>."""

    def get(self, request: Any, job_id: str) -> Any:
        store = ensure_platform_wiring()
        events = store.list_events(run_id=job_id, limit=100)
        state = _active_pipelines.get(job_id, {})
        l2_count = int(state.get("findings_count", 0) or 0)
        try:
            from hunter_ai.protocol.blackboard import ThreeTierBlackboardMemory

            bb = ThreeTierBlackboardMemory(job_id=job_id)
            evids = getattr(bb, "list_evidence", lambda: [])()
            l2_count = max(l2_count, len(evids))
        except Exception:
            pass
        return ok_json(
            {
                "job_id": job_id,
                "level2_evidence_count": l2_count,
                "events": events,
                "state": state,
            }
        )


class HunterAgentMemoryView(APIView):
    """GET /api/hunter/memory/agent/<agent_name>."""

    def get(self, request: Any, agent_name: str) -> Any:
        try:
            from hunter_ai.brain.memory_hierarchy import MemoryHierarchy

            mh = MemoryHierarchy()
            mem = getattr(mh, "get_agent_lessons", lambda n: {})(agent_name)
            return ok_json({"agent_name": agent_name, "agent": agent_name, "memory": mem})
        except Exception:
            return ok_json({"agent_name": agent_name, "agent": agent_name, "memory": {}})


@require_http_methods(["POST"])
async def mission_start_view(request: HttpRequest) -> JsonResponse:
    """POST /api/mission/start."""
    data, err = parse_json_body(request)
    if err is not None:
        return err
    target = str(data.get("target") or "").strip()
    ok, reason, policy = validate_scan_target(
        target,
        scope=data.get("scope") or data.get("in_scope"),
        out_of_scope=data.get("out_of_scope"),
        engagement_id=data.get("engagement_id"),
        action_type="mission_start",
    )
    if not ok:
        return django_err(reason, status=403, extra={"policy": policy, "status": "BLOCKED_SCOPE"})

    session_id = str(data.get("session_id") or new_id("mission"))
    run = await start_platform_run(
        kind="mission",
        target=target,
        engagement_id=data.get("engagement_id"),
        scope=data.get("scope") or data.get("in_scope"),
        out_of_scope=data.get("out_of_scope"),
        mode=str(data.get("mode") or "autonomous"),
    )
    _ACTIVE_MASTER_MISSIONS[session_id] = {
        "session_id": session_id,
        "run_id": run["run_id"],
        "target": target,
        "status": "running",
        "started_at": time.time(),
    }
    return django_json({"ok": True, "session_id": session_id, "run_id": run["run_id"], "run": run})


class MissionSkillsView(APIView):
    """GET /api/mission/skills."""

    def get(self, request: Any) -> Any:
        try:
            from core.skill_registry import SkillRegistry

            reg = SkillRegistry()
            skills = getattr(reg, "list_skills", lambda: [])()
            return ok_json({"skills": skills})
        except Exception as exc:
            return ok_json({"skills": [], "error": str(exc)})


class MissionStatusView(APIView):
    """GET /api/mission/<session_id>/status."""

    def get(self, request: Any, session_id: str) -> Any:
        info = _ACTIVE_MASTER_MISSIONS.get(session_id)
        store = ensure_platform_wiring()
        run = store.get_run(session_id) or (store.get_run(info["run_id"]) if info and info.get("run_id") else None)
        if not info and not run:
            return err_json(f"Mission {session_id} not found", status=404)
        return ok_json({"session_id": session_id, "mission": info, "run": run})


class MissionReportView(APIView):
    """GET /api/mission/<session_id>/report."""

    def get(self, request: Any, session_id: str) -> Any:
        target = (request.GET.get("target") or "").strip()
        info = _ACTIVE_MASTER_MISSIONS.get(session_id) or {}
        resolved_target = target or info.get("target", "")
        store = ensure_platform_wiring()
        events = store.list_events(run_id=info.get("run_id") or session_id, limit=200)
        return ok_json(
            {
                "session_id": session_id,
                "target": resolved_target,
                "mission": info,
                "events": events,
            }
        )


@require_http_methods(["POST"])
async def omni_launch_view(request: HttpRequest) -> JsonResponse:
    """POST /api/omni/launch."""
    data, err = parse_json_body(request)
    if err is not None:
        return err
    target = str(data.get("target") or "").strip()
    ok, reason, policy = validate_scan_target(
        target,
        scope=data.get("scope") or data.get("in_scope"),
        out_of_scope=data.get("out_of_scope"),
        engagement_id=data.get("engagement_id"),
        action_type="omni_launch",
    )
    if not ok:
        return django_err(reason, status=403, extra={"policy": policy, "status": "BLOCKED_SCOPE"})

    run = await start_platform_run(
        kind="omni",
        target=target,
        engagement_id=data.get("engagement_id"),
        scope=data.get("scope") or data.get("in_scope"),
        out_of_scope=data.get("out_of_scope"),
        mode=str(data.get("mode") or "full"),
    )
    eid = run["engagement_id"] or new_id("eng")
    _OMNI_RUNS[eid] = {
        "engagement_id": eid,
        "run_id": run["run_id"],
        "target": target,
        "status": "LAUNCHED",
        "current_phase": "RECON",
        "findings": [],
    }
    return django_json({"ok": True, "status": "LAUNCHED", "engagement_id": eid, "run_id": run["run_id"], "run": run})


class OmniStatusView(APIView):
    """GET /api/omni/status/<engagement_id>."""

    def get(self, request: Any, engagement_id: str) -> Any:
        item = _OMNI_RUNS.get(engagement_id)
        store = ensure_platform_wiring()
        eng = store.get_engagement(engagement_id)
        if not item and not eng:
            return err_json(f"Omni run {engagement_id} not found", status=404)
        return ok_json(
            {
                "engagement_id": engagement_id,
                "current_phase": (item or {}).get("current_phase", "INIT"),
                "omni": item,
                "engagement": eng,
            }
        )


class OmniFindingsView(APIView):
    """GET /api/omni/findings/<engagement_id>."""

    def get(self, request: Any, engagement_id: str) -> Any:
        item = _OMNI_RUNS.get(engagement_id) or {}
        findings = list(item.get("findings") or [])
        return ok_json({"engagement_id": engagement_id, "findings": findings, "count": len(findings)})


# ---------------------------------------------------------------------------
# /api/enhanced/*
# ---------------------------------------------------------------------------


@require_http_methods(["POST"])
async def enhanced_omni_launch_all_view(request: HttpRequest) -> JsonResponse:
    """POST /api/enhanced/omni/launch-all."""
    data, err = parse_json_body(request)
    if err is not None:
        return err
    req, verr = validate_model(MasterLaunchRequest, data, error_status=422)
    if verr is not None:
        return verr
    assert req is not None

    ok, reason, policy = validate_scan_target(
        req.target,
        scope=req.scope,
        out_of_scope=req.out_of_scope,
        action_type="enhanced_omni_launch",
    )
    if not ok:
        return django_err(reason, status=403, extra={"policy": policy, "status": "BLOCKED_SCOPE"})

    mission_id = new_id("master")
    run = await start_platform_run(
        kind="omni",
        target=req.target,
        scope=req.scope,
        out_of_scope=req.out_of_scope,
        coverage=req.coverage,
        max_cycles=req.max_cycles,
        force_fallback=req.force_fallback,
        self_operate=req.self_operate,
        proxy=req.proxy,
    )
    _ACTIVE_MASTER_MISSIONS[mission_id] = {
        "mission_id": mission_id,
        "run_id": run["run_id"],
        "target": req.target,
        "platform": req.platform,
        "status": "LAUNCHED",
        "current_phase": "RECON",
        "started_at": time.time(),
    }
    return django_json(
        {
            "ok": True,
            "mission_id": mission_id,
            "run_id": run["run_id"],
            "target": req.target,
            "status": "LAUNCHED",
        }
    )


class EnhancedOmniStatusView(APIView):
    """GET /api/enhanced/omni/status/<mission_id>."""

    def get(self, request: Any, mission_id: str) -> Any:
        item = _ACTIVE_MASTER_MISSIONS.get(mission_id)
        if not item:
            return err_json(f"Master mission {mission_id} not found", status=404)
        store = ensure_platform_wiring()
        run = store.get_run(item["run_id"]) if item.get("run_id") else None
        return ok_json({**item, "run": run})


@require_http_methods(["POST"])
async def enhanced_burp_inspect_view(request: HttpRequest) -> JsonResponse:
    """POST /api/enhanced/burp/inspect."""
    data, err = parse_json_body(request)
    if err is not None:
        return err
    req, verr = validate_model(BurpInspectRequest, data, error_status=422)
    if verr is not None:
        return verr
    assert req is not None
    if req.source not in {"live", "pasted"} and "://" not in req.source and not req.content_text:
        try:
            safe_resolve_path(req.source, [DATA_DIR, BASE_DIR])
        except (PermissionError, FileNotFoundError) as exc:
            return django_err(str(exc), status=403)
    text = req.content_text or ""
    findings: List[Dict[str, Any]] = []
    if text:
        for pat, title, sev in (
            (r"\bAKIA[0-9A-Z]{16}\b", "Exposed AWS Access Key ID", "High"),
            (r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", "JWT Bearer Token in HTTP Traffic", "Info"),
            (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", "Private Key Material Exposed", "Critical"),
            (r"(?:SQL syntax|PostgreSQL.*ERROR|mysql_fetch|ORA-\d{5})", "Database Error Disclosure", "Medium"),
        ):
            for m in re.finditer(pat, text):
                findings.append({"title": title, "severity": sev, "match": m.group(0)[:80], "target": req.target})
    return django_json(
        {
            "ok": True,
            "success": True,
            "source": req.source,
            "target": req.target,
            "min_risk": req.min_risk,
            "total_findings": len(findings),
            "findings": findings,
        }
    )


@require_http_methods(["POST"])
async def enhanced_browser_explore_view(request: HttpRequest) -> JsonResponse:
    """POST /api/enhanced/browser/explore."""
    data, err = parse_json_body(request)
    if err is not None:
        return err
    req, verr = validate_model(BrowserExploreRequest, data, error_status=422)
    if verr is not None:
        return verr
    assert req is not None

    ok, reason, policy = validate_http_url_ssrf_and_scope(
        req.target_url,
        scope=data.get("scope") or data.get("in_scope"),
        out_of_scope=data.get("out_of_scope"),
        engagement_id=data.get("engagement_id"),
        action_type="browser_explore",
    )
    if not ok:
        return django_err(reason, status=403, extra={"policy": policy})

    try:
        from core.browser.ai_browser_operator import run_ai_browser_session_sync

        res = await asyncio.to_thread(
            run_ai_browser_session_sync,
            req.target_url,
            proxy=req.proxy,
            headless=req.headless,
            max_steps=req.max_pages,
        )
        res_dict = dataclasses.asdict(res) if dataclasses.is_dataclass(res) else (res if isinstance(res, dict) else {"raw": str(res)})
        res_dict.setdefault("target", req.target_url)
        return django_json({"ok": True, "result": res_dict, **res_dict})
    except Exception as exc:
        return django_json({"ok": False, "error": str(exc)}, status=500)


class EnhancedArsenalSynthesizeView(APIView):
    """POST /api/enhanced/arsenal/synthesize."""

    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        req, verr = validate_model(CommandSynthesizeRequest, data, error_status=422)
        if verr is not None:
            return drf_validation_response(verr)
        assert req is not None
        try:
            from core.arsenal.ai_command_synthesizer import (
                AIToolCommandSynthesizer,
                TargetContext,
            )
            from core.arsenal.kali_catalog import get_tool_definition

            tool_def = get_tool_definition(req.tool_name)
            if not tool_def:
                return err_json(f"Tool '{req.tool_name}' not found in catalog", status=404)
            ctx = TargetContext(
                target=req.target,
                waf_name=req.waf_name,
                open_ports=list(req.ports or []),
                tech_stack=list(req.tech_stack or []),
                proxy=req.proxy,
            )
            synth = AIToolCommandSynthesizer()
            cmd_obj = synth.synthesize_sync(tool_def, ctx)
            cmd_dict = dataclasses.asdict(cmd_obj) if dataclasses.is_dataclass(cmd_obj) else {"synthesized_command": str(cmd_obj)}
            cmd_str = cmd_dict.get("synthesized_command") or cmd_dict.get("command") or str(cmd_obj)
            return ok_json({"ok": True, "tool": req.tool_name, "command": cmd_str, "synthesized_command": cmd_str, "waf_evasion_applied": bool(req.waf_name), **cmd_dict})
        except Exception as exc:
            return ok_json({"ok": False, "error": str(exc)})


class EnhancedSkillsCatalogView(APIView):
    """GET /api/enhanced/skills/catalog."""

    def get(self, request: Any) -> Any:
        category = request.GET.get("category") or None
        layer = request.GET.get("layer") or None
        try:
            from core.skills.skill_matrix_viewer import SkillMatrixViewer

            stats = SkillMatrixViewer.get_summary_stats()
            skills = SkillMatrixViewer.list_all_skills(category=category, layer=layer)
            return ok_json({"skills": skills, "total": len(skills), "stats": stats})
        except Exception as exc:
            return ok_json({"skills": [], "total": 0, "stats": {}, "error": str(exc)})


@require_http_methods(["POST"])
async def enhanced_skills_elite_run_view(request: HttpRequest) -> JsonResponse:
    """POST /api/enhanced/skills/elite-run."""
    data, err = parse_json_body(request)
    if err is not None:
        return err
    req, verr = validate_model(EliteSkillRequest, data, error_status=422)
    if verr is not None:
        return verr
    assert req is not None

    ok, reason, policy = validate_http_url_ssrf_and_scope(
        req.target_url,
        scope=data.get("scope") or data.get("in_scope"),
        out_of_scope=data.get("out_of_scope"),
        engagement_id=data.get("engagement_id"),
        action_type="elite_skill",
    )
    if not ok:
        return django_err(reason, status=403, extra={"policy": policy})
    return django_json(
        {
            "ok": True,
            "skill_name": req.skill_name,
            "target_url": req.target_url,
            "param_name": req.param_name,
            "verified": False,
            "status": "executed",
        }
    )


class EnhancedReportsListView(APIView):
    """GET /api/enhanced/reports."""

    def get(self, request: Any) -> Any:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        items: List[Dict[str, Any]] = []
        for p in sorted(REPORTS_DIR.glob("*.md"), key=lambda x: x.stat().st_mtime, reverse=True):
            st = p.stat()
            items.append(
                {
                    "filename": p.name,
                    "path": str(p),
                    "size_bytes": st.st_size,
                    "modified": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime)),
                    "is_master_dossier": "MASTER_DOSSIER" in p.name or "MASTER_MULTI_TARGET" in p.name,
                }
            )
        return ok_json({"reports": items, "count": len(items)})


class EnhancedReportDetailView(APIView):
    """GET /api/enhanced/reports/<filename> (strict path containment under REPORTS_DIR)."""

    def get(self, request: Any, filename: str) -> Any:
        if "/" in filename or "\\" in filename or ".." in filename or ":" in filename:
            return err_json("Invalid report filename", status=400)
        try:
            target = safe_resolve_path(filename, [REPORTS_DIR], must_exist=True)
        except PermissionError as exc:
            return err_json(str(exc), status=403)
        except FileNotFoundError:
            return err_json(f"Report {filename} not found", status=404)
        return ok_json(
            {"filename": target.name, "content": target.read_text(encoding="utf-8", errors="replace")}
        )


class EnhancedSnapshotsListView(APIView):
    """GET /api/enhanced/snapshots."""

    def get(self, request: Any) -> Any:
        SNAPSHOTS_DIR.mkdir(parents=True, exist_ok=True)
        items: List[Dict[str, Any]] = []
        for p in sorted(SNAPSHOTS_DIR.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
            try:
                snap = json.loads(p.read_text(encoding="utf-8"))
                items.append(
                    {
                        "filename": p.name,
                        "snapshot_id": snap.get("snapshot_id", p.stem),
                        "target": snap.get("target", "unknown"),
                        "phase": snap.get("phase", "UNKNOWN"),
                        "coverage_pct": snap.get("coverage_pct", 0.0),
                        "findings_count": len(snap.get("confirmed_findings", [])),
                        "modified": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(p.stat().st_mtime)),
                    }
                )
            except Exception:
                continue
        return ok_json({"snapshots": items, "count": len(items)})


# ---------------------------------------------------------------------------
# Scheduler, Sessions, Reports, Tool Outputs
# ---------------------------------------------------------------------------


@require_http_methods(["POST"])
async def scheduler_enqueue_view(request: HttpRequest) -> JsonResponse:
    """POST /api/scheduler/enqueue."""
    data, err = parse_json_body(request)
    if err is not None:
        return err
    target = str(data.get("target") or "").strip()
    ok, reason, policy = validate_scan_target(
        target,
        scope=data.get("scope") or data.get("in_scope"),
        out_of_scope=data.get("out_of_scope"),
        action_type="scheduler_enqueue",
    )
    if not ok:
        return django_err(reason, status=403, extra={"policy": policy})
    run = await start_platform_run(
        kind="pipeline",
        target=target,
        scope=data.get("scope") or data.get("in_scope"),
        out_of_scope=data.get("out_of_scope"),
        mode=str(data.get("mode") or "scheduled"),
    )
    return django_json({"ok": True, "queued": True, "run_id": run["run_id"]})


class SessionsListView(APIView):
    """GET /api/sessions."""

    def get(self, request: Any) -> Any:
        try:
            from core.session_manager import SessionManager

            sessions = SessionManager().list_all()
            return Response(sessions if isinstance(sessions, list) else [])
        except Exception:
            RUNS_DIR.mkdir(parents=True, exist_ok=True)
            items = [{"id": p.name, "target": p.name, "mode": "scan", "status": "saved"} for p in sorted(RUNS_DIR.iterdir(), reverse=True) if p.is_dir()]
            return Response(items)


class SessionDetailView(APIView):
    """GET /api/session/<sid>."""

    def get(self, request: Any, sid: str) -> Any:
        if not _SAFE_ID_RE.fullmatch(sid) or ".." in sid:
            return err_json("Invalid session ID", status=400)
        try:
            from core.session_manager import SessionManager

            s = SessionManager().load(sid)
            if s:
                return ok_json(
                    {
                        "id": s.id,
                        "session_id": s.id,
                        "target": s.target,
                        "mode": s.mode,
                        "status": s.status,
                        "created_at": s.created_at,
                        "findings_count": len(s.findings),
                    }
                )
        except Exception:
            pass
        run = ensure_platform_wiring().get_run(sid)
        if not run:
            return err_json(f"Session {sid} not found", status=404)
        return ok_json({"session_id": sid, "run": run})


_ALLOWED_REPORT_FORMATS = {"hackerone", "executive", "md", "markdown", "html", "json", "txt", "sarif", "pdf"}


class ReportExportView(APIView):
    """GET /api/report/<sid>/<fmt>."""

    def get(self, request: Any, sid: str, fmt: str) -> Any:
        fmt_clean = (fmt or "").strip().lower()
        if not _SAFE_ID_RE.fullmatch(sid) or ".." in sid or fmt_clean not in _ALLOWED_REPORT_FORMATS:
            return err_json("Invalid report session ID or format", status=400)
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)

        if fmt_clean == "hackerone":
            cand = safe_resolve_path(f"{sid}_hackerone.md", [REPORTS_DIR])
            if not cand.exists():
                try:
                    from core.bugbounty_reporter import BugBountyReporter
                    from core.session_manager import SessionManager

                    s = SessionManager().load(sid)
                    if s:
                        BugBountyReporter(output_dir=str(REPORTS_DIR)).generate_hackerone_report(
                            {
                                "id": s.id,
                                "target": s.target,
                                "findings": [
                                    {
                                        "title": f.title,
                                        "severity": f.severity,
                                        "cvss_score": f.cvss_score,
                                        "tool": f.tool,
                                        "evidence": f.evidence,
                                        "recommendation": getattr(f, "recommendation", ""),
                                    }
                                    for f in s.findings
                                ],
                            }
                        )
                except Exception:
                    pass
            if cand.is_file():
                return HttpResponse(cand.read_text(encoding="utf-8", errors="replace"), content_type="text/markdown")
        elif fmt_clean == "executive":
            cand = safe_resolve_path(f"{sid}_executive.html", [REPORTS_DIR])
            if cand.is_file():
                return HttpResponse(cand.read_text(encoding="utf-8", errors="replace"), content_type="text/html")

        store = ensure_platform_wiring()
        run = store.get_run(sid)
        session_obj = None
        if not run:
            try:
                from core.session_manager import SessionManager

                session_obj = SessionManager().load(sid)
            except Exception:
                session_obj = None
        if not run and not session_obj:
            return err_json(f"Session {sid} not found", status=404)
        if fmt_clean == "json":
            if session_obj:
                return ok_json(
                    {
                        "session_id": sid,
                        "target": session_obj.target,
                        "findings": [dataclasses.asdict(f) if dataclasses.is_dataclass(f) else dict(vars(f)) for f in session_obj.findings],
                    }
                )
            return ok_json({"session_id": sid, "run": run, "events": store.list_events(run_id=sid, limit=200)})
        if session_obj:
            lines = [f"# HunterAI Report ({sid})", f"Target: {session_obj.target}", ""]
            for f in session_obj.findings:
                lines.append(f"- [{f.severity}] {f.title}: {str(f.evidence)[:200]}")
            body = "\n".join(lines) + "\n"
        else:
            body = f"# HunterAI Report ({sid})\nTarget: {run.get('target', '')}\nStatus: {run.get('status', '')}\n"
        ctype = "text/html" if fmt_clean == "html" else ("text/markdown" if fmt_clean in {"md", "markdown"} else "text/plain")
        return HttpResponse(body, content_type=ctype)


class ToolOutputsListView(APIView):
    """GET /api/tool_outputs."""

    def get(self, request: Any) -> Any:
        TOOL_OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
        files = sorted([p.name for p in TOOL_OUTPUTS_DIR.iterdir() if p.is_file()], reverse=True)
        return ok_json({"files": files, "count": len(files)})


class ToolOutputDetailView(APIView):
    """GET /api/tool_outputs/<filename>."""

    def get(self, request: Any, filename: str) -> Any:
        if "/" in filename or "\\" in filename or ".." in filename or ":" in filename:
            return err_json("Invalid tool output filename", status=400)
        try:
            target = safe_resolve_path(filename, [TOOL_OUTPUTS_DIR], must_exist=True)
        except PermissionError as exc:
            return err_json(str(exc), status=403)
        except FileNotFoundError:
            return err_json(f"Output {filename} not found", status=404)
        return ok_json(
            {"filename": target.name, "content": target.read_text(encoding="utf-8", errors="replace")}
        )
