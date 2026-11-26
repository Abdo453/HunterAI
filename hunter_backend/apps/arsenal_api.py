"""Control Center, Arsenal, Scope, Burp Suite, MCP, Sandbox, CTF Flags, and Extensions APIs."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import httpx
from django.http import HttpRequest, JsonResponse
from django.views.decorators.http import require_http_methods
from pydantic import BaseModel, Field
from rest_framework.views import APIView

from core.copilot_service import (
    _StrictScopeGuardAdapter,
    detect_live_providers,
    evaluate_action_policy,
)
from core.platform_store import new_id
from core.policy.red_team import (
    AuthorizationGrant,
    Profile,
    ScopeTarget,
    load_grant,
    save_grant,
)
from core.run_control import GLOBAL_RUN_CONTROLLER
from core.sandbox import LocalSandbox
from core.scope_guard import ScopeGuard
from hunter_backend.apps.common import (
    call_ai,
    django_err,
    django_json,
    drf_validation_response,
    err_json,
    ok_json,
    parse_json_body,
    parse_query_int,
    run_command_no_shell,
    safe_resolve_path,
    validate_http_url_ssrf_and_scope,
    validate_model,
    validate_scan_target,
)
from hunter_backend.runtime import (
    BASE_DIR,
    CHECKLIST_STATE_FILE,
    CONTROL_SETTINGS_FILE,
    DATA_DIR,
    RADAR_STATE_FILE,
    TARGETS_FILE,
    _SCOPE_STATE,
    ensure_platform_wiring,
    get_activity_logs,
    get_burp_agent,
    get_burp_bridge,
    get_burp_sensor_bridge,
    get_extension_manager,
    get_flag_service,
    get_mcp_registry,
    get_scope_enforcer,
    log_activity_event,
    refresh_scope_enforcer,
)
from hunter_backend.secrets_util import get_or_create_policy_secret

logger = logging.getLogger("hunter_backend.apps.arsenal_api")

GRANT_PATH = DATA_DIR / "root_controller" / "grant.json"

_DEFAULT_CONTROL_SETTINGS: Dict[str, Any] = {
    "upstream_proxy": "",
    "burp_agent_port": 8085,
    "max_concurrent_agents": 5,
    "safe_boundaries_enforced": True,
    "llm_policy": "balanced",
    "default_model": os.getenv("HUNTER_DEFAULT_MODEL", "qwen2.5:14b"),
    "rate_limit_rps": 10.0,
}

_MCP_SERVERS: Dict[str, Dict[str, Any]] = {}


class AgentChatRequest(BaseModel):
    agent_id: str
    message: str
    target: Optional[str] = None
    provider: Optional[str] = "gemini"


class ToolTestRequest(BaseModel):
    tool_name: str
    target: Optional[str] = "127.0.0.1"


class ScopeValidateRequest(BaseModel):
    target_url: str
    in_scope: Optional[List[str]] = None
    out_of_scope: Optional[List[str]] = None


class TargetSaveRequest(BaseModel):
    name: str
    url: str
    description: str = ""
    in_scope: List[str] = Field(default_factory=list)
    out_of_scope: List[str] = Field(default_factory=list)


class ControlSettingsUpdate(BaseModel):
    upstream_proxy: Optional[str] = None
    burp_agent_port: Optional[int] = Field(default=None, ge=1, le=65535)
    max_concurrent_agents: Optional[int] = Field(default=None, ge=1, le=50)
    safe_boundaries_enforced: Optional[bool] = None
    llm_policy: Optional[str] = None
    default_model: Optional[str] = None
    rate_limit_rps: Optional[float] = Field(default=None, ge=0.1, le=100.0)


class RadarIngestRequest(BaseModel):
    round: Optional[Union[int, str]] = None
    win_pos: int
    cards: List[Any]
    hands: Optional[List[Any]] = None
    source: Optional[str] = "proxy_hook"
    simulated: bool = False


class ChecklistToggleReq(BaseModel):
    item_id: str
    checked: bool


class RedTeamGrantIssueReq(BaseModel):
    scope: str
    authorized_by: str
    days: int = Field(default=7, ge=1, le=365)


class LeadAddReq(BaseModel):
    target: str
    skill: str
    evidence: str
    signal: Optional[str] = "manual"
    priority: Optional[str] = "high"


class LeadTouchReq(BaseModel):
    target: str
    lead_id: str
    status: str
    note: Optional[str] = ""


class SevenGateReq(BaseModel):
    title: str
    asset: str
    poc: str
    impact: str
    reproducibility: Optional[str] = "100% reproducible"
    vulnerability_class: Optional[str] = "idor"
    in_scope: Optional[List[str]] = None


class TelemetryStepReq(BaseModel):
    step_type: Optional[str] = "FINDING_DISCOVERED"
    node_name: Optional[str] = "endpoint"
    agent: Optional[str] = "BugHunter"


class MCPServerConfig(BaseModel):
    server_id: str
    name: str
    transport: str = "stdio"
    command: Optional[str] = None
    args: List[str] = Field(default_factory=list)
    endpoint: Optional[str] = None
    enabled: bool = True


class MCPCallRequest(BaseModel):
    server_id: str
    tool_name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)


class SandboxRunRequest(BaseModel):
    command: List[str]
    timeout_s: float = 60.0
    max_output_bytes: int = 1000000


class ScopeConfig(BaseModel):
    in_scope: List[str] = Field(default_factory=list)
    out_of_scope: List[str] = Field(default_factory=list)


class FlagIngestRequest(BaseModel):
    text: str


class FlagSubmitRequest(BaseModel):
    platform_url: str
    token: str
    challenge_id: str = ""
    dry_run: bool = False


class ExtensionInstallRequest(BaseModel):
    path: str


class BurpTargetRequest(BaseModel):
    target: str
    limit: int = 50


class BurpJobRequest(BaseModel):
    target: str
    job_type: str = "passive_scan"


def _read_json_file(path: Path, default: Any) -> Any:
    if not path.is_file():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def _write_json_file(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


# ---------------------------------------------------------------------------
# /api/control/* (31 routes)
# ---------------------------------------------------------------------------


class ControlSystemStatusView(APIView):
    def get(self, request: Any) -> Any:
        store = ensure_platform_wiring()
        runs = GLOBAL_RUN_CONTROLLER.list_runs(limit=50)
        return ok_json(
            {
                "status": "online",
                "backend": "django-asgi",
                "active_runs": sum(1 for r in runs if r.get("state") in {"running", "paused"}),
                "total_runs": len(runs),
                "engagements": len(store.list_engagements(limit=100)),
                "timestamp": time.time(),
            }
        )


class ControlAgentsListView(APIView):
    def get(self, request: Any) -> Any:
        agents = [
            {"id": "recon-agent", "name": "Recon Agent", "status": "ready"},
            {"id": "validator", "name": "7-Question Validator", "status": "ready"},
            {"id": "chain-builder", "name": "Exploit Chain Builder", "status": "ready"},
            {"id": "report-writer", "name": "Report Writer", "status": "ready"},
            {"id": "burp-agent", "name": "Burp Traffic Analyst", "status": "ready"},
            {"id": "autopilot", "name": "Autonomous Autopilot", "status": "ready"},
        ]
        return ok_json({"agents": agents, "count": len(agents)})


@require_http_methods(["POST"])
async def control_agent_chat_view(request: HttpRequest) -> JsonResponse:
    data, err = parse_json_body(request)
    if err is not None:
        return err
    req, verr = validate_model(AgentChatRequest, data, error_status=422)
    if verr is not None:
        return verr
    assert req is not None
    prompt = f"[Agent={req.agent_id}] Target={req.target or 'none'}\n{req.message}"
    reply = await call_ai(prompt, provider=req.provider)
    log_activity_event("agent", f"chat:{req.agent_id}", req.target or "")
    return django_json({"agent_id": req.agent_id, "reply": reply, "target": req.target})


class ControlSkillsListView(APIView):
    def get(self, request: Any) -> Any:
        category = request.GET.get("category") or None
        try:
            from core.skill_registry import SkillRegistry

            reg = SkillRegistry()
            skills = getattr(reg, "list_skills", lambda: [])()
            if category:
                skills = [s for s in skills if str(s.get("category", "")).lower() == category.lower()]
            return ok_json({"skills": skills, "count": len(skills)})
        except Exception:
            return ok_json({"skills": [], "count": 0})


class ControlToolsListView(APIView):
    def get(self, request: Any) -> Any:
        try:
            from tools.tool_manager import ToolManager

            tm = ToolManager()
            tools = tm.get_available_tools()
        except Exception:
            tools = {}
        return ok_json({"tools": tools, "mcp_servers": list(_MCP_SERVERS.values())})


@require_http_methods(["POST"])
async def control_tools_test_view(request: HttpRequest) -> JsonResponse:
    data, err = parse_json_body(request)
    if err is not None:
        return err
    req, verr = validate_model(ToolTestRequest, data, error_status=422)
    if verr is not None:
        return verr
    assert req is not None
    tool_name = Path(req.tool_name.strip()).name
    if not tool_name or not tool_name.replace("-", "").replace("_", "").isalnum():
        return django_err("Invalid tool name", status=400)
    res = await run_command_no_shell([tool_name, "--version"], timeout_s=10.0)
    return django_json(
        {
            "ok": res.get("returncode") == 0,
            "tool_name": tool_name,
            "returncode": res.get("returncode"),
            "stdout": (res.get("stdout") or "")[:400],
            "stderr": (res.get("stderr") or "")[:400],
        }
    )


class ControlBrowserStatusView(APIView):
    def get(self, request: Any) -> Any:
        try:
            from core.browser.playwright_controller import PLAYWRIGHT_AVAILABLE

            available = bool(PLAYWRIGHT_AVAILABLE)
        except Exception:
            available = False
        return ok_json({"playwright_available": available, "status": "ready" if available else "unavailable"})


class ControlBurpMonitorView(APIView):
    def get(self, request: Any) -> Any:
        try:
            stats = get_burp_agent().get_stats()
        except Exception as exc:
            stats = {"online": False, "error": str(exc)}
        return ok_json({"burp": stats})


class ControlModelsListView(APIView):
    def get(self, request: Any) -> Any:
        try:
            providers = detect_live_providers()
        except Exception:
            providers = []
        return ok_json({"models": providers, "providers": providers})


class ControlTargetsListView(APIView):
    def get(self, request: Any) -> Any:
        items = _read_json_file(TARGETS_FILE, [])
        return ok_json({"targets": items if isinstance(items, list) else []})


class ControlTargetsValidateScopeView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        req, verr = validate_model(ScopeValidateRequest, data, error_status=422)
        if verr is not None:
            return drf_validation_response(verr)
        assert req is not None
        ok, reason, policy = validate_scan_target(
            req.target_url,
            scope=req.in_scope,
            out_of_scope=req.out_of_scope,
            action_type="validate_scope",
        )
        return ok_json({"target_url": req.target_url, "allowed": ok, "reason": reason, "policy": policy})


class ControlTargetsSaveView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        req, verr = validate_model(TargetSaveRequest, data, error_status=422)
        if verr is not None:
            return drf_validation_response(verr)
        assert req is not None
        targets = _read_json_file(TARGETS_FILE, [])
        if not isinstance(targets, list):
            targets = []
        entry = req.model_dump()
        entry["id"] = new_id("tgt")
        entry["saved_at"] = time.time()
        targets.append(entry)
        _write_json_file(TARGETS_FILE, targets)
        ensure_platform_wiring().upsert_engagement(
            name=req.name,
            target=req.url,
            in_scope=req.in_scope or [req.url],
            out_of_scope=req.out_of_scope,
        )
        log_activity_event("targets", "target.saved", req.url)
        return ok_json({"ok": True, "target": entry})


class ControlActivityView(APIView):
    def get(self, request: Any) -> Any:
        limit = parse_query_int(request.GET.get("limit"), 100)
        return ok_json({"activity": get_activity_logs(limit=limit)})


class ControlResultsView(APIView):
    def get(self, request: Any) -> Any:
        store = ensure_platform_wiring()
        runs = store.list_runs(limit=100)
        return ok_json({"runs": runs, "count": len(runs)})


class ControlDiagnosticsRunView(APIView):
    def get(self, request: Any) -> Any:
        try:
            from core.ai_diagnostics import run_full_ai_diagnostics

            diag = run_full_ai_diagnostics()
        except Exception as exc:
            diag = {"error": str(exc)}
        return ok_json({"ok": True, "diagnostics": diag, "timestamp": time.time()})


class ControlSettingsView(APIView):
    def get(self, request: Any) -> Any:
        saved = _read_json_file(CONTROL_SETTINGS_FILE, {})
        merged = {**_DEFAULT_CONTROL_SETTINGS, **(saved if isinstance(saved, dict) else {})}
        return ok_json(merged)

    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        req, verr = validate_model(ControlSettingsUpdate, data, error_status=422)
        if verr is not None:
            return drf_validation_response(verr)
        assert req is not None
        saved = _read_json_file(CONTROL_SETTINGS_FILE, {})
        merged = {**_DEFAULT_CONTROL_SETTINGS, **(saved if isinstance(saved, dict) else {})}
        for k, v in req.model_dump(exclude_none=True).items():
            merged[k] = v
        _write_json_file(CONTROL_SETTINGS_FILE, merged)
        return ok_json({"ok": True, "settings": merged})


class ControlRadarView(APIView):
    def get(self, request: Any) -> Any:
        state = _read_json_file(RADAR_STATE_FILE, None)
        return ok_json({"state": state, "active": state is not None})


class ControlRadarIngestView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        req, verr = validate_model(RadarIngestRequest, data, error_status=422)
        if verr is not None:
            return drf_validation_response(verr)
        assert req is not None
        state = {**req.model_dump(), "ingested_at": time.time()}
        _write_json_file(RADAR_STATE_FILE, state)
        return ok_json({"ok": True, "state": state})


class ControlRadarSimulateView(APIView):
    def post(self, request: Any) -> Any:
        state = {
            "round": int(time.time()) % 10000,
            "win_pos": 1,
            "cards": ["AS", "KH"],
            "hands": [["AS", "KH"], ["QD", "JC"]],
            "source": "simulator",
            "simulated": True,
            "ingested_at": time.time(),
        }
        _write_json_file(RADAR_STATE_FILE, state)
        return ok_json({"ok": True, "state": state})


class ControlChecklistsView(APIView):
    def get(self, request: Any) -> Any:
        try:
            from core.security_checklists import CHECKLIST_CATALOG

            catalog = CHECKLIST_CATALOG
        except Exception:
            catalog = {}
        state = _read_json_file(CHECKLIST_STATE_FILE, {})
        return ok_json({"catalog": catalog, "state": state})


class ControlChecklistsToggleView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        req, verr = validate_model(ChecklistToggleReq, data, error_status=422)
        if verr is not None:
            return drf_validation_response(verr)
        assert req is not None
        state = _read_json_file(CHECKLIST_STATE_FILE, {})
        if not isinstance(state, dict):
            state = {}
        state[req.item_id] = req.checked
        _write_json_file(CHECKLIST_STATE_FILE, state)
        return ok_json({"ok": True, "item_id": req.item_id, "checked": req.checked})


class ControlRedteamPolicyStatusView(APIView):
    """GET /api/control/redteam-policy — validates persisted/env policy secret (never hardcoded)."""

    def get(self, request: Any) -> Any:
        if not GRANT_PATH.is_file():
            return ok_json({"active": False, "grant": None})
        try:
            grant = load_grant(str(GRANT_PATH))
            secret = get_or_create_policy_secret().encode("utf-8")
            valid_sig = grant.verify(secret)
            active = bool(valid_sig and grant.active_at(time.time()))
            return ok_json(
                {
                    "active": active,
                    "valid_signature": valid_sig,
                    "grant": grant.to_dict(),
                }
            )
        except Exception as exc:
            return ok_json({"active": False, "error": str(exc)})


class ControlRedteamPolicyIssueView(APIView):
    """POST /api/control/redteam-policy/issue."""

    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        req, verr = validate_model(RedTeamGrantIssueReq, data, error_status=422)
        if verr is not None:
            return drf_validation_response(verr)
        assert req is not None

        targets = [t.strip() for t in req.scope.split(",") if t.strip()]
        if not targets:
            return err_json("scope must contain at least one target", status=400)

        scope_objs = [
            ScopeTarget(kind="cidr" if "/" in t else "domain", value=t)
            for t in targets
        ]
        now = time.time()
        secret = get_or_create_policy_secret().encode("utf-8")
        grant = AuthorizationGrant.sign(
            secret,
            grant_id=new_id("grant"),
            authorized_by=req.authorized_by,
            scope=scope_objs,
            not_before=now - 5.0,
            not_after=now + (req.days * 86400.0),
            profiles=[Profile.RED_TEAM, Profile.STANDARD, Profile.SAFE],
        )
        GRANT_PATH.parent.mkdir(parents=True, exist_ok=True)
        save_grant(grant, str(GRANT_PATH))
        log_activity_event("policy", "redteam_grant.issued", req.scope)
        return ok_json({"ok": True, "active": True, "grant": grant.to_dict()})


class ControlRedteamPolicyRevokeView(APIView):
    """POST /api/control/redteam-policy/revoke."""

    def post(self, request: Any) -> Any:
        revoked = False
        if GRANT_PATH.is_file():
            GRANT_PATH.unlink()
            revoked = True
        log_activity_event("policy", "redteam_grant.revoked", "")
        return ok_json({"ok": True, "revoked": revoked, "active": False})


class ControlLeadBoardView(APIView):
    def get(self, request: Any) -> Any:
        target = (request.GET.get("target") or "").strip()
        try:
            from bughunter.tools.lead_board import load_ledger

            leads = load_ledger(target) if target else []
            return ok_json({"target": target, "leads": leads})
        except Exception as exc:
            return ok_json({"target": target, "leads": [], "error": str(exc)})


class ControlLeadBoardAddView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        req, verr = validate_model(LeadAddReq, data, error_status=422)
        if verr is not None:
            return drf_validation_response(verr)
        assert req is not None
        from bughunter.tools.lead_board import add

        res = add(req.target, req.skill, req.evidence, req.signal or "manual", req.priority or "high")
        return ok_json({"ok": True, "lead": res})


class ControlLeadBoardTouchView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        req, verr = validate_model(LeadTouchReq, data, error_status=422)
        if verr is not None:
            return drf_validation_response(verr)
        assert req is not None
        from bughunter.tools.lead_board import touch

        res = touch(req.target, req.lead_id, req.status, req.note or "")
        return ok_json({"ok": True, "lead": res})


class ControlSevenGateEvaluateView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        req, verr = validate_model(SevenGateReq, data, error_status=422)
        if verr is not None:
            return drf_validation_response(verr)
        assert req is not None
        from core.seven_question_gate import SevenQuestionGate

        gate = SevenQuestionGate()
        result = gate.evaluate_finding(req.model_dump(), in_scope_list=req.in_scope)
        payload = result.__dict__ if hasattr(result, "__dict__") else result
        return ok_json({"ok": True, "evaluation": payload})


class ControlSwarmTelemetryView(APIView):
    def get(self, request: Any) -> Any:
        target = (request.GET.get("target") or "").strip()
        try:
            from core.reasoning.attack_surface_graph import AttackSurfaceGraph

            g = AttackSurfaceGraph()
            return ok_json({"target": target, "graph": g.to_dict(), "activity": get_activity_logs(30)})
        except Exception as exc:
            return ok_json({"target": target, "graph": {}, "error": str(exc)})


class ControlSwarmTelemetrySimulateStepView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        req, verr = validate_model(TelemetryStepReq, data, error_status=422)
        if verr is not None:
            return drf_validation_response(verr)
        assert req is not None
        ev = log_activity_event(
            "swarm",
            req.step_type or "FINDING_DISCOVERED",
            f"{req.agent}: {req.node_name}",
        )
        return ok_json({"ok": True, "event": ev})


# ---------------------------------------------------------------------------
# Phase G: MCP, Sandbox, Scope (canonical check vs enforce), Flags, Extensions
# ---------------------------------------------------------------------------


class MCPServersView(APIView):
    def get(self, request: Any) -> Any:
        try:
            tools = get_mcp_registry().get_tool_definitions()
        except Exception:
            tools = []
        return ok_json({"servers": list(_MCP_SERVERS.values()), "tools": tools})

    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        req, verr = validate_model(MCPServerConfig, data, error_status=422)
        if verr is not None:
            return drf_validation_response(verr)
        assert req is not None
        _MCP_SERVERS[req.server_id] = req.model_dump()
        return ok_json({"ok": True, "server": _MCP_SERVERS[req.server_id]})


@require_http_methods(["POST"])
async def mcp_call_view(request: HttpRequest) -> JsonResponse:
    data, err = parse_json_body(request)
    if err is not None:
        return err
    req, verr = validate_model(MCPCallRequest, data, error_status=422)
    if verr is not None:
        return verr
    assert req is not None
    try:
        bridge = get_mcp_registry()
        fn = getattr(bridge, "handle_tool_call_async", None)
        if callable(fn):
            res = await fn(req.tool_name, req.arguments)
            return django_json({"ok": True, "result": res})
        res = bridge.handle_tool_call(req.tool_name, req.arguments)
        return django_json({"ok": True, "result": res})
    except Exception as exc:
        return django_json({"ok": False, "error": str(exc)}, status=500)


class SandboxHealthView(APIView):
    def get(self, request: Any) -> Any:
        sb = LocalSandbox()
        return ok_json(sb.health_check())


class SandboxRunView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        req, verr = validate_model(SandboxRunRequest, data, error_status=422)
        if verr is not None:
            return drf_validation_response(verr)
        assert req is not None
        sb = LocalSandbox()
        res = sb.run(req.command, timeout_s=req.timeout_s, max_output_bytes=req.max_output_bytes)
        return ok_json(res.__dict__ if hasattr(res, "__dict__") else {"result": res})


class ScopeConfigView(APIView):
    def get(self, request: Any) -> Any:
        return ok_json(dict(_SCOPE_STATE))

    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        req, verr = validate_model(ScopeConfig, data, error_status=422)
        if verr is not None:
            return drf_validation_response(verr)
        assert req is not None
        _SCOPE_STATE["in_scope"] = list(req.in_scope)
        _SCOPE_STATE["out_of_scope"] = list(req.out_of_scope)
        refresh_scope_enforcer()
        return ok_json({"ok": True, **_SCOPE_STATE})


class ScopeCheckCanonicalView(APIView):
    """Canonical POST /api/scope/check validating target via ScopeGuard + strict invariants."""

    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        target = str(data.get("target") or "").strip()
        if not target:
            return err_json("target is required", status=400)

        in_scope = data.get("in_scope") if data.get("in_scope") is not None else data.get("scope")
        out_of_scope = data.get("out_of_scope")
        sg = ScopeGuard(
            in_scope=in_scope if isinstance(in_scope, list) else ([in_scope] if in_scope else _SCOPE_STATE["in_scope"]),
            out_of_scope=out_of_scope if isinstance(out_of_scope, list) else _SCOPE_STATE["out_of_scope"],
        )
        allowed_sg, reason_sg = sg.is_allowed(target)
        policy = evaluate_action_policy(
            action_type="scope_check",
            target=target,
            in_scope=sg.in_scope or None,
            out_of_scope=sg.out_of_scope or None,
        )
        allowed = bool(allowed_sg and policy.get("allowed", False))
        reason = policy.get("reason") or reason_sg or ""
        return ok_json(
            {
                "target": target,
                "in_scope": allowed,
                "allowed": allowed,
                "reason": reason,
                "status": policy.get("status", "APPROVED" if allowed else "BLOCKED_SCOPE"),
            }
        )


class ScopeEnforcePhaseGView(APIView):
    """Stateful Phase G POST /api/scope/enforce using ScopeEnforcer."""

    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        target = str(data.get("target") or "").strip()
        if not target:
            return err_json("target is required", status=400)
        enforcer = get_scope_enforcer()
        allowed, reason = enforcer.enforce_target(target)
        return ok_json({"target": target, "allowed": allowed, "reason": reason})


class FlagsIngestView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        req, verr = validate_model(FlagIngestRequest, data, error_status=422)
        if verr is not None:
            return drf_validation_response(verr)
        assert req is not None
        candidates = get_flag_service().ingest(req.text, source="api")
        return ok_json({"ingested": len(candidates), "flags": [c.__dict__ for c in candidates]})


class FlagsProgressView(APIView):
    def get(self, request: Any) -> Any:
        return ok_json(get_flag_service().progress())


class CTFSubmitView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        req, verr = validate_model(FlagSubmitRequest, data, error_status=422)
        if verr is not None:
            return drf_validation_response(verr)
        assert req is not None
        from ctf.bridge import FlagSubmitter
        from ctf.ctfd import CTFdPlatform

        platform = CTFdPlatform(req.platform_url, req.token)
        submitter = FlagSubmitter(get_flag_service(), platform, challenge_id=req.challenge_id)
        if req.dry_run:
            return ok_json({"ok": True, "dry_run": True, "progress": get_flag_service().progress()})
        res = submitter.submit_pending()
        return ok_json({"ok": True, "results": [r.__dict__ for r in res]})


class ExtensionsListView(APIView):
    def get(self, request: Any) -> Any:
        items = get_extension_manager().list_extensions()
        return ok_json({"extensions": [getattr(x, "__dict__", x) for x in items]})


class ExtensionsInstallView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        req, verr = validate_model(ExtensionInstallRequest, data, error_status=422)
        if verr is not None:
            return drf_validation_response(verr)
        assert req is not None
        try:
            ext_path = safe_resolve_path(
                req.path, [BASE_DIR / "extensions", BASE_DIR / "extensions_ext", DATA_DIR], must_exist=True
            )
        except PermissionError as exc:
            return err_json(str(exc), status=403)
        except FileNotFoundError as exc:
            return err_json(str(exc), status=404)
        rec = get_extension_manager().install(ext_path, is_local=True)
        return ok_json({"ok": True, "extension": getattr(rec, "__dict__", rec)})


# ---------------------------------------------------------------------------
# Burp Suite APIs (Agent + Adapter + Repeater + Traffic)
# ---------------------------------------------------------------------------


class BurpStatsView(APIView):
    def get(self, request: Any) -> Any:
        return ok_json(get_burp_agent().get_stats())


class BurpEndpointsView(APIView):
    def get(self, request: Any) -> Any:
        host = (request.GET.get("host") or "").strip() or None
        return ok_json({"endpoints": get_burp_agent().db.list_endpoints(host)})


class BurpFindingsView(APIView):
    """Supports both GET (BurpAgent DB) and POST (BurpAdapter import)."""

    def get(self, request: Any) -> Any:
        return ok_json({"findings": get_burp_agent().db.list_findings()})

    def post(self, request: Any) -> Any:
        items = get_burp_bridge().import_supported_findings()
        return ok_json({"findings": [getattr(x, "__dict__", x) for x in items]})


class BurpGraphView(APIView):
    def get(self, request: Any) -> Any:
        return ok_json(get_burp_agent().db.get_attack_graph())


class BurpScopeView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        agent = get_burp_agent()
        for inc in data.get("include", []) or []:
            agent.scope.add_include(str(inc))
        for exc in data.get("exclude", []) or []:
            agent.scope.add_exclude(str(exc))
        return ok_json(
            {
                "status": "updated",
                "include": agent.scope.include_rules,
                "exclude": agent.scope.exclude_rules,
            }
        )


class BurpHealthView(APIView):
    def get(self, request: Any) -> Any:
        return ok_json(get_burp_bridge().health_check())


class BurpCapabilitiesView(APIView):
    def get(self, request: Any) -> Any:
        return ok_json(get_burp_bridge().get_available_capabilities())


class BurpHistoryView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        req, verr = validate_model(BurpTargetRequest, data, error_status=422)
        if verr is not None:
            return drf_validation_response(verr)
        assert req is not None
        rows = get_burp_bridge().retrieve_authorized_http_history(target=req.target, limit=req.limit)
        return ok_json({"history": [getattr(x, "__dict__", x) for x in rows]})


class BurpAnalysisView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        req, verr = validate_model(BurpJobRequest, data, error_status=422)
        if verr is not None:
            return drf_validation_response(verr)
        assert req is not None
        res = get_burp_bridge().submit_supported_analysis_job(target=req.target, job_type=req.job_type)
        return ok_json(res)


class BurpStatusView(APIView):
    def get(self, request: Any) -> Any:
        try:
            stats = get_burp_agent().get_stats()
        except Exception:
            stats = {}
        return ok_json({"online": True, "stats": stats, "gateway": get_burp_bridge().health_check()})


class BurpTrafficView(APIView):
    def get(self, request: Any) -> Any:
        limit = parse_query_int(request.GET.get("limit"), 50, max_value=500)
        try:
            endpoints = get_burp_agent().db.list_endpoints(None)[:limit]
        except Exception:
            endpoints = []
        return ok_json({"traffic": endpoints, "count": len(endpoints)})


@require_http_methods(["POST"])
async def burp_repeater_send_view(request: HttpRequest) -> JsonResponse:
    """POST /api/burp/repeater/send — enforced SSRF + ScopeGuard + no-redirect httpx."""
    data, err = parse_json_body(request)
    if err is not None:
        return err
    url = str(data.get("url") or "").strip()
    method = str(data.get("method") or "GET").upper().strip()
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
        return django_err(f"Unsupported HTTP method: {method}", status=400)

    ok, reason, policy = validate_http_url_ssrf_and_scope(
        url,
        scope=data.get("scope") or data.get("in_scope"),
        out_of_scope=data.get("out_of_scope"),
        engagement_id=data.get("engagement_id"),
        action_type="burp_repeater_send",
    )
    if not ok:
        return django_err(reason, status=403, extra={"policy": policy, "status": "BLOCKED_SCOPE"})

    headers = data.get("headers") if isinstance(data.get("headers"), dict) else {}
    body = data.get("body")
    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=False, trust_env=False) as client:
            resp = await client.request(
                method,
                url,
                headers={str(k): str(v) for k, v in headers.items()},
                content=body if isinstance(body, (str, bytes)) else (json.dumps(body) if body is not None else None),
            )
        return django_json(
            {
                "ok": True,
                "url": url,
                "method": method,
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp.text[:16384],
            }
        )
    except Exception as exc:
        return django_json({"ok": False, "url": url, "error": str(exc)}, status=502)


@require_http_methods(["POST"])
async def burp_ai_audit_view(request: HttpRequest) -> JsonResponse:
    data, err = parse_json_body(request)
    if err is not None:
        return err
    raw_req = str(data.get("request") or data.get("url") or "").strip()
    if not raw_req:
        return django_err("request payload is required", status=400)
    analysis = await call_ai(
        f"Audit this HTTP request for bug bounty vulnerabilities (IDOR, SSRF, Auth, SQLi, XSS):\n{raw_req[:4000]}"
    )
    return django_json({"ok": True, "audit": analysis})


class BurpIngestView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        sensor = get_burp_sensor_bridge()
        res = getattr(sensor, "ingest", lambda d: {"accepted": True})(data)
        return ok_json({"ok": True, "result": res})


class BurpArtifactsView(APIView):
    def get(self, request: Any) -> Any:
        try:
            items = get_burp_agent().db.list_endpoints(None)
        except Exception:
            items = []
        return ok_json({"artifacts": items})


class BurpEvidenceView(APIView):
    def get(self, request: Any) -> Any:
        try:
            items = get_burp_agent().db.list_findings()
        except Exception:
            items = []
        return ok_json({"evidence": items})


class BurpSensoryEventsView(APIView):
    def get(self, request: Any) -> Any:
        return ok_json({"events": get_activity_logs(50)})


# ---------------------------------------------------------------------------
# Arsenal & Active Probe Tools (No Shell + ScopeGuard)
# ---------------------------------------------------------------------------


class ArsenalToolsView(APIView):
    def get(self, request: Any) -> Any:
        category = request.GET.get("category") or None
        try:
            from core.arsenal.kali_catalog import KALI_TOOL_CATALOG

            tools = KALI_TOOL_CATALOG
            if category:
                tools = {
                    k: v
                    for k, v in tools.items()
                    if str(getattr(v, "category", "") if not isinstance(v, dict) else v.get("category", "")).lower() == category.lower()
                }
            return ok_json({"tools": tools})
        except Exception as exc:
            return ok_json({"tools": {}, "error": str(exc)})


class ArsenalToolDetailView(APIView):
    def get(self, request: Any, tool_name: str) -> Any:
        try:
            from core.arsenal.kali_catalog import get_tool_definition

            defn = get_tool_definition(tool_name)
            if not defn:
                return err_json(f"Tool {tool_name} not found", status=404)
            return ok_json({"tool": tool_name, "definition": getattr(defn, "__dict__", defn)})
        except Exception as exc:
            return err_json(str(exc), status=404)


@require_http_methods(["POST"])
async def arsenal_run_view(request: HttpRequest) -> JsonResponse:
    """POST /api/arsenal/run — strict ScopeGuard + no-shell subprocess."""
    data, err = parse_json_body(request)
    if err is not None:
        return err
    tool = str(data.get("tool") or data.get("tool_name") or "").strip()
    target = str(data.get("target") or "").strip()
    if not tool:
        return django_err("tool is required", status=400)
    if target:
        ok, reason, policy = validate_scan_target(
            target,
            scope=data.get("scope") or data.get("in_scope"),
            out_of_scope=data.get("out_of_scope"),
            action_type="arsenal_run",
        )
        if not ok:
            return django_err(reason, status=403, extra={"policy": policy})
    args = data.get("args") if isinstance(data.get("args"), list) else []
    cmd = [Path(tool).name, *[str(a) for a in args]]
    if target and target not in cmd:
        cmd.append(target)
    try:
        res = await run_command_no_shell(cmd, timeout_s=float(data.get("timeout_s") or 60.0))
        return django_json({"ok": res["returncode"] == 0, **res})
    except PermissionError as exc:
        return django_err(str(exc), status=403)


@require_http_methods(["POST"])
async def run_tool_view(request: HttpRequest) -> JsonResponse:
    """POST /api/run-tool — strict ScopeGuard + create_subprocess_exec."""
    data, err = parse_json_body(request)
    if err is not None:
        return err
    command = data.get("command") or data.get("cmd")
    target = str(data.get("target") or "").strip()
    if not command:
        return django_err("command is required", status=400)
    if target:
        ok, reason, policy = validate_scan_target(
            target,
            scope=data.get("scope") or data.get("in_scope"),
            out_of_scope=data.get("out_of_scope"),
            action_type="run_tool",
        )
        if not ok:
            return django_err(reason, status=403, extra={"policy": policy})
    try:
        res = await run_command_no_shell(command, timeout_s=float(data.get("timeout_s") or 60.0))
        return django_json({"ok": res["returncode"] == 0, **res})
    except PermissionError as exc:
        return django_err(str(exc), status=403)
    except ValueError as exc:
        return django_err(str(exc), status=400)


@require_http_methods(["POST"])
async def browser_browse_view(request: HttpRequest) -> JsonResponse:
    data, err = parse_json_body(request)
    if err is not None:
        return err
    url = str(data.get("url") or data.get("target_url") or "").strip()
    ok, reason, policy = validate_http_url_ssrf_and_scope(
        url,
        scope=data.get("scope") or data.get("in_scope"),
        out_of_scope=data.get("out_of_scope"),
        action_type="browser_browse",
    )
    if not ok:
        return django_err(reason, status=403, extra={"policy": policy})
    try:
        from core.browser.ai_browser_operator import run_ai_browser_session_sync

        res = await asyncio.to_thread(run_ai_browser_session_sync, url, headless=bool(data.get("headless", True)))
        return django_json({"ok": True, "url": url, "result": res})
    except Exception as exc:
        return django_json({"ok": False, "url": url, "error": str(exc)}, status=500)


@require_http_methods(["POST"])
async def waf_check_view(request: HttpRequest) -> JsonResponse:
    data, err = parse_json_body(request)
    if err is not None:
        return err
    url = str(data.get("url") or data.get("target") or "").strip()
    ok, reason, policy = validate_http_url_ssrf_and_scope(
        url,
        scope=data.get("scope") or data.get("in_scope"),
        out_of_scope=data.get("out_of_scope"),
        action_type="waf_check",
    )
    if not ok:
        return django_err(reason, status=403, extra={"policy": policy})
    try:
        from tools.waf_evasion import WAFEvasionEngine

        eng = WAFEvasionEngine()
        res = getattr(eng, "fingerprint", lambda u: {"target": u, "waf": "unknown"})(url)
        return django_json({"ok": True, "result": res})
    except Exception as exc:
        return django_json({"ok": False, "error": str(exc)}, status=500)


@require_http_methods(["POST"])
async def probe_verify_view(request: HttpRequest) -> JsonResponse:
    data, err = parse_json_body(request)
    if err is not None:
        return err
    url = str(data.get("url") or data.get("target") or "").strip()
    ok, reason, policy = validate_http_url_ssrf_and_scope(
        url,
        scope=data.get("scope") or data.get("in_scope"),
        out_of_scope=data.get("out_of_scope"),
        action_type="probe_verify",
    )
    if not ok:
        return django_err(reason, status=403, extra={"policy": policy})
    try:
        from core.smart_probe_engine import SmartPoCExecutor

        exe = SmartPoCExecutor()
        fn = getattr(exe, "verify", None)
        res = fn(data) if callable(fn) else {"verified": False}
        if asyncio.iscoroutine(res):
            res = await res
        return django_json({"ok": True, "result": res})
    except Exception as exc:
        return django_json({"ok": False, "error": str(exc)}, status=500)
