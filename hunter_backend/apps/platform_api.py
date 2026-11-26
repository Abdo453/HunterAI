"""Unified /api/platform/*, /api/csrf, SSE telemetry stream, and :7071 Artex proxy."""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import os
import time
from typing import Any, Dict, List, Optional

from django.http import HttpRequest, HttpResponse, JsonResponse, StreamingHttpResponse
from django.middleware.csrf import get_token
from django.views.decorators.http import require_GET, require_http_methods
from pydantic import BaseModel, Field
from rest_framework.views import APIView

from agents.security_intelligence.schemas import ScopeDecision, ScopeMode, ScopeRule
from core.copilot_service import (
    detect_live_providers,
    evaluate_action_policy,
    is_tcp_reachable,
)
from core.evidence_store import EvidenceStore
from core.platform_store import get_platform_store
from core.run_control import GLOBAL_RUN_CONTROLLER
from core.security_mode import web_governance_enforced
from hunter_backend.apps.common import (
    await_sync,
    django_err,
    django_json,
    err_json,
    format_sse,
    ok_json,
    parse_json_body,
    parse_query_bool,
    parse_query_float,
    parse_query_int,
    split_out_of_scope_exclusions,
    validate_http_url_ssrf_and_scope,
    validate_model,
    validate_scan_target,
)
from hunter_backend.runtime import (
    ARTEX_BASE_URL,
    EVENT_BUS,
    control_managed_run_sync,
    ensure_platform_wiring,
    execute_approved_action,
    get_go_client,
    probe_artex_health,
    start_platform_run,
)

logger = logging.getLogger("hunter_backend.apps.platform_api")

_HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
}
_PROXY_ALLOWED_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH"}


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
    kind: str = Field(default="pipeline")
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
    decision: str = Field(...)
    note: str = ""
    decided_by: str = "operator"


def _is_safe_proxy_subpath(subpath: str) -> bool:
    """Reject traversal, encoded dot-segments, NULs, scheme injection, or backslashes."""
    raw = (subpath or "").strip()
    if not raw or "\x00" in raw or "\\" in raw or "://" in raw:
        return False
    lower = raw.lower()
    if "%2e" in lower or "%5c" in lower or "%00" in lower:
        return False
    for seg in raw.split("/"):
        if seg in {".", ".."}:
            return False
    return True


def _find_findings_for_engagement(target: str) -> List[Dict[str, Any]]:
    try:
        from bughunter.tools.lead_board import load_ledger

        items = load_ledger(target) if target else []
        if isinstance(items, list):
            return items
    except Exception:
        pass
    try:
        ev = EvidenceStore()
        all_rows = getattr(ev, "list_findings", lambda: [])()
        if target:
            return [r for r in all_rows if target in str(r)]
        return list(all_rows)
    except Exception:
        return []


class CsrfTokenView(APIView):
    """Issue a double-submit CSRF cookie and return the token for Next.js frontend."""

    def get(self, request: Any) -> Any:
        token = get_token(request)
        return ok_json({"csrfToken": token, "headerName": "X-CSRFToken"})


class PlatformContextView(APIView):
    """GET / PUT /api/platform/context."""

    def get(self, request: Any) -> Any:
        store = ensure_platform_wiring()
        ctx = store.get_context()
        return ok_json({"status": "ok", "context": ctx, **ctx})

    def put(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        req, verr = validate_model(ContextUpdateRequest, data)
        if verr is not None:
            return err_json("Invalid context update payload", status=400)
        store = ensure_platform_wiring()
        kwargs: Dict[str, Any] = {}
        if "active_engagement_id" in data:
            kwargs["active_engagement_id"] = req.active_engagement_id
        if "active_run_id" in data:
            kwargs["active_run_id"] = req.active_run_id
        if "active_conversation_id" in data:
            kwargs["active_conversation_id"] = req.active_conversation_id
        if req.extra is not None:
            kwargs["extra"] = req.extra
        updated = store.update_context(**kwargs)
        EVENT_BUS.publish_threadsafe(
            "context.updated",
            payload=updated,
            engagement_id=updated.get("active_engagement_id"),
            run_id=updated.get("active_run_id"),
            source="platform",
        )
        return ok_json({"status": "ok", "context": updated, **updated})


_TOOLS_CACHE: Tuple[float, Any] = (0.0, [])


@require_GET
async def platform_overview_view(request: HttpRequest) -> JsonResponse:
    """GET /api/platform/overview: aggregated platform state, providers, runs, and Artex probe."""
    global _TOOLS_CACHE
    store = ensure_platform_wiring()
    ctx = store.get_context()
    engagements = store.list_engagements(limit=50)
    runs = store.list_runs(limit=50)
    approvals = store.list_approvals(status="pending", limit=50)
    notifications = store.list_notifications(unread_only=True, limit=30)
    recent_events = store.list_events(since_seq=max(0, store.latest_seq() - 40), limit=40)

    active_eng = (
        store.get_engagement(ctx["active_engagement_id"])
        if ctx.get("active_engagement_id")
        else None
    )
    active_run = (
        store.get_run(ctx["active_run_id"])
        if ctx.get("active_run_id")
        else None
    )

    def _load_tools() -> Any:
        from tools.tool_manager import ToolManager

        return ToolManager().get_available_tools()

    async def _safe_providers() -> Dict[str, Any]:
        try:
            res = await asyncio.to_thread(detect_live_providers)
            return res if isinstance(res, dict) else {}
        except Exception:
            return {}

    async def _safe_tools() -> Any:
        global _TOOLS_CACHE
        now_m = time.monotonic()
        cached_at, cached_val = _TOOLS_CACHE
        if cached_val and (now_m - cached_at) < 15.0:
            return cached_val
        try:
            res = await asyncio.to_thread(_load_tools)
            val = res if res is not None else []
            _TOOLS_CACHE = (time.monotonic(), val)
            return val
        except Exception:
            return cached_val or []

    providers, tools, artex = await asyncio.gather(
        _safe_providers(),
        _safe_tools(),
        probe_artex_health(),
    )
    prov_dict = providers if isinstance(providers, dict) else {}
    latest_seq = store.latest_seq()
    services = {
        "artex_go_core": artex,
        "ollama": {
            "online": bool(prov_dict.get("ollama_reachable")),
            "host": str(prov_dict.get("ollama_host") or ""),
        },
        "lm_studio": {
            "online": bool(prov_dict.get("lm_studio_reachable")),
            "host": str(prov_dict.get("lm_studio_host") or ""),
        },
        "cloud_providers": list(prov_dict.get("cloud") or []),
    }
    counts = {
        "engagements": len(engagements),
        "runs": len(runs),
        "active_runs": sum(1 for r in runs if r.get("status") in {"running", "paused"}),
        "pending_approvals": len(approvals),
        "unread_notifications": len(notifications),
        "assets": len(engagements),
        "findings": 0,
    }
    return django_json(
        {
            "status": "ok",
            "latest_seq": latest_seq,
            "context": ctx,
            "active_engagement": active_eng,
            "active_run": active_run,
            "engagements": engagements,
            "runs": runs,
            "pending_approvals": approvals,
            "approvals": {
                "pending": approvals,
                "pending_count": len(approvals),
            },
            "unread_notifications": notifications,
            "recent_events": recent_events,
            "providers": providers,
            "services": services,
            "counts": counts,
            "tools": tools,
            "artex": artex,
            "stats": {
                "engagement_count": len(engagements),
                "run_count": len(runs),
                "active_run_count": counts["active_runs"],
                "pending_approval_count": len(approvals),
                "unread_notification_count": len(notifications),
                "latest_seq": latest_seq,
            },
        }
    )


class PlatformEngagementsView(APIView):
    """GET / POST /api/platform/engagements."""

    def get(self, request: Any) -> Any:
        store = ensure_platform_wiring()
        limit = parse_query_int(request.GET.get("limit"), 100)
        items = store.list_engagements(limit=limit)
        go_online = is_tcp_reachable("127.0.0.1", 7071, timeout=0.05)
        return ok_json(
            {
                "status": "ok",
                "engagements": items,
                "count": len(items),
                "go_core": {"online": go_online},
            }
        )

    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        req, verr = validate_model(EngagementCreateRequest, data, error_status=422)
        if verr is not None:
            return err_json("Invalid engagement payload", status=422, extra=json.loads(verr.content))
        target = req.target.strip()
        in_scope = req.in_scope if req.in_scope is not None else [target]
        out_of_scope = req.out_of_scope or []
        ok_tgt, reason_tgt, policy_tgt = validate_scan_target(
            target,
            scope=in_scope,
            out_of_scope=out_of_scope,
            action_type="ENGAGEMENT_SCOPE",
        )
        if not ok_tgt:
            return err_json(
                reason_tgt or "Target blocked by ScopeGuard",
                status=403,
                extra={"policy": policy_tgt},
            )
        host_out_scope, _ = split_out_of_scope_exclusions(out_of_scope)
        policy_check = evaluate_action_policy(
            action_type="ENGAGEMENT_SCOPE",
            target=target,
            tool_name="scope_guard",
            in_scope=in_scope,
            out_of_scope=host_out_scope,
            allow_active_tests=True,
        )
        if not policy_check.get("allowed"):
            return err_json(
                str(policy_check.get("reason") or "Target blocked by ScopeGuard"),
                status=403,
                extra={"policy": policy_check},
            )
        store = ensure_platform_wiring()
        eng = store.upsert_engagement(
            name=req.name or target,
            target=target,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            status=req.status,
            metadata=req.metadata or {},
        )
        if req.set_active:
            store.update_context(active_engagement_id=eng["engagement_id"])
        store.append_event(
            "engagement.created",
            engagement_id=eng["engagement_id"],
            source="platform",
            payload=eng,
        )
        return ok_json({"status": "ok", "engagement": eng, **eng}, status=201)


class PlatformEngagementDetailView(APIView):
    """GET /api/platform/engagements/<engagement_id>."""

    def get(self, request: Any, engagement_id: str) -> Any:
        store = ensure_platform_wiring()
        eng = store.get_engagement(engagement_id)
        if not eng:
            return err_json(f"Engagement {engagement_id} not found", status=404)
        runs = store.list_runs(engagement_id=engagement_id, limit=100)
        approvals = store.list_approvals(engagement_id=engagement_id, limit=100)
        conversations = store.list_conversations(engagement_id=engagement_id, limit=50)
        events = store.list_events(engagement_id=engagement_id, limit=100)
        findings = _find_findings_for_engagement(eng.get("target", ""))
        return ok_json(
            {
                "engagement": eng,
                "runs": runs,
                "approvals": approvals,
                "conversations": conversations,
                "events": events,
                "findings": findings,
            }
        )


class PlatformRunsListView(APIView):
    """GET /api/platform/runs."""

    def get(self, request: Any) -> Any:
        store = ensure_platform_wiring()
        runs = store.list_runs(
            kind=request.GET.get("kind") or None,
            engagement_id=request.GET.get("engagement_id") or None,
            status=request.GET.get("status") or None,
            active_only=parse_query_bool(request.GET.get("active_only"), False),
            limit=parse_query_int(request.GET.get("limit"), 100),
        )
        return ok_json({"runs": runs, "count": len(runs)})


@require_http_methods(["POST"])
async def platform_run_start_view(request: HttpRequest) -> JsonResponse:
    """POST /api/platform/runs/start (native async view so background task stays on uvicorn loop)."""
    data, err = parse_json_body(request)
    if err is not None:
        return err
    req, verr = validate_model(RunStartRequest, data, error_status=422)
    if verr is not None:
        return verr
    assert req is not None
    try:
        run = await start_platform_run(
            kind=req.kind,
            target=req.target,
            engagement_id=req.engagement_id,
            scope=req.scope,
            out_of_scope=req.out_of_scope,
            mode=req.mode,
            prompt=req.prompt,
            engine=req.engine,
            model=req.model,
            coverage=req.coverage,
            max_cycles=req.max_cycles,
            force_fallback=req.force_fallback,
            self_operate=req.self_operate,
            proxy=req.proxy,
        )
        return django_json({"ok": True, "run": run, "run_id": run.get("run_id")})
    except PermissionError as exc:
        return django_err(str(exc), status=403, extra={"status": "BLOCKED_SCOPE"})
    except ValueError as exc:
        return django_err(str(exc), status=400)


class PlatformRunControlView(APIView):
    """POST /api/platform/runs/<run_id>/{pause|resume|stop}."""

    action: str = "pause"

    def post(self, request: Any, run_id: str) -> Any:
        store = ensure_platform_wiring()
        run = store.get_run(run_id)
        if not run:
            return err_json(f"Run {run_id} not found", status=404)

        current_status = str(run.get("status") or "")
        if self.action == "pause":
            ok = control_managed_run_sync(run_id, "pause")
            if not ok and current_status in {"completed", "stopped", "failed"}:
                return ok_json({"ok": False, "run": run, "status": current_status, "state": current_status})
            updated = store.update_run(run_id, status="paused") or run
            store.append_event(
                "run.paused",
                run_id=run_id,
                engagement_id=run.get("engagement_id"),
                source="platform",
                payload={"run_id": run_id, "controller_ack": ok},
            )
            return ok_json({"ok": True, "run": updated, "status": "paused", "state": "paused"})

        if self.action == "resume":
            ok = control_managed_run_sync(run_id, "resume")
            if not ok and current_status in {"completed", "stopped", "failed"}:
                return ok_json({"ok": False, "run": run, "status": current_status, "state": current_status})
            updated = store.update_run(run_id, status="running") or run
            store.append_event(
                "run.resumed",
                run_id=run_id,
                engagement_id=run.get("engagement_id"),
                source="platform",
                payload={"run_id": run_id, "controller_ack": ok},
            )
            return ok_json({"ok": True, "run": updated, "status": "running", "state": "running"})

        ok = control_managed_run_sync(run_id, "stop")
        updated = store.update_run(run_id, status="stopped", finished_at=time.time()) or run
        store.append_event(
            "run.stopped",
            run_id=run_id,
            engagement_id=run.get("engagement_id"),
            source="platform",
            payload={"run_id": run_id, "controller_ack": ok},
        )
        return ok_json({"ok": True, "run": updated, "status": "stopped", "state": "stopped"})


@require_GET
async def platform_sse_stream_view(request: HttpRequest) -> StreamingHttpResponse:
    """GET /api/platform/stream: native async SSE replay + live push + heartbeats."""
    ensure_platform_wiring()
    last_ev_hdr = request.META.get("HTTP_LAST_EVENT_ID")
    raw_since = request.GET.get("since_seq") or last_ev_hdr
    since_seq: Optional[int] = int(raw_since) if raw_since and raw_since.lstrip("-").isdigit() else None
    run_id = request.GET.get("run_id") or None
    engagement_id = request.GET.get("engagement_id") or None
    heartbeat_s = max(0.05, parse_query_float(request.GET.get("heartbeat_s"), 15.0))
    once = parse_query_bool(request.GET.get("once"), False)

    async def event_generator():
        q = EVENT_BUS.subscribe()
        last_sent_seq = 0 if since_seq is None else since_seq
        try:
            backlog = EVENT_BUS.backlog_since(
                since_seq, run_id=run_id, engagement_id=engagement_id, limit=200
            )
            for ev in backlog:
                seq = ev.get("seq")
                if seq is not None:
                    last_sent_seq = max(last_sent_seq, int(seq))
                ev_type = str(ev.get("event_type") or ev.get("type") or "platform.event")
                yield format_sse(ev_type, ev, event_id=seq)

            if once:
                yield format_sse("platform.ready", {"seq": last_sent_seq, "once": True})
                return

            yield format_sse("platform.ready", {"seq": last_sent_seq})

            while True:
                try:
                    ev = await asyncio.wait_for(q.get(), timeout=heartbeat_s)
                except asyncio.TimeoutError:
                    yield format_sse("ping", {"ts": asyncio.get_running_loop().time()})
                    continue

                if run_id and ev.get("run_id") != run_id:
                    continue
                if engagement_id and ev.get("engagement_id") != engagement_id:
                    continue
                seq = ev.get("seq")
                if seq is not None and int(seq) <= last_sent_seq:
                    continue
                if seq is not None:
                    last_sent_seq = int(seq)
                ev_type = str(ev.get("event_type") or ev.get("type") or "platform.event")
                yield format_sse(ev_type, ev, event_id=seq)
        except asyncio.CancelledError:
            return
        finally:
            EVENT_BUS.unsubscribe(q)

    resp = StreamingHttpResponse(event_generator(), content_type="text/event-stream")
    resp["Cache-Control"] = "no-cache, no-transform"
    resp["X-Accel-Buffering"] = "no"
    return resp


class PlatformApprovalsListView(APIView):
    """GET /api/platform/approvals."""

    def get(self, request: Any) -> Any:
        store = ensure_platform_wiring()
        store.expire_stale_approvals()
        items = store.list_approvals(
            status=request.GET.get("status") or None,
            engagement_id=request.GET.get("engagement_id") or None,
            run_id=request.GET.get("run_id") or None,
            limit=parse_query_int(request.GET.get("limit"), 100),
        )
        return ok_json({"approvals": items, "count": len(items)})


class _ApprovalScopeGuardAdapter:
    """Adapter bridging Engagement scope and common/policy guards to PolicyEngine."""

    def __init__(
        self,
        in_scope: List[str],
        out_of_scope: List[str],
        *,
        engagement_id: Optional[str] = None,
        allow_active_tests: bool = True,
    ) -> None:
        self._in_scope = [str(s).strip() for s in (in_scope or []) if str(s).strip()]
        self._out_of_scope = [str(s).strip() for s in (out_of_scope or []) if str(s).strip()]
        self._engagement_id = engagement_id
        host_out, path_exclusions = split_out_of_scope_exclusions(self._out_of_scope)
        self._host_out_scope = host_out
        self.rule = ScopeRule(
            target=self._in_scope[0] if self._in_scope else "",
            allowed_domains=list(self._in_scope),
            excluded_paths=[p for _h, p in path_exclusions],
            allow_active_tests=allow_active_tests,
            mode=ScopeMode.ACTIVE if allow_active_tests else ScopeMode.PASSIVE,
        )

    def set_scope(self, rule: ScopeRule) -> None:
        self.rule = rule

    def evaluate_scope_decision(
        self, target: str, action: str = "passive_analysis"
    ) -> ScopeDecision:
        clean_target = (target or "").strip()
        if not clean_target:
            return ScopeDecision(
                allowed=False,
                mode=ScopeMode.BLOCKED,
                target=target,
                action=action,
                reason="Target is empty.",
            )
        if not self._in_scope and web_governance_enforced():
            return ScopeDecision(
                allowed=False,
                mode=ScopeMode.BLOCKED,
                target=clean_target,
                action=action,
                reason="No authorized target scope configured (empty in_scope fails closed).",
            )

        if "://" in clean_target:
            ok, reason, _policy = validate_http_url_ssrf_and_scope(
                clean_target,
                scope=self._in_scope,
                out_of_scope=self._out_of_scope,
                engagement_id=self._engagement_id,
                action_type=action or "CLI_TOOL",
            )
        else:
            ok, reason, _policy = validate_scan_target(
                clean_target,
                scope=self._in_scope,
                out_of_scope=self._out_of_scope,
                engagement_id=self._engagement_id,
                action_type=action or "CLI_TOOL",
            )
        if not ok:
            return ScopeDecision(
                allowed=False,
                mode=ScopeMode.BLOCKED,
                target=clean_target,
                action=action,
                reason=reason or "Target blocked by ScopeGuard.",
            )

        policy = evaluate_action_policy(
            action_type=action or "CLI_TOOL",
            target=clean_target,
            in_scope=self._in_scope,
            out_of_scope=self._host_out_scope,
            allow_active_tests=bool(self.rule.allow_active_tests),
        )
        allowed = bool(policy.get("allowed"))
        return ScopeDecision(
            allowed=allowed,
            mode=(
                ScopeMode.ACTIVE if self.rule.allow_active_tests else ScopeMode.PASSIVE
            )
            if allowed
            else ScopeMode.BLOCKED,
            target=clean_target,
            action=action,
            reason=str(policy.get("reason") or reason or ""),
        )


def _validate_approval_scope_precheck(
    existing: Dict[str, Any],
    in_scope: List[str],
    out_of_scope: List[str],
) -> Dict[str, Any]:
    """Fail-closed scope/SSRF/risk validation before persisting an approval decision."""
    if not in_scope and web_governance_enforced():
        return {
            "allowed": False,
            "status": "BLOCKED_SCOPE",
            "reason": "No authorized target scope configured (empty in_scope fails closed).",
        }
    target_str = str(existing.get("target") or "").strip()
    host_out_scope, _ = split_out_of_scope_exclusions(out_of_scope)
    ok_tgt, reason_tgt, policy_tgt = validate_scan_target(
        target_str,
        scope=in_scope,
        out_of_scope=out_of_scope,
        engagement_id=existing.get("engagement_id"),
        action_type=existing["action_type"],
    )
    if not ok_tgt:
        blocked = dict(policy_tgt or {})
        blocked["allowed"] = False
        blocked["reason"] = reason_tgt or str(blocked.get("reason") or "Blocked by ScopeGuard")
        return blocked
    return evaluate_action_policy(
        action_type=existing["action_type"],
        target=target_str,
        tool_name=existing.get("tool_name") or "",
        command_args=existing.get("command_args") or "",
        in_scope=in_scope,
        out_of_scope=host_out_scope,
        allow_active_tests=True,
        rationale=existing.get("rationale") or "",
    )


@require_http_methods(["POST"])
async def platform_approval_decide_view(
    request: HttpRequest, approval_id: str
) -> JsonResponse:
    """POST /api/platform/approvals/<approval_id>/decide."""
    data, err = parse_json_body(request)
    if err is not None:
        return err
    req, verr = validate_model(ApprovalDecideRequest, data, error_status=422)
    if verr is not None:
        return verr
    assert req is not None

    norm = req.decision.strip().lower()
    if norm in {"approve", "approved", "allow", "allowed"}:
        decision = "approved"
    elif norm in {"reject", "rejected", "deny", "denied"}:
        decision = "rejected"
    else:
        return django_err("decision must be 'approved' or 'rejected'", status=400)

    store = ensure_platform_wiring()
    existing = store.get_approval(approval_id)
    if not existing:
        return django_err(f"Approval {approval_id} not found", status=404)
    if existing.get("status") != "pending":
        return django_err(
            f"Approval {approval_id} is already '{existing.get('status')}'",
            status=409,
        )

    in_scope: List[str] = []
    out_of_scope: List[str] = []
    if decision == "approved":
        eng = (
            store.get_engagement(existing["engagement_id"])
            if existing.get("engagement_id")
            else None
        )
        in_scope = [str(s).strip() for s in ((eng or {}).get("in_scope") or []) if str(s).strip()]
        out_of_scope = [str(s).strip() for s in ((eng or {}).get("out_of_scope") or []) if str(s).strip()]
        policy = _validate_approval_scope_precheck(existing, in_scope, out_of_scope)
        if not policy.get("allowed"):
            rejected = store.decide_approval(
                approval_id,
                "rejected",
                decided_by="policy_guard",
                note=f"Blocked on approval check: {policy.get('reason')}",
            )
            store.append_event(
                "approval.rejected",
                run_id=existing.get("run_id"),
                engagement_id=existing.get("engagement_id"),
                source="policy_guard",
                payload=rejected or {},
            )
            return django_err(
                str(policy.get("reason") or "Blocked by ScopeGuard"),
                status=403,
                extra={"policy": policy, "approval": rejected},
            )

    updated = store.decide_approval(
        approval_id,
        decision,
        decided_by=req.decided_by,
        note=req.note,
    )
    if updated is None:
        return django_err(f"Approval {approval_id} not found", status=404)

    store.append_event(
        f"approval.{decision}",
        run_id=updated.get("run_id"),
        engagement_id=updated.get("engagement_id"),
        source="approvals",
        payload=updated,
    )

    execution: Optional[Dict[str, Any]] = None
    if decision == "approved":
        if updated.get("action_type") == "RUN_TOOL" or (
            updated.get("tool_name") and updated.get("action_type") not in {"platform_run", "scan", "mission", "pipeline"}
        ):
            try:
                from core.gateway.policy_engine import PolicyEngine
                from core.gateway.schemas import ActionProposal
                from core.gateway.tool_gateway import GovernedToolGateway

                eng_id = updated.get("engagement_id")
                sg = _ApprovalScopeGuardAdapter(
                    in_scope=in_scope,
                    out_of_scope=out_of_scope,
                    engagement_id=eng_id,
                    allow_active_tests=True,
                )
                gw = GovernedToolGateway(policy_engine=PolicyEngine(scope_guard=sg))
                proposal_action = (
                    "HTTP_REQUEST"
                    if str(updated.get("action_type") or "").upper() == "HTTP_REQUEST"
                    else "CLI_TOOL"
                )
                proposal = ActionProposal(
                    proposing_agent="ApprovalQueue",
                    target=str(updated.get("target") or ""),
                    tool_name=str(updated.get("tool_name") or "nmap"),
                    command_args=str(updated.get("command_args") or updated.get("target") or ""),
                    action_type=proposal_action,
                    rationale=str(updated.get("rationale") or "Operator approved action"),
                )
                gw_res = gw.execute_proposal(proposal)
                if inspect.isawaitable(gw_res):
                    gw_res = await gw_res
                execution = {
                    "executed": bool(getattr(gw_res, "success", False)),
                    "blocked": bool(getattr(gw_res, "blocked", False)),
                    "returncode": getattr(gw_res, "returncode", 0),
                    "stdout_excerpt": str(getattr(gw_res, "raw_stdout", "") or "")[:2000],
                    "stderr_excerpt": str(getattr(gw_res, "raw_stderr", "") or "")[:1000],
                    "error": getattr(gw_res, "error", None),
                    "action_type": updated.get("action_type"),
                    "target": updated.get("target"),
                    "approval_id": approval_id,
                }
            except Exception as exc:
                logger.exception("Approved tool execution failed for %s", approval_id)
                execution = {
                    "executed": False,
                    "blocked": False,
                    "returncode": -1,
                    "stdout_excerpt": "",
                    "stderr_excerpt": str(exc)[:1000],
                    "error": str(exc),
                    "action_type": updated.get("action_type"),
                    "target": updated.get("target"),
                    "approval_id": approval_id,
                }
        else:
            try:
                execution = await execute_approved_action(updated)
            except Exception as exc:
                logger.exception("Approved action execution failed for %s", approval_id)
                execution = {
                    "executed": False,
                    "blocked": False,
                    "returncode": -1,
                    "stdout_excerpt": "",
                    "stderr_excerpt": str(exc)[:1000],
                    "error": str(exc),
                    "action_type": updated.get("action_type"),
                    "target": updated.get("target"),
                    "approval_id": approval_id,
                }

    return django_json(
        {
            "ok": True,
            "status": "ok",
            "decision": decision,
            "approval": updated,
            "execution": execution,
            "executed": bool((execution or {}).get("executed")),
        }
    )


class PlatformSearchView(APIView):
    """GET /api/platform/search?q=...&limit=..."""

    def get(self, request: Any) -> Any:
        store = ensure_platform_wiring()
        q = (request.GET.get("q") or "").strip()
        limit = parse_query_int(request.GET.get("limit"), 25, max_value=200)
        if not q:
            return ok_json(
                {
                    "query": "",
                    "total": 0,
                    "results": [],
                    "engagements": [],
                    "runs": [],
                    "conversations": [],
                    "approvals": [],
                    "events": [],
                }
            )
        ql = q.lower()
        engs = [
            e
            for e in store.list_engagements(limit=200)
            if ql in str(e.get("name", "")).lower() or ql in str(e.get("target", "")).lower()
        ][:limit]
        runs = [
            r
            for r in store.list_runs(limit=200)
            if ql in str(r.get("target", "")).lower()
            or ql in str(r.get("run_id", "")).lower()
            or ql in str(r.get("kind", "")).lower()
        ][:limit]
        convs = store.search_conversations(q, limit=limit)
        approvals = [
            a
            for a in store.list_approvals(limit=200)
            if ql in str(a.get("target", "")).lower()
            or ql in str(a.get("action_type", "")).lower()
            or ql in str(a.get("tool_name", "")).lower()
        ][:limit]
        events = [
            ev
            for ev in store.list_events(since_seq=max(0, store.latest_seq() - 300), limit=300)
            if ql in str(ev.get("type", "")).lower() or ql in str(ev.get("payload", "")).lower()
        ][:limit]

        unified: List[Dict[str, Any]] = []
        for e in engs:
            unified.append({"kind": "engagement", "id": e["engagement_id"], "title": e.get("name") or e.get("target"), "item": e})
        for r in runs:
            unified.append({"kind": "run", "id": r["run_id"], "title": f"{r.get('kind')}:{r.get('target')}", "item": r})
        for c in convs:
            unified.append({"kind": "conversation", "id": c["conversation_id"], "title": c.get("title"), "item": c})
        for a in approvals:
            unified.append({"kind": "approval", "id": a["approval_id"], "title": a.get("action_type"), "item": a})

        return ok_json(
            {
                "query": q,
                "total": len(unified),
                "results": unified[:limit],
                "engagements": engs,
                "runs": runs,
                "conversations": convs,
                "approvals": approvals,
                "events": events,
                "groups": {
                    "engagements": [{**e, "id": e["engagement_id"]} for e in engs],
                    "runs": [{**r, "id": r["run_id"]} for r in runs],
                    "conversations": [{**c, "id": c["conversation_id"]} for c in convs],
                    "approvals": [{**a, "id": a["approval_id"]} for a in approvals],
                },
            }
        )


class PlatformNotificationsView(APIView):
    """GET /api/platform/notifications."""

    def get(self, request: Any) -> Any:
        store = ensure_platform_wiring()
        unread_only = parse_query_bool(request.GET.get("unread_only"), False)
        limit = parse_query_int(request.GET.get("limit"), 50)
        items = store.list_notifications(unread_only=unread_only, limit=limit)
        return ok_json({"notifications": items, "count": len(items)})


class PlatformNotificationReadView(APIView):
    """POST /api/platform/notifications/<notification_id>/read."""

    def post(self, request: Any, notification_id: str) -> Any:
        store = ensure_platform_wiring()
        ok = store.mark_notification_read(notification_id)
        if not ok:
            return err_json(f"Notification {notification_id} not found", status=404)
        return ok_json({"ok": True, "notification_id": notification_id})


@require_GET
async def artex_go_health_view(request: HttpRequest) -> JsonResponse:
    """GET /api/platform/artex/health."""
    res = await probe_artex_health()
    if "status" not in res:
        res["status"] = "online" if res.get("online") else "offline"
    return django_json(res)


@require_http_methods(["GET", "POST", "PUT", "DELETE", "PATCH"])
async def artex_go_proxy_view(request: HttpRequest, path: str) -> HttpResponse:
    """Async HTTP proxy forwarding /api/platform/artex/* cleanly to Go Core (:7071)."""
    if request.method not in _PROXY_ALLOWED_METHODS:
        return django_err("Method not allowed", status=405)

    clean_path = (path or "").lstrip("/")
    if not _is_safe_proxy_subpath(clean_path):
        return django_err("Invalid proxy subpath", status=400)

    if clean_path.startswith("api/v1/"):
        target_path = f"/{clean_path}"
    elif clean_path.startswith("v1/"):
        target_path = f"/api/{clean_path}"
    elif clean_path.startswith("api/"):
        target_path = f"/api/v1/{clean_path[4:]}"
    else:
        target_path = f"/api/v1/{clean_path}"
    query = request.META.get("QUERY_STRING", "")
    url_path = f"{target_path}?{query}" if query else target_path

    fwd_headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() not in _HOP_BY_HOP_HEADERS and not k.lower().startswith("cookie")
    }
    body = request.body if request.method in {"POST", "PUT", "PATCH"} else b""

    try:
        client = get_go_client()
        upstream = await client.request(
            request.method,
            url_path,
            headers=fwd_headers,
            content=body if body else None,
        )
    except Exception as exc:
        logger.debug("Go Core proxy offline (%s %s): %s", request.method, url_path, exc)
        return django_json(
            {
                "online": False,
                "error": f"Go Core backend unreachable at {ARTEX_BASE_URL}: {exc}",
                "upstream_url": f"{ARTEX_BASE_URL}{target_path}",
            },
            status=503,
        )

    resp = HttpResponse(
        upstream.content,
        status=upstream.status_code,
        content_type=upstream.headers.get("content-type", "application/json"),
    )
    return resp
