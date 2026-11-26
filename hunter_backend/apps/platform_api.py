"""Unified /api/platform/*, /api/csrf, SSE telemetry stream, and :7071 Artex proxy."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any, Dict, List, Optional

from django.http import HttpRequest, HttpResponse, JsonResponse, StreamingHttpResponse
from django.middleware.csrf import get_token
from django.views.decorators.http import require_GET, require_http_methods
from pydantic import BaseModel, Field
from rest_framework.views import APIView

from core.copilot_service import detect_live_providers
from core.evidence_store import EvidenceStore
from core.platform_store import get_platform_store
from core.run_control import GLOBAL_RUN_CONTROLLER
from hunter_backend.apps.common import (
    django_err,
    django_json,
    err_json,
    format_sse,
    ok_json,
    parse_json_body,
    parse_query_bool,
    parse_query_float,
    parse_query_int,
    validate_model,
)
from hunter_backend.runtime import (
    ARTEX_BASE_URL,
    EVENT_BUS,
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
        return ok_json(store.get_context())

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
        return ok_json(updated)


@require_GET
async def platform_overview_view(request: HttpRequest) -> JsonResponse:
    """GET /api/platform/overview: aggregated platform state, providers, runs, and Artex probe."""
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

    try:
        providers = await asyncio.to_thread(detect_live_providers)
    except Exception:
        providers = []

    try:
        from tools.tool_manager import ToolManager

        tm = ToolManager()
        tools = tm.get_available_tools()
    except Exception:
        tools = {}

    artex = await probe_artex_health()
    return django_json(
        {
            "context": ctx,
            "active_engagement": active_eng,
            "active_run": active_run,
            "engagements": engagements,
            "runs": runs,
            "pending_approvals": approvals,
            "unread_notifications": notifications,
            "recent_events": recent_events,
            "providers": providers,
            "tools": tools,
            "artex": artex,
            "stats": {
                "engagement_count": len(engagements),
                "run_count": len(runs),
                "active_run_count": sum(1 for r in runs if r.get("status") in {"running", "paused"}),
                "pending_approval_count": len(approvals),
                "unread_notification_count": len(notifications),
                "latest_seq": store.latest_seq(),
            },
        }
    )


class PlatformEngagementsView(APIView):
    """GET / POST /api/platform/engagements."""

    def get(self, request: Any) -> Any:
        store = ensure_platform_wiring()
        limit = parse_query_int(request.GET.get("limit"), 100)
        items = store.list_engagements(limit=limit)
        return ok_json({"engagements": items, "count": len(items)})

    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        req, verr = validate_model(EngagementCreateRequest, data, error_status=422)
        if verr is not None:
            return err_json("Invalid engagement payload", status=422, extra=json.loads(verr.content))
        store = ensure_platform_wiring()
        in_scope = req.in_scope if req.in_scope is not None else [req.target]
        eng = store.upsert_engagement(
            name=req.name or req.target,
            target=req.target,
            in_scope=in_scope,
            out_of_scope=req.out_of_scope or [],
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
        return ok_json({"engagement": eng, **eng}, status=201)


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

        if self.action == "pause":
            ok = GLOBAL_RUN_CONTROLLER.pause(run_id)
            updated = store.update_run(run_id, status="paused") or run
            store.append_event(
                "run.paused",
                run_id=run_id,
                engagement_id=run.get("engagement_id"),
                source="platform",
                payload={"run_id": run_id, "controller_ack": ok},
            )
            return ok_json({"ok": True, "run": updated, "status": "paused"})

        if self.action == "resume":
            ok = GLOBAL_RUN_CONTROLLER.resume(run_id)
            updated = store.update_run(run_id, status="running") or run
            store.append_event(
                "run.resumed",
                run_id=run_id,
                engagement_id=run.get("engagement_id"),
                source="platform",
                payload={"run_id": run_id, "controller_ack": ok},
            )
            return ok_json({"ok": True, "run": updated, "status": "running"})

        ok = GLOBAL_RUN_CONTROLLER.stop(run_id, force=True)
        updated = store.update_run(run_id, status="stopped") or run
        store.append_event(
            "run.stopped",
            run_id=run_id,
            engagement_id=run.get("engagement_id"),
            source="platform",
            payload={"run_id": run_id, "controller_ack": ok},
        )
        return ok_json({"ok": True, "run": updated, "status": "stopped"})


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
                yield format_sse(str(ev.get("type") or "platform.event"), ev, event_id=seq)

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
                yield format_sse(str(ev.get("type") or "platform.event"), ev, event_id=seq)
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

    decision = req.decision.strip().lower()
    if decision not in {"approved", "rejected"}:
        return django_err("decision must be 'approved' or 'rejected'", status=400)

    store = ensure_platform_wiring()
    existing = store.get_approval(approval_id)
    if not existing:
        return django_err(f"Approval {approval_id} not found", status=404)

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
        execution = await execute_approved_action(updated)

    return django_json({"ok": True, "approval": updated, "execution": execution})


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
    return django_json(await probe_artex_health())


@require_http_methods(["GET", "POST", "PUT", "DELETE", "PATCH"])
async def artex_go_proxy_view(request: HttpRequest, path: str) -> HttpResponse:
    """Async HTTP proxy forwarding /api/platform/artex/* cleanly to Go Core (:7071)."""
    if request.method not in _PROXY_ALLOWED_METHODS:
        return django_err("Method not allowed", status=405)

    clean_path = (path or "").lstrip("/")
    if not _is_safe_proxy_subpath(clean_path):
        return django_err("Invalid proxy subpath", status=400)

    target_path = f"/api/{clean_path}" if not clean_path.startswith("api/") else f"/{clean_path}"
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
