"""
واجهات API للتبويبات الجديدة في الواجهة الأمامية (Phase F/G/H).
تجمع: MCP، Sandbox، Scope Enforcement، CTF Flags، Extensions.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["phase-fg"])

# =====================================================================
# MCP SERVERS
# =====================================================================

class MCPServerConfig(BaseModel):
    server_id: str
    name: str
    transport: str = "stdio"
    command: Optional[str] = None
    args: List[str] = []
    endpoint: Optional[str] = None
    enabled: bool = True


class MCPCallRequest(BaseModel):
    server_id: str
    tool_name: str
    arguments: Dict[str, Any] = {}


# مؤقتًا: قائمة في الذاكرة حتى يتم ربطها بـ MCPClientManager الحقيقي
_MCP_SERVERS: Dict[str, Dict[str, Any]] = {}
_MCP_CLIENTS: Dict[str, Any] = {}


@router.get("/mcp/servers")
async def mcp_list_servers():
    return {"servers": list(_MCP_SERVERS.values())}


@router.post("/mcp/servers")
async def mcp_add_server(cfg: MCPServerConfig):
    _MCP_SERVERS[cfg.server_id] = cfg.dict()
    return {"status": "added", "server_id": cfg.server_id}


@router.post("/mcp/call")
async def mcp_call_tool(req: MCPCallRequest):
    # محاولة استدعاء حقيقي عبر MCPClientManager إذا كان متاحًا
    try:
        from core.global_state import GLOBAL_COORDINATOR
        # placeholder: لا يوجد MCPClientManager مكتمل بعد في GlobalState
        return {"ok": False, "error": "MCP client not wired yet", "server_id": req.server_id, "tool_name": req.tool_name}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc), "server_id": req.server_id, "tool_name": req.tool_name}


# =====================================================================
# SANDBOX
# =====================================================================

class SandboxRunRequest(BaseModel):
    command: List[str]
    timeout_s: float = 60.0
    max_output_bytes: int = 1_000_000


@router.get("/sandbox/health")
async def sandbox_health():
    try:
        from core.sandbox import LocalSandbox
        sb = LocalSandbox()
        ok = await sb.health_check()
        return {"ok": ok, "status": "ready" if ok else "unavailable"}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)}


@router.post("/sandbox/run")
async def sandbox_run(req: SandboxRunRequest):
    try:
        from core.sandbox import LocalSandbox
        sb = LocalSandbox()
        result = await sb.run(
            req.command,
            timeout_s=req.timeout_s,
            max_output_bytes=req.max_output_bytes,
        )
        return {
            "ok": result.ok,
            "exit_code": result.exit_code,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "duration_s": result.duration_s,
            "error": result.error,
            "error_category": result.error_category,
        }
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc), "error_category": "EXECUTION_ERROR"}


# =====================================================================
# SCOPE ENFORCEMENT
# =====================================================================

class ScopeConfig(BaseModel):
    in_scope: List[str] = []
    out_of_scope: List[str] = []


class ScopeCheckRequest(BaseModel):
    target: str


_SCOPE_STATE: Dict[str, Any] = {"in_scope": [], "out_of_scope": []}


@router.get("/scope")
async def scope_get():
    return _SCOPE_STATE


@router.post("/scope")
async def scope_set(cfg: ScopeConfig):
    _SCOPE_STATE["in_scope"] = cfg.in_scope
    _SCOPE_STATE["out_of_scope"] = cfg.out_of_scope
    return {"status": "updated", "in_scope": cfg.in_scope, "out_of_scope": cfg.out_of_scope}


@router.post("/scope/check")
async def scope_check(req: ScopeCheckRequest):
    try:
        from core.scope_enforcer import ScopeEnforcer
        from core.scope_guard import ScopeGuard
        guard = ScopeGuard(in_scope=_SCOPE_STATE["in_scope"], out_of_scope=_SCOPE_STATE["out_of_scope"])
        enforcer = ScopeEnforcer(guard)
        allowed, reason = enforcer.enforce_target(req.target)
        return {"allowed": allowed, "reason": reason, "target": req.target}
    except Exception as exc:  # noqa: BLE001
        return {"allowed": False, "reason": str(exc), "target": req.target}


# =====================================================================
# CTF FLAGS
# =====================================================================

class FlagIngestRequest(BaseModel):
    text: str


class FlagSubmitRequest(BaseModel):
    platform_url: str
    token: str
    challenge_id: str = ""


@router.post("/flags/ingest")
async def flags_ingest(req: FlagIngestRequest):
    try:
        from flags.service import FlagService
        svc = FlagService()
        fresh = svc.ingest(req.text)
        return {
            "fresh": len(fresh),
            "candidates": [{"value": c.value, "confidence": c.confidence} for c in fresh],
            "progress": svc.progress().to_dict(),
        }
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(500, str(exc))


@router.get("/flags/progress")
async def flags_progress():
    try:
        from flags.service import FlagService
        svc = FlagService()
        return svc.progress().to_dict()
    except Exception as exc:  # noqa: BLE001
        return {"accepted_count": 0, "expected_count": 0, "complete": False}


@router.post("/ctf/submit")
async def ctf_submit(req: FlagSubmitRequest):
    try:
        from ctf.bridge import FlagSubmitter
        from ctf.ctfd import CTFdPlatform
        from flags.service import FlagService
        svc = FlagService()
        # ملء بسيط للاستعراض — في الإنتاج يُجلب من مخزن الفلوغات الحقيقي
        svc.ingest("flag{placeholder}")
        platform = CTFdPlatform(req.platform_url, req.token)
        sub = FlagSubmitter(svc, platform, challenge_id=req.challenge_id)
        summary = sub.submit_pending(dry_run=True)
        return summary.to_dict()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(500, str(exc))


# =====================================================================
# EXTENSIONS
# =====================================================================

class ExtensionInstallRequest(BaseModel):
    path: str


_EXTENSIONS: List[Dict[str, Any]] = []


@router.get("/extensions")
async def extensions_list():
    return {"extensions": _EXTENSIONS}


@router.post("/extensions/install")
async def extensions_install(req: ExtensionInstallRequest):
    try:
        from extensions_ext import ExtensionRegistry, TrustLevel
        reg = ExtensionRegistry(min_trust=TrustLevel.LOW)
        reg.install(req.path)
        _EXTENSIONS.append({"name": req.path, "trust": "LOW", "enabled": True})
        return {"ok": True, "message": f"Installed {req.path}"}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "message": str(exc)}


# =====================================================================
# BURP SUITE (additional UI endpoints)
# =====================================================================

class BurpTargetRequest(BaseModel):
    target: str
    limit: int = 50


class BurpJobRequest(BaseModel):
    target: str
    job_type: str = "passive_scan"


_BURP_STATE: Dict[str, Any] = {"connected": False, "capabilities": {}}


@router.get("/burp/health")
async def burp_health():
    try:
        from core.burp_adapter import GLOBAL_BURP_ADAPTER
        h = await GLOBAL_BURP_ADAPTER.health_check()
        _BURP_STATE["connected"] = h.get("available", False)
        return h
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "reason": str(exc), "status": "degraded"}


@router.get("/burp/capabilities")
async def burp_capabilities():
    try:
        from core.burp_adapter import GLOBAL_BURP_ADAPTER
        caps = await GLOBAL_BURP_ADAPTER.get_available_capabilities()
        _BURP_STATE["capabilities"] = caps.get("operations", {})
        return caps
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "operations": {}, "error": str(exc)}


@router.post("/burp/history")
async def burp_history(req: BurpTargetRequest):
    try:
        from core.burp_adapter import GLOBAL_BURP_ADAPTER
        txs = await GLOBAL_BURP_ADAPTER.retrieve_authorized_http_history(
            target=req.target, limit=req.limit
        )
        return {
            "transactions": [
                {
                    "tx_id": t.tx_id,
                    "target_host": t.target_host,
                    "method": t.method,
                    "url": t.url,
                    "status_code": t.status_code,
                    "tool_source": t.tool_source,
                }
                for t in txs
            ]
        }
    except Exception as exc:  # noqa: BLE001
        return {"transactions": [], "error": str(exc)}


@router.post("/burp/analysis")
async def burp_analysis(req: BurpJobRequest):
    try:
        from core.burp_adapter import GLOBAL_BURP_ADAPTER
        res = await GLOBAL_BURP_ADAPTER.submit_supported_analysis_job(
            target=req.target, job_type=req.job_type
        )
        return res
    except Exception as exc:  # noqa: BLE001
        return {"accepted": False, "job_id": "", "error": str(exc)}


@router.post("/burp/findings")
async def burp_findings():
    try:
        from core.burp_adapter import GLOBAL_BURP_ADAPTER
        findings = await GLOBAL_BURP_ADAPTER.import_supported_findings()
        return {
            "count": len(findings),
            "findings": [f.to_dict() for f in findings],
        }
    except Exception as exc:  # noqa: BLE001
        return {"count": 0, "findings": [], "error": str(exc)}


# Export للربط في app.py
__all__ = ["router"]
