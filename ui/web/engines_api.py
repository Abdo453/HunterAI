"""API routes لمحركات الوكلاء (CLI Engine Workers).

يوفر:
- GET  /api/engines                : قائمة المحركات وقدراتها
- POST /api/engines/selfcheck      : فحص صحة كل المحركات المُهيّأة
- POST /api/engines/run            : تشغيل مهمة واحدة عبر محرك (مع الحوكمة)
- GET  /api/engines/workspace/{engine} : آخر ملفات إثبات لمحرك
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from engines.registry import DRIVERS, driver_for
from engines.selfcheck import run_selfcheck
from engines.types import StreamStep
from engines.worker import EngineWorker, EngineWorkerConfig

logger = logging.getLogger(__name__)


class SelfCheckRequest(BaseModel):
    engines: Optional[list] = None          # None = كل المحركات
    profiles: Optional[list] = None         # personal profiles اختيارية


class EngineRunRequest(BaseModel):
    engine: str = "claude"
    target: str = ""
    prompt: str
    model: str = ""
    permission_mode: str = ""
    sandbox_mode: str = ""
    web_access: bool = True
    timeout_s: float = Field(default=1800.0, le=7200.0)
    resume_session: str = ""               # لاستئناف جلسة سابقة
    credential_env: Dict[str, str] = Field(default_factory=dict)
    # نطاق الجلسة: يُبنى ScopeGuard لكل تشغيل من هذه القوائم
    in_scope: list = Field(default_factory=list)
    out_of_scope: list = Field(default_factory=list)


def create_engines_router(
    *,
    policy_gate: Any = None,
    scope_guard: Any = None,
    progress_callback: Any = None,
) -> APIRouter:
    router = APIRouter(prefix="/api/engines", tags=["engines"])
    _active_runs: Dict[str, asyncio.Task] = {}

    @router.get("")
    async def list_engines():
        """قائمة المحركات وقدراتها الحالية."""
        items = []
        for name, drv in DRIVERS.items():
            items.append({
                "engine": name,
                "display_name": drv.display_name or name,
                "capabilities": drv.capabilities,
                "secure_prompt_transport": drv.secure_prompt_transport,
                "supports_resume": drv.supports_resume,
                "supports_streaming": drv.supports_streaming,
            })
        return {"engines": items}

    @router.post("/selfcheck")
    async def selfcheck(req: SelfCheckRequest):
        """فحص صحة المحركات: probe حقيقي بجولة واحدة لكل محرك."""
        report = await run_selfcheck(
            engine_names=req.engines, profiles=req.profiles)
        return report.to_dict()

    @router.post("/run")
    async def run_task(req: EngineRunRequest):
        """تشغيل مهمة عبر محرك CLI — يمرّ عبر ScopeGuard + PolicyGate."""
        if not req.prompt.strip():
            raise HTTPException(status_code=400, detail="prompt مطلوب")
        if req.engine not in DRIVERS:
            raise HTTPException(
                status_code=404,
                detail=f"محرك غير معروف: {req.engine}. المتاح = {sorted(DRIVERS)}")

        cfg = EngineWorkerConfig(
            engine=req.engine,
            model=req.model,
            permission_mode=req.permission_mode,
            sandbox_mode=req.sandbox_mode,
            web_access=req.web_access,
            timeout_s=req.timeout_s,
            credential_env=req.credential_env,
        )
        # نطاق الجلسة: يُبنى guard جديد لكل تشغيل من in_scope/out_of_scope
        guard = scope_guard
        if (req.in_scope or req.out_of_scope):
            try:
                from core.scope_guard import ScopeGuard as _SG
                guard = _SG(
                    in_scope=req.in_scope or ([req.target] if req.target else []),
                    out_of_scope=req.out_of_scope,
                )
            except Exception as exc:  # noqa: BLE001
                raise HTTPException(
                    status_code=400, detail=f"نطاق غير صالح: {exc}") from exc
        elif req.target and guard is None:
            # بدون نطاق صريح ولا guard عام: نرفض (fail-closed)
            raise HTTPException(
                status_code=400,
                detail="حدد in_scope/out_of_scope أو الهدف ضمن نطاق عام معروف")
        worker = EngineWorker(
            cfg,
            policy_gate=policy_gate,
            scope_guard=guard,
            progress_callback=progress_callback,
        )

        from agents.base_agent import AgentTask
        task = AgentTask(
            target=req.target,
            mode="engine",
            extra={"prompt": req.prompt},
        )
        if req.resume_session:
            worker._sessions[req.target] = req.resume_session

        try:
            result = await worker.run(task)
        except Exception as exc:  # noqa: BLE001
            logger.exception("engine run failed")
            raise HTTPException(status_code=500, detail=str(exc)) from exc

        return {
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

    return router
