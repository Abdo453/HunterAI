"""API routes للتحكم في التشغيلات والميزانية — Phase 3.

- GET  /api/runs               : قائمة التشغيلات (active_only/kind)
- POST /api/runs/{id}/pause    : إيقاف مؤقت
- POST /api/runs/{id}/resume   : استئناف
- POST /api/runs/{id}/stop     : إيقاف فوري
- GET  /api/budget             : لقطة التكلفة والميزانية
- POST /api/budget             : تحديث سقوف الميزانية
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from core.cost_budget import GLOBAL_COST_CONTROLLER, Budget
from core.run_control import GLOBAL_RUN_CONTROLLER, RunController

logger = logging.getLogger(__name__)


class BudgetUpdate(BaseModel):
    per_run_usd: Optional[float] = Field(default=None, ge=0)
    per_solver_usd: Optional[float] = Field(default=None, ge=0)
    per_day_usd: Optional[float] = Field(default=None, ge=0)


def create_run_control_router(
    controller: Optional[RunController] = None,
) -> APIRouter:
    ctl = controller or GLOBAL_RUN_CONTROLLER
    router = APIRouter(prefix="/api/runs", tags=["runs"])

    @router.get("")
    async def list_runs(kind: Optional[str] = None, active_only: bool = False,
                        limit: int = 100):
        return {"runs": ctl.list_runs(kind=kind, active_only=active_only, limit=limit)}

    @router.post("/{run_id}/pause")
    async def pause_run(run_id: str):
        if not ctl.pause(run_id):
            raise HTTPException(404, "تشغيل غير موجود أو لا يقبل الإيقاف المؤقت")
        return {"run_id": run_id, "state": "paused"}

    @router.post("/{run_id}/resume")
    async def resume_run(run_id: str):
        if not ctl.resume(run_id):
            raise HTTPException(404, "تشغيل غير موجود أو ليس متوقفًا مؤقتًا")
        return {"run_id": run_id, "state": "running"}

    @router.post("/{run_id}/stop")
    async def stop_run(run_id: str):
        ok = await ctl.stop(run_id)
        if not ok:
            raise HTTPException(404, "تشغيل غير موجود أو منتهٍ")
        return {"run_id": run_id, "state": "stopped"}

    return router


def create_budget_router(
    controller: Any = None,
) -> APIRouter:
    cost = controller or GLOBAL_COST_CONTROLLER
    router = APIRouter(prefix="/api/budget", tags=["budget"])

    @router.get("")
    async def budget_snapshot():
        return cost.snapshot()

    @router.post("")
    async def update_budget(req: BudgetUpdate):
        cost.budget = Budget(
            per_run_usd=req.per_run_usd,
            per_solver_usd=req.per_solver_usd,
            per_day_usd=req.per_day_usd,
        )
        return cost.snapshot()

    return router
