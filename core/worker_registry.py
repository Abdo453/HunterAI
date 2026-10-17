"""
سجل العمال المركزي (Worker Registry) — Phase C.

يُسجّل العمال ويُExpose بيانات وصفية لكل عامل (المعرف، الاسم، الدور، المزود/وقت التشغيل،
الأدوات المتاحة، أنواع المدخلات المدعومة، الحالة الحالية، حدود الموارد، المهمة الحالية،
الصحة). العمال لا يحصلون تلقائيًا على وصول غير مقيد لجميع الأدوات — فقط الأدوات
المصرح بها لكل دور.

هذا السجل يُبنى على المكونات القائمة (BaseAgent، AgentProvider، ToolRegistry)
دون استبدالها.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence

logger = logging.getLogger(__name__)


class WorkerStatus(str):
    IDLE = "idle"
    BUSY = "busy"
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    OFFLINE = "offline"


@dataclass
class WorkerInfo:
    """بيانات وصفية لعامل واحد."""
    worker_id: str
    display_name: str
    role: str                     # مثال: "recon", "web", "report"
    provider_or_runtime: str      # مثال: "claude-cli", "local-model", "builtin"
    available_tools: Sequence[str] = field(default_factory=list)  # tool IDs المصرح بها فقط
    supported_input_types: Sequence[str] = field(default_factory=list)
    status: str = WorkerStatus.IDLE
    resource_limits: Dict[str, Any] = field(default_factory=dict)
    current_task: Optional[str] = None   # task_id أو None
    health: str = WorkerStatus.HEALTHY
    last_heartbeat: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "worker_id": self.worker_id,
            "display_name": self.display_name,
            "role": self.role,
            "provider_or_runtime": self.provider_or_runtime,
            "available_tools": list(self.available_tools),
            "supported_input_types": list(self.supported_input_types),
            "status": self.status,
            "resource_limits": dict(self.resource_limits),
            "current_task": self.current_task,
            "health": self.health,
            "last_heartbeat": self.last_heartbeat,
            "metadata": dict(self.metadata),
        }


@dataclass
class TaskAssignment:
    """تخصيص مهمة لعامل."""
    task_id: str
    worker_id: str
    assigned_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    result: Optional[Any] = None
    error: Optional[str] = None


class WorkerRegistry:
    """
    سجل العمال: تسجيل، استعلام، تخصيص مهام، فحوصات صحة.

    ملاحظة: هذا السجل ينسق التخصيص وليس تنفيذ المهام نفسه — التنفيذ يُوكل إلى
    AgentRuntime / Coordinator (مرحل C اللاحقة).
    """

    def __init__(self, tool_registry: Optional[Any] = None):
        self._workers: Dict[str, WorkerInfo] = {}
        self._assignments: Dict[str, TaskAssignment] = {}  # task_id -> TaskAssignment
        self._worker_tasks: Dict[str, str] = {}  # worker_id -> task_id الحالي
        self._lock = asyncio.Lock()
        self._tool_registry = tool_registry   # مرجع لتحقق الأدوات إن وُجد

    # ── التسجيل والاستعلام ───────────────────────────────────────────────
    def register(self, info: WorkerInfo) -> None:
        self._workers[info.worker_id] = info
        logger.info("تم تسجيل العامل: %s (الدور=%s، الأدوات=%d)",
                    info.worker_id, info.role, len(info.available_tools))

    def get(self, worker_id: str) -> Optional[WorkerInfo]:
        return self._workers.get(worker_id)

    def list_workers(self, *, role: Optional[str] = None,
                     healthy_only: bool = False) -> List[WorkerInfo]:
        out = list(self._workers.values())
        if role:
            out = [w for w in out if w.role == role]
        if healthy_only:
            out = [w for w in out if w.health == WorkerStatus.HEALTHY
                   and w.status != WorkerStatus.OFFLINE]
        return sorted(out, key=lambda w: w.worker_id)

    def ids_by_role(self, role: str) -> List[str]:
        return [w.worker_id for w in self.list_workers(role=role)]

    # ── حالات العمل ──────────────────────────────────────────────────────
    def set_status(self, worker_id: str, status: str) -> bool:
        w = self._workers.get(worker_id)
        if w is None:
            return False
        w.status = status
        return True

    def set_health(self, worker_id: str, health: str) -> bool:
        w = self._workers.get(worker_id)
        if w is None:
            return False
        w.health = health
        w.last_heartbeat = time.time()
        return True

    def heartbeat(self, worker_id: str) -> bool:
        w = self._workers.get(worker_id)
        if w is None:
            return False
        w.last_heartbeat = time.time()
        w.health = WorkerStatus.HEALTHY
        return True

    # ── تخصيص المهام ────────────────────────────────────────────────────
    def assign(self, task_id: str, worker_id: str) -> bool:
        """تخصيص مهمة لعامل. يعود False إذا العامل مشغول أو غير موجود."""
        w = self._workers.get(worker_id)
        if w is None:
            return False
        if w.status == WorkerStatus.BUSY:
            return False
        if worker_id in self._worker_tasks:
            return False  # العامل لديه مهمة بالفعل

        w.status = WorkerStatus.BUSY
        w.current_task = task_id
        self._worker_tasks[worker_id] = task_id
        self._assignments[task_id] = TaskAssignment(
            task_id=task_id, worker_id=worker_id,
            started_at=time.time())
        logger.info("تم تخصيص المهمة %s للعامل %s", task_id, worker_id)
        return True

    def complete(self, task_id: str, result: Optional[Any] = None,
                 error: Optional[str] = None) -> bool:
        """إنهاء مهمة وتحرير العامل."""
        a = self._assignments.get(task_id)
        if a is None:
            return False
        worker_id = a.worker_id
        w = self._workers.get(worker_id)
        if w is not None:
            w.status = WorkerStatus.IDLE
            w.current_task = None
            self._worker_tasks.pop(worker_id, None)
        a.finished_at = time.time()
        a.result = result
        a.error = error
        logger.info("انتهت المهمة %s (%s)", task_id,
                    "سUCCESS" if result is not None and error is None else "FAILED")
        return True

    def assignment(self, task_id: str) -> Optional[TaskAssignment]:
        return self._assignments.get(task_id)

    def worker_for_task(self, task_id: str) -> Optional[str]:
        a = self._assignments.get(task_id)
        return a.worker_id if a else None

    def is_worker_busy(self, worker_id: str) -> bool:
        w = self._workers.get(worker_id)
        return bool(w and w.status == WorkerStatus.BUSY)

    # ── مراقبة التوافر ──────────────────────────────────────────────────
    def available_workers(self, *, role: Optional[str] = None) -> List[WorkerInfo]:
        """عمال غير مشغولين وسليمين (للاختيار من قبل المنسق)."""
        out = []
        for w in self.list_workers(role=role):
            if w.status == WorkerStatus.IDLE and w.health == WorkerStatus.HEALTHY:
                out.append(w)
        return sorted(out, key=lambda w: w.worker_id)

    def snapshot(self) -> Dict[str, Any]:
        return {
            "workers": [w.to_dict() for w in self.list_workers()],
            "total": len(self._workers),
            "busy": sum(1 for w in self._workers.values()
                        if w.status == WorkerStatus.BUSY),
            "healthy": sum(1 for w in self._workers.values()
                           if w.health == WorkerStatus.HEALTHY),
            "active_assignments": len([
                a for a in self._assignments.values() if a.finished_at is None]),
        }
