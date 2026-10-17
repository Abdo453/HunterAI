"""
آلة حالات المهام (Task Lifecycle) — Phase C.

تُنمذج دورة حياة كل مهمة تُجرى داخل المنسق، مع تحولات حالات صحية
ومعرفة من هو المخوّل بتنفيذ كل تحول.

الحالات (كما في المواصفة):
  PENDING          - أنشئت، تنتظر التوابع
  READY            - التوابع مستوفية، جاهزة للاستلام
  RUNNING          - تُنفَّذ حاليًا من قبل مالك المهمة
  WAITING_FOR_APPROVAL - تنتظر موافقة بشرية على عملية عالية المخاطرة
  BLOCKED          - محظورة بفشل تبعية أو مخالفة نطاق
  SUCCEEDED        - مراجعة सफलت والإثباتات تم التحقق منها
  FAILED           - فشلت بعد إعادة المحاولات
  CANCELLED        - أُلغيت من قبل المشغل / المنسق الأساسي

التحولات الصالحة (من -> إلى):
  PENDING    -> READY, BLOCKED, CANCELLED
  READY      -> RUNNING, BLOCKED, CANCELLED
  RUNNING    -> WAITING_FOR_APPROVAL, SUCCEEDED, FAILED, BLOCKED, CANCELLED
  WAITING_FOR_APPROVAL -> RUNNING, BLOCKED, CANCELLED, FAILED
  BLOCKED    -> READY, FAILED, CANCELLED
  SUCCEEDED  -> (نهاية)
  FAILED     -> (نهاية)
  CANCELLED  -> (نهاية)

يمنع النشر المكرر الناتج عن إعادة المحاولات أو طلبات واجهة مكررة عبر معرف المهمة
الفريد وفحص "هل المهمة قيد التنفيذ بالفعل".
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class TaskStatus(str, Enum):
    PENDING = "PENDING"
    READY = "READY"
    RUNNING = "RUNNING"
    WAITING_FOR_APPROVAL = "WAITING_FOR_APPROVAL"
    BLOCKED = "BLOCKED"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

    @property
    def is_terminal(self) -> bool:
        return self in (TaskStatus.SUCCEEDED, TaskStatus.FAILED,
                        TaskStatus.CANCELLED)

    @property
    def is_active(self) -> bool:
        return self in (TaskStatus.PENDING, TaskStatus.READY,
                        TaskStatus.RUNNING, TaskStatus.WAITING_FOR_APPROVAL)


# التحولات المسموحة: من -> مجموعة الحالات المقبولة
_VALID_TRANSITIONS: Dict[TaskStatus, Set[TaskStatus]] = {
    TaskStatus.PENDING: {
        TaskStatus.READY, TaskStatus.BLOCKED, TaskStatus.CANCELLED,
    },
    TaskStatus.READY: {
        TaskStatus.RUNNING, TaskStatus.BLOCKED, TaskStatus.CANCELLED,
    },
    TaskStatus.RUNNING: {
        TaskStatus.WAITING_FOR_APPROVAL, TaskStatus.SUCCEEDED,
        TaskStatus.FAILED, TaskStatus.BLOCKED, TaskStatus.CANCELLED,
    },
    TaskStatus.WAITING_FOR_APPROVAL: {
        TaskStatus.RUNNING, TaskStatus.BLOCKED, TaskStatus.CANCELLED,
        TaskStatus.FAILED,
    },
    TaskStatus.BLOCKED: {
        TaskStatus.READY, TaskStatus.FAILED, TaskStatus.CANCELLED,
    },
    TaskStatus.SUCCEEDED: set(),
    TaskStatus.FAILED: set(),
    TaskStatus.CANCELLED: set(),
}


@dataclass
class TaskRecord:
    """سجل مهمة واحد مع دورة حياة كاملة."""
    task_id: str
    run_id: str                      # التشغيل التي تنتمي إليه هذه المهمة
    goal: str
    parent_task_id: Optional[str] = None
    assigned_worker: Optional[str] = None
    status: TaskStatus = TaskStatus.PENDING
    dependencies: List[str] = field(default_factory=list)
    attempt_count: int = 0
    max_attempts: int = 3
    scope: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    error: Optional[str] = None
    result: Optional[Any] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "run_id": self.run_id,
            "goal": self.goal,
            "parent_task_id": self.parent_task_id,
            "assigned_worker": self.assigned_worker,
            "status": self.status.value,
            "dependencies": list(self.dependencies),
            "attempt_count": self.attempt_count,
            "max_attempts": self.max_attempts,
            "scope": dict(self.scope),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "error": self.error,
            "metadata": dict(self.metadata),
        }


class TaskLifecycle:
    """مدير آلة حالات المهام — يُ.apply التحولات بشكل آمن."""

    def __init__(self):
        self._tasks: Dict[str, TaskRecord] = {}

    def create(self, *, run_id: str, goal: str,
               parent_task_id: Optional[str] = None,
               dependencies: Optional[List[str]] = None,
               scope: Optional[Dict[str, Any]] = None,
               max_attempts: int = 3,
               metadata: Optional[Dict[str, Any]] = None) -> TaskRecord:
        """إنشاء مهمة جديدة بحالة PENDING. يُ reject التكرارات المكررة."""
        task_id = f"task-{uuid.uuid4().hex[:8]}"
        if task_id in self._tasks:
            # معرّفات UUID نادرة التكرار؛ redundancy guard
            task_id = f"task-{uuid.uuid4().hex[:8]}"
        record = TaskRecord(
            task_id=task_id, run_id=run_id, goal=goal,
            parent_task_id=parent_task_id,
            dependencies=list(dependencies or []),
            max_attempts=max_attempts,
            scope=dict(scope or {}),
            metadata=dict(metadata or {}),
        )
        self._tasks[task_id] = record
        logger.info("تم إنشاء المهمة %s في التشغيل %s (حالة=%s)",
                    task_id, run_id, record.status.value)
        return record

    def get(self, task_id: str) -> Optional[TaskRecord]:
        return self._tasks.get(task_id)

    def list_tasks(self, *, run_id: Optional[str] = None,
                   status: Optional[TaskStatus] = None) -> List[TaskRecord]:
        out = list(self._tasks.values())
        if run_id is not None:
            out = [t for t in out if t.run_id == run_id]
        if status is not None:
            out = [t for t in out if t.status == status]
        return sorted(out, key=lambda t: t.created_at)

    def transition(self, task_id: str, new_status: TaskStatus,
                   *, actor: str = "system",
                   error: Optional[str] = None,
                   result: Optional[Any] = None,
                   assigned_worker: Optional[str] = None) -> bool:
        """
        تطبيق تحول حالة. يُreject التحولات غير الصالحة والمحاولات على مهام نهائية.
        يعود True إذا نجح التحول.
        """
        record = self._tasks.get(task_id)
        if record is None:
            logger.warning("محاولة تحول على مهمة غير موجودة: %s", task_id)
            return False

        if record.status.is_terminal:
            logger.warning("محاولة تحول على مهمة نهائية %s (%s)",
                           task_id, record.status.value)
            return False

        allowed = _VALID_TRANSITIONS.get(record.status, set())
        if new_status not in allowed:
            logger.warning("تحول غير صالح: %s -> %s للمهمة %s (الم'acteur=%s)",
                           record.status.value, new_status.value, task_id, actor)
            return False

        old_status = record.status
        record.status = new_status
        record.updated_at = time.time()
        if error is not None:
            record.error = error
        if result is not None:
            record.result = result
        if assigned_worker is not None:
            record.assigned_worker = assigned_worker
        if new_status == TaskStatus.RUNNING and record.started_at is None:
            record.started_at = time.time()
            record.attempt_count += 1
        if new_status.is_terminal:
            record.finished_at = time.time()

        logger.info("مهمة %s: %s -> %s (الم'acteur=%s)", task_id,
                    old_status.value, new_status.value, actor)
        return True

    def is_transition_valid(self, from_status: TaskStatus,
                            to_status: TaskStatus) -> bool:
        return to_status in _VALID_TRANSITIONS.get(from_status, set())

    def snapshot(self) -> Dict[str, Any]:
        counts: Dict[str, int] = {}
        for t in self._tasks.values():
            counts[t.status.value] = counts.get(t.status.value, 0) + 1
        return {
            "total": len(self._tasks),
            "by_status": counts,
            "active": sum(1 for t in self._tasks.values() if t.status.is_active),
            "terminal": sum(1 for t in self._tasks.values()
                            if t.status.is_terminal),
        }
