"""
Task Dependency Graph (TDG) — Layer 1 of the Pentest Scaffold
==============================================================

رسم بياني ديناميكي لتبعية المهام يُبنى فوق CausalAttackGraph الموجود.
كل مهمة ( Reconnaissance, Service Discovery, Exploit, PrivEsc ... ) عقدة
في الرسم البياني مع حالة دورة حياة وعلاقات تبعية، ويدعم backtracking
(tجربة فرع بديل لو فرع فشل) لمنع وقوع الوكيل في فخ "العمق أولاً".

Design goals:
- لا يحل محل CausalAttackGraph، بل يمده (المهمات مرتبطة بعقد الهجوم عبر linked_attack_node_id).
- جميع الحالات مستمرة وقابلة للتصدير (JSON / dict) لعرضها في الـ Dashboard أو استئنافها لاحقاً.
- جاهز للتوصيل بـ ModelRouter / Executor في الطبقات اللاحقة.
"""

from __future__ import annotations

import logging
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Any

from pydantic import BaseModel, Field

from core.attack_graph.graph import CausalAttackGraph
from core.attack_graph.nodes import AttackNode, NodeType

log = logging.getLogger("core.attack_graph.task_graph")


class TaskStatus(str, Enum):
    """حالات دورة حياة المهمة"""
    PENDING = "pending"        # منتظرة依赖ياتها
    IN_PROGRESS = "in_progress"  # تُنفذ حالياً بواسطة Executor
    BLOCKED = "blocked"        # معلقة بسبب依赖ية غير منتهية
    DONE = "done"              # منجزة بنجاح
    FAILED = "failed"          # فاشلة واستنفدت البدائل
    SKIPPED = "skipped"        # تُخطط للتجاوز لأن بديلاً أُنجز أو لا حاجة لها


class TaskPriority(int, Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class TaskEdge:
    """رابط تبعية بين مهمتين"""
    source_task_id: str      # المهمة التي يجب أن تنتهي أولاً
    target_task_id: str      # المهمة التي تعتمد على المصدر
    relation: str = "prerequisite"  # prerequisite | parallel | alternative


class TaskNode(BaseModel):
    """عقدة مهمة في الرسم البياني"""
    id: str = Field(default_factory=lambda: f"TASK-{uuid.uuid4().hex[:8]}")
    title: str
    description: str = ""
    status: TaskStatus = TaskStatus.PENDING
    priority: TaskPriority = TaskPriority.MEDIUM

    # معرّفات المهام التي يجب أن تُنجز قبل هذه المهمة
    depends_on: List[str] = Field(default_factory=list)
    # مهام بديلة تُجرب لو فشلت هذه المهمة (يدعم backtracking)
    alternatives: List[str] = Field(default_factory=list)

    # ربط مهمة الاختبار بعقدة في رسم الهجوم القمي (Asset, Service, Endpoint, Vulnerability...)
    linked_attack_node_id: Optional[str] = None

    # نتائج التنفيذ
    result_summary: str = ""
    evidence: List[str] = Field(default_factory=list)
    failure_reason: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 2

    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None

    def mark_started(self) -> None:
        self.status = TaskStatus.IN_PROGRESS
        self.started_at = time.time()
        self.updated_at = time.time()

    def to_tdg_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class TaskDependencyGraph:
    """
    مديري رسم بياني للمهمات مع تبعيات و backtracking.
    """

    def __init__(self, attack_graph: Optional[CausalAttackGraph] = None):
        self.attack_graph = attack_graph or CausalAttackGraph()
        self.tasks: Dict[str, TaskNode] = {}
        # source_task_id -> [TaskEdge]
        self.edges: Dict[str, List[TaskEdge]] = defaultdict(list)
        # target_task_id -> [TaskEdge] (عكس الاتجاه للبحث السريع عن dependents)
        self._reverse_edges: Dict[str, List[TaskEdge]] = defaultdict(list)

    # ------------------------------------------------------------------ #
    # CRUD للمهمات
    # ------------------------------------------------------------------ #
    def add_task(self, task: TaskNode) -> TaskNode:
        self.tasks[task.id] = task
        log.debug(f"[TDG] Added task {task.id}: {task.title}")
        return task

    def get_task(self, task_id: str) -> Optional[TaskNode]:
        return self.tasks.get(task_id)

    def remove_task(self, task_id: str) -> bool:
        if task_id not in self.tasks:
            return False
        # إزالة الحواف المرتبطة
        self.edges.pop(task_id, None)
        for src in list(self.edges.keys()):
            self.edges[src] = [e for e in self.edges[src] if e.target_task_id != task_id]
        self._reverse_edges.pop(task_id, None)
        for tgt in list(self._reverse_edges.keys()):
            self._reverse_edges[tgt] = [e for e in self._reverse_edges[tgt] if e.source_task_id != task_id]
        # إزالة من depends_on في المهام الأخرى
        for t in self.tasks.values():
            if task_id in t.depends_on:
                t.depends_on.remove(task_id)
        self.tasks.pop(task_id)
        log.debug(f"[TDG] Removed task {task_id}")
        return True

    # ------------------------------------------------------------------ #
    # العلاقات بين المهام
    # ------------------------------------------------------------------ #
    def add_dependency(self, source_task_id: str, target_task_id: str,
                       relation: str = "prerequisite") -> None:
        """
        target تعتمد على source: يجب أن تنتهي source قبل أن تبدأ target.
        """
        if source_task_id not in self.tasks:
            raise KeyError(f"Source task '{source_task_id}' not found.")
        if target_task_id not in self.tasks:
            raise KeyError(f"Target task '{target_task_id}' not found.")

        edge = TaskEdge(source_task_id, target_task_id, relation=relation)
        self.edges[source_task_id].append(edge)
        self._reverse_edges[target_task_id].append(edge)

        if source_task_id not in self.tasks[target_task_id].depends_on:
            self.tasks[target_task_id].depends_on.append(source_task_id)

        log.debug(f"[TDG] Dependency: {source_task_id} -> {target_task_id} ({relation})")

    def add_alternative(self, failed_task_id: str, alternative_task_id: str) -> None:
        """
        إضافة مهمة بديلة تُنفذ لو فشلت المهمة الأساسية.
        تُستخدم في backtracking عندما يُبلغ Executor/Reviewer بفشل task.
        """
        if failed_task_id not in self.tasks:
            raise KeyError(f"Failed task '{failed_task_id}' not found.")
        if alternative_task_id not in self.tasks:
            raise KeyError(f"Alternative task '{alternative_task_id}' not found.")
        if alternative_task_id not in self.tasks[failed_task_id].alternatives:
            self.tasks[failed_task_id].alternatives.append(alternative_task_id)
            log.debug(f"[TDG] Alternative for {failed_task_id}: {alternative_task_id}")

    def link_to_attack_node(self, task_id: str, attack_node_id: str) -> None:
        task = self.get_task(task_id)
        if not task:
            raise KeyError(f"Task '{task_id}' not found.")
        if attack_node_id not in self.attack_graph.nodes:
            raise KeyError(f"Attack node '{attack_node_id}' not found.")
        task.linked_attack_node_id = attack_node_id
        task.updated_at = time.time()

    def set_priority(self, task_id: str, priority: TaskPriority) -> None:
        task = self.get_task(task_id)
        if task:
            task.priority = priority
            task.updated_at = time.time()

    # ------------------------------------------------------------------ #
    # تخطيط المهام الجاهزة للتنفيذ
    # ------------------------------------------------------------------ #
    def get_ready_tasks(self) -> List[TaskNode]:
        """
        إرجاع المهام التي tutte依赖ياتها منتهية (DONE) وهي PENDING حالياً،
        مرتبة حسب الأولوية تنازلياً.
        """
        ready: List[TaskNode] = []
        for task in self.tasks.values():
            if task.status != TaskStatus.PENDING:
                continue
            deps_done = all(
                (self.tasks.get(dep_id) or TaskNode(title="missing-dep", status=TaskStatus.PENDING)).status == TaskStatus.DONE
                for dep_id in task.depends_on
            )
            if deps_done:
                ready.append(task)
        ready.sort(key=lambda t: t.priority.value, reverse=True)
        return ready

    def get_blocked_tasks(self) -> List[TaskNode]:
        return [t for t in self.tasks.values() if t.status == TaskStatus.BLOCKED]

    def get_in_progress_tasks(self) -> List[TaskNode]:
        return [t for t in self.tasks.values() if t.status == TaskStatus.IN_PROGRESS]

    def get_failed_tasks(self) -> List[TaskNode]:
        return [t for t in self.tasks.values() if t.status == TaskStatus.FAILED]

    def get_blocked_reason(self, task_id: str) -> Optional[str]:
        task = self.get_task(task_id)
        if not task or task.status != TaskStatus.BLOCKED:
            return None
        for dep_id in task.depends_on:
            dep = self.get_task(dep_id)
            if dep and dep.status in (TaskStatus.FAILED, TaskStatus.PENDING):
                return f"Blocked by dependency '{dep_id}' ({dep.status.value if dep else 'missing'})"
        return "Blocked (unknown reason)"

    # ------------------------------------------------------------------ #
    # تحديث الحالات
    # ------------------------------------------------------------------ #
    def mark_started(self, task_id: str) -> None:
        task = self.get_task(task_id)
        if not task:
            raise KeyError(f"Task '{task_id}' not found.")
        task.mark_started()
        log.info(f"[TDG] Task {task_id} started: {task.title}")

    def mark_done(self, task_id: str, summary: str = "",
                  evidence: Optional[List[str]] = None) -> None:
        task = self.get_task(task_id)
        if not task:
            raise KeyError(f"Task '{task_id}' not found.")
        task.status = TaskStatus.DONE
        task.result_summary = summary
        task.evidence = evidence or []
        task.completed_at = time.time()
        task.updated_at = time.time()
        log.info(f"[TDG] Task {task_id} DONE: {summary[:100]}")

    def mark_failed(self, task_id: str, reason: str,
                    try_alternative: bool = True) -> Optional[str]:
        """
        وضع المهمة كفاشلة.
        إذا كان هناك بديل بديل (alternative) ولم تتجاوز الحد الأقصى للمحاولات،
        تُعاد معرّف المهمة البديلة للـ backtracking (يُنفذها Executor بدلاً منها).
        تُرجع None إذا استنفدت جميع الخيارات.
        """
        task = self.get_task(task_id)
        if not task:
            raise KeyError(f"Task '{task_id}' not found.")

        task.failure_reason = reason
        task.retry_count += 1
        task.updated_at = time.time()

        # هل نجرّب بديلاً؟
        if (try_alternative
                and task.retry_count <= task.max_retries
                and task.alternatives):
            for alt_id in task.alternatives:
                alt = self.get_task(alt_id)
                if alt and alt.status == TaskStatus.PENDING:
                    task.status = TaskStatus.SKIPPED
                    log.info(f"[TDG] Backtracking: {task_id} failed -> trying alternative {alt_id}")
                    return alt_id

        # لا بدائل متاحة أو استنفدت المحاولات
        task.status = TaskStatus.FAILED
        task.completed_at = time.time()
        log.warning(f"[TDG] Task {task_id} FAILED: {reason}")
        return None

    def mark_blocked(self, task_id: str, reason: str = "") -> None:
        task = self.get_task(task_id)
        if not task:
            raise KeyError(f"Task '{task_id}' not found.")
        task.status = TaskStatus.BLOCKED
        if reason:
            task.failure_reason = reason  # إعادة استخدام الحقل لسبب الحظر مؤقتاً
        task.updated_at = time.time()

    # ------------------------------------------------------------------ #
    # إحصائيات وتصدير
    # ------------------------------------------------------------------ #
    def get_completion_stats(self) -> Dict[str, Any]:
        total = len(self.tasks)
        if total == 0:
            return {
                "total": 0, "done": 0, "failed": 0,
                "pending": 0, "in_progress": 0, "blocked": 0,
                "skipped": 0, "completion_rate": 0.0,
            }
        statuses: Dict[str, int] = {}
        for t in self.tasks.values():
            statuses[t.status.value] = statuses.get(t.status.value, 0) + 1
        done = statuses.get("done", 0)
        return {
            "total": total,
            "done": done,
            "failed": statuses.get("failed", 0),
            "pending": statuses.get("pending", 0),
            "in_progress": statuses.get("in_progress", 0),
            "blocked": statuses.get("blocked", 0),
            "skipped": statuses.get("skipped", 0),
            "completion_rate": round(done / total * 100, 2),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tasks": {tid: t.to_tdg_dict() for tid, t in self.tasks.items()},
            "edges": {
                src: [{"target": e.target_task_id, "relation": e.relation}
                      for e in edgelist]
                for src, edgelist in self.edges.items()
            },
            "stats": self.get_completion_stats(),
        }
