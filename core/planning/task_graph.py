"""
Task Dependency Graph (TDG) for HunterAI
تخطيط استراتيجي مع إمكانية الرجوع للخلف (Backtracking)
يدعم غير المتزامن (async)، السجلات، والتكوينات المركزية
"""
from __future__ import annotations

import asyncio
import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from core.config.settings import config
from core.exceptions import TDGError, HunterAIError
from core.logging.logger import logger


class TaskStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    BLOCKED = "blocked"
    FAILED = "failed"
    BYPASSED = "bypassed"
    COMPLETED = "completed"


@dataclass
class TaskNode:
    task_id: str
    name: str
    technique: str
    target: str
    status: TaskStatus = TaskStatus.PENDING
    dependencies: List[str] = field(default_factory=list)
    dependents: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    failure_reason: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 3
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "TaskNode":
        d["status"] = TaskStatus(d["status"])
        return cls(**d)


class TaskDependencyGraph:
    """
    مدير الرسم البياني لتبعية المهام.
    يسمح بالتخطيط الديناميكي، الرجوع للخلف، وتجربة مسارات بديلة.
    """

    def __init__(self, graph_id: str = "default", storage_path: Optional[str] = None):
        self.graph_id = graph_id
        self.storage_path = Path(storage_path or config.tdg.storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self._nodes: Dict[str, TaskNode] = {}
        self._edges: Dict[str, Set[str]] = {}  # task_id -> set of dependent task_ids
        self._reverse_edges: Dict[str, Set[str]] = {}  # task_id -> set of dependency task_ids
        self._lock = asyncio.Lock()
        self._load_state()

    def _load_state(self) -> None:
        """تحميل حالة الرسم البياني من القرص."""
        path = self.storage_path / f"{self.graph_id}.json"
        if path.exists():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._nodes = {tid: TaskNode.from_dict(n) for tid, n in data.get("nodes", {}).items()}
                self._edges = {tid: set(d) for tid, d in data.get("edges", {}).items()}
                self._rebuild_reverse_edges()
                logger.info(f"[TDG] تم تحميل الرسم البياني '{self.graph_id}' ({len(self._nodes)} مهمة)")
            except Exception as e:
                logger.warning(f"[TDG] فشل تحميل الرسم البياني: {e}")
        else:
            logger.info(f"[TDG] إنشاء رسم بياني جديد: '{self.graph_id}'")

    def _rebuild_reverse_edges(self) -> None:
        """إعادة بناء الحواف العكسية."""
        self._reverse_edges = {}
        for tid, deps in self._edges.items():
            self._reverse_edges.setdefault(tid, set())
            for dep in deps:
                self._reverse_edges.setdefault(dep, set()).add(tid)

    async def _save_state_async(self) -> None:
        """حفظ حالة الرسم البياني بشكل غير متزامن."""
        path = self.storage_path / f"{self.graph_id}.json"
        data = {
            "nodes": {tid: node.to_dict() for tid, node in self._nodes.items()},
            "edges": {tid: list(deps) for tid, deps in self._edges.items()},
        }
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._write_json, path, data)

    def _write_json(self, path: Path, data: Dict[str, Any]) -> None:
        """كتابة بيانات JSON إلى ملف (للاستخدام في executor)."""
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def save(self) -> None:
        """حفظ متزامن."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self._save_state_async())
        finally:
            loop.close()

    async def add_task_async(
        self,
        name: str,
        technique: str,
        target: str,
        dependencies: Optional[List[str]] = None,
        task_id: Optional[str] = None,
    ) -> str:
        """إضافة مهمة بشكل غير متزامن."""
        async with self._lock:
            return self._add_task_sync(name, technique, target, dependencies, task_id)

    def add_task(
        self,
        name: str,
        technique: str,
        target: str,
        dependencies: Optional[List[str]] = None,
        task_id: Optional[str] = None,
    ) -> str:
        """إضافة مهمة بشكل متزامن."""
        return self._add_task_sync(name, technique, target, dependencies, task_id)

    def _add_task_sync(
        self,
        name: str,
        technique: str,
        target: str,
        dependencies: Optional[List[str]] = None,
        task_id: Optional[str] = None,
    ) -> str:
        tid = task_id or f"task-{uuid.uuid4().hex[:8]}"
        deps = dependencies or []

        # التحقق من وجود التبعيات
        for dep in deps:
            if dep not in self._nodes:
                raise TDGError(f"التبعية '{dep}' غير موجودة", task_id=tid)

        # التحقق من الدورات (cycle detection)
        if self._would_create_cycle(tid, deps):
            raise TDGError(f"إضافة المهمة '{tid}' ست创建 دورة في الرسم البياني", task_id=tid)

        node = TaskNode(
            task_id=tid,
            name=name,
            technique=technique,
            target=target,
            dependencies=deps,
        )
        self._nodes[tid] = node
        self._edges[tid] = set()
        self._reverse_edges[tid] = set(deps)

        for dep in deps:
            if dep in self._edges:
                self._edges[dep].add(tid)

        logger.debug(f"[TDG] أضيفت مهمة '{tid}': {name} ({technique}) للهدف {target}")
        return tid

    def _would_create_cycle(self, new_id: str, dependencies: List[str]) -> bool:
        """التحقق مما إذا كانت إضافة المهمة ستخلق دورة."""
        visited = set()

        def dfs(node_id: str) -> bool:
            if node_id == new_id:
                return True
            if node_id in visited:
                return False
            visited.add(node_id)
            for dep in self._reverse_edges.get(node_id, set()):
                if dfs(dep):
                    return True
            return False

        for dep in dependencies:
            if dfs(dep):
                return True
        return False

    def get_ready_tasks(self) -> List[TaskNode]:
        """إرجاع المهام التي اكتملت جميع تبعياتها وجاهزة للتنفيذ."""
        ready = []
        for tid, node in self._nodes.items():
            if node.status == TaskStatus.PENDING:
                deps_ok = all(
                    self._nodes[dep].status == TaskStatus.COMPLETED
                    for dep in node.dependencies
                    if dep in self._nodes
                )
                if deps_ok:
                    ready.append(node)
        return sorted(ready, key=lambda n: n.created_at)

    def mark_completed(self, task_id: str, evidence: Optional[Dict[str, Any]] = None) -> None:
        """تحديد مهمة كمكتملة."""
        if task_id not in self._nodes:
            raise TDGError(f"المهمة '{task_id}' غير موجودة", task_id=task_id)
        node = self._nodes[task_id]
        node.status = TaskStatus.COMPLETED
        if evidence:
            node.evidence = evidence
        node.updated_at = time.time()
        logger.info(f"[TDG]任务 '{task_id}' مكتملة: {node.name}")

    def mark_failed(self, task_id: str, reason: str, retry: bool = True) -> bool:
        """تحديد مهمة كفاشلة مع إمكانية إعادة المحاولة."""
        if task_id not in self._nodes:
            raise TDGError(f"المهمة '{task_id}' غير موجودة", task_id=task_id)
        node = self._nodes[task_id]
        node.retry_count += 1
        node.failure_reason = reason
        node.updated_at = time.time()

        if retry and node.retry_count <= node.max_retries:
            node.status = TaskStatus.PENDING
            logger.warning(f"[TDG] مهمة '{task_id}' فشلت (محاولة {node.retry_count}/{node.max_retries}): {reason}")
            return True

        node.status = TaskStatus.FAILED
        logger.error(f"[TDG] مهمة '{task_id}' فشلت نهائياً: {reason}")

        # حصر المهام التابعة كفشلية أيضاً
        for dependent in list(self._edges.get(task_id, set())):
            if self._nodes[dependent].status in (TaskStatus.PENDING, TaskStatus.IN_PROGRESS):
                self._nodes[dependent].status = TaskStatus.BLOCKED
                self._nodes[dependent].failure_reason = f"blocked by {task_id}: {reason}"
                self._nodes[dependent].updated_at = time.time()
                logger.warning(f"[TDG] مهمة '{dependent}' محظورة بسبب فشل '{task_id}'")

        return False

    def mark_bypassed(self, task_id: str, bypass_method: str) -> None:
        """تجاوز مهمة باستخدام طريقة بديلة."""
        if task_id not in self._nodes:
            raise TDGError(f"المهمة '{task_id}' غير موجودة", task_id=task_id)
        node = self._nodes[task_id]
        node.status = TaskStatus.BYPASSED
        node.evidence["bypass_method"] = bypass_method
        node.updated_at = time.time()
        logger.info(f"[TDG]任务 '{task_id}' تجاوزت عبر: {bypass_method}")

    def get_path_to_target(self, target_technique: str) -> List[TaskNode]:
        """إرجاع سلسلة المهام التي تؤدي إلى تقنية الهدف."""
        path = []
        visited = set()

        def dfs(node: TaskNode) -> None:
            if node.task_id in visited:
                return
            visited.add(node.task_id)
            path.append(node)
            for dep_id in node.dependencies:
                if dep_id in self._nodes:
                    dfs(self._nodes[dep_id])

        for node in self._nodes.values():
            if node.technique == target_technique:
                dfs(node)

        return path

    def get_status_summary(self) -> Dict[str, int]:
        """إرجاع ملخص حالة جميع المهام."""
        summary: Dict[str, int] = {s.value: 0 for s in TaskStatus}
        for node in self._nodes.values():
            summary[node.status.value] += 1
        return summary

    def get_task(self, task_id: str) -> Optional[TaskNode]:
        """استرجاع مهمة بالمعرف."""
        return self._nodes.get(task_id)

    def list_tasks(self) -> List[TaskNode]:
        """إرجاع جميع المهام."""
        return list(self._nodes.values())
