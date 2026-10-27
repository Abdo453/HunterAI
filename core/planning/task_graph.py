"""
Task Dependency Graph (TDG) for HunterAI
تخطيط استراتيجي مع إمكانية الرجوع للخلف (Backtracking)
"""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


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

    def __init__(self, storage_path: str = "data/task_graphs"):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self._nodes: Dict[str, TaskNode] = {}
        self._edges: Dict[str, Set[str]] = {}  # task_id -> set of dependent task_ids
        self._reverse_edges: Dict[str, Set[str]] = {}  # task_id -> set of dependency task_ids

    def add_task(
        self,
        name: str,
        technique: str,
        target: str,
        dependencies: Optional[List[str]] = None,
        task_id: Optional[str] = None,
    ) -> str:
        tid = task_id or f"task-{uuid.uuid4().hex[:8]}"
        deps = dependencies or []
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

        return tid

    def get_ready_tasks(self) -> List[TaskNode]:
        """إرجاع المهام التي اكتملت جميع dependecies لها وجاهزة للتنفيذ."""
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
        return ready

    def mark_completed(self, task_id: str, evidence: Optional[Dict[str, Any]] = None) -> None:
        if task_id not in self._nodes:
            return
        node = self._nodes[task_id]
        node.status = TaskStatus.COMPLETED
        if evidence:
            node.evidence = evidence
        node.updated_at = time.time()

    def mark_failed(self, task_id: str, reason: str, retry: bool = True) -> bool:
        """تحديد مهمة كفاشلة مع إمكانية إعادة المحاولة أو الرجوع للخلف."""
        if task_id not in self._nodes:
            return False
        node = self._nodes[task_id]
        node.retry_count += 1
        node.failure_reason = reason
        node.updated_at = time.time()

        if retry and node.retry_count <= node.max_retries:
            node.status = TaskStatus.PENDING
            return True

        node.status = TaskStatus.FAILED
        # حصر المهام التابعة كفشلية أيضاً (تأثير متسلسل)
        for dependent in list(self._edges.get(task_id, set())):
            if self._nodes[dependent].status in (TaskStatus.PENDING, TaskStatus.IN_PROGRESS):
                self._nodes[dependent].status = TaskStatus.BLOCKED
                self._nodes[dependent].failure_reason = f"blocked by {task_id}: {reason}"
                self._nodes[dependent].updated_at = time.time()

        return False

    def mark_bypassed(self, task_id: str, bypass_method: str) -> None:
        """تجاوز مهمة باستخدام طريقة بديلة (مثلاً WAF bypass)."""
        if task_id not in self._nodes:
            return
        node = self._nodes[task_id]
        node.status = TaskStatus.BYPASSED
        node.evidence["bypass_method"] = bypass_method
        node.updated_at = time.time()

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
        summary: Dict[str, int] = {s.value: 0 for s in TaskStatus}
        for node in self._nodes.values():
            summary[node.status.value] += 1
        return summary

    def save(self, graph_id: str) -> None:
        path = self.storage_path / f"{graph_id}.json"
        data = {
            "nodes": {tid: node.to_dict() for tid, node in self._nodes.items()},
            "edges": {tid: list(deps) for tid, deps in self._edges.items()},
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def load(self, graph_id: str) -> None:
        path = self.storage_path / f"{graph_id}.json"
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._nodes = {tid: TaskNode.from_dict(n) for tid, n in data.get("nodes", {}).items()}
            self._edges = {tid: set(d) for tid, d in data.get("edges", {}).items()}
            self._reverse_edges = {}
            for tid, deps in self._edges.items():
                self._reverse_edges.setdefault(tid, set())
                for dep in deps:
                    self._reverse_edges.setdefault(dep, set()).add(tid)
