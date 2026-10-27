"""
منسق الوكلاء المتعدد لـ HunterAI مع دعم TDG والذاكرة الثلاثية.
"""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.planning.task_graph import TaskDependencyGraph, TaskStatus, TaskNode
from core.memory.triple_memory import TripleMemory, MemoryType


class AgentRole(str, Enum):
    ORCHESTRATOR = "orchestrator"
    EXECUTOR = "executor"
    REVIEWER = "reviewer"


@dataclass
class OrchestrationTask:
    task_id: str
    target: str
    role: AgentRole
    description: str
    technique: str
    status: str = "pending"
    result: Optional[Dict[str, Any]] = None
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)


class MultiAgentOrchestrator:
    """
    منسق الوكلاء المتعدد مع دعم TDG والذاكرة الثلاثية.
    """

    def __init__(self, graph_id: str = "default"):
        self.graph = TaskDependencyGraph()
        self.memory = TripleMemory()
        self.graph_id = graph_id
        self._tasks: Dict[str, OrchestrationTask] = {}
        self._load_state()

    def _load_state(self) -> None:
        self.graph.load(self.graph_id)

    def _save_state(self) -> None:
        self.graph.save(self.graph_id)

    def create_task(
        self,
        target: str,
        role: AgentRole,
        description: str,
        technique: str,
        dependencies: Optional[List[str]] = None,
    ) -> OrchestrationTask:
        task_id = f"orch-{uuid.uuid4().hex[:8]}"
        graph_tid = self.graph.add_task(
            name=description,
            technique=technique,
            target=target,
            dependencies=dependencies,
            task_id=task_id,
        )
        task = OrchestrationTask(
            task_id=task_id,
            target=target,
            role=role,
            description=description,
            technique=technique,
        )
        self._tasks[task_id] = task
        self._save_state()
        return task

    def get_next_pending_task(self, role: Optional[AgentRole] = None) -> Optional[OrchestrationTask]:
        """إرجاع المهمة التالية الجاهزة للتنفيذ بناءً على TDG."""
        ready_nodes = self.graph.get_ready_tasks()
        for node in ready_nodes:
            if node.task_id in self._tasks:
                task = self._tasks[node.task_id]
                if role is None or task.role == role:
                    return task
        return None

    def complete_task(
        self,
        task_id: str,
        evidence: Optional[Dict[str, Any]] = None,
    ) -> bool:
        if task_id not in self._tasks:
            return False
        task = self._tasks[task_id]
        task.status = "completed"
        task.result = evidence
        task.updated_at = time.time()

        if evidence:
            self.memory.write_semantic(
                target=task.target,
                key=f"{task.technique}-result",
                value=evidence,
                tags=[task.technique, "completed"],
            )

        self.graph.mark_completed(task_id, evidence)
        self._save_state()
        return True

    def fail_task(
        self,
        task_id: str,
        reason: str,
        retry: bool = True,
    ) -> bool:
        if task_id not in self._tasks:
            return False
        task = self._tasks[task_id]

        self.memory.record_failure(
            target=task.target,
            technique=task.technique,
            reason=reason,
            context={"task_id": task_id, "role": task.role.value},
        )

        retried = self.graph.mark_failed(task_id, reason, retry=retry)
        if not retried:
            task.status = "failed"
        task.updated_at = time.time()
        self._save_state()
        return retried

    def bypass_task(
        self,
        task_id: str,
        bypass_method: str,
    ) -> bool:
        if task_id not in self._tasks:
            return False
        self.graph.mark_bypassed(task_id, bypass_method)
        self._tasks[task_id].status = "bypassed"
        self._tasks[task_id].updated_at = time.time()
        self._save_state()
        return True

    def get_ready_tasks_for_role(self, role: AgentRole) -> List[OrchestrationTask]:
        ready_nodes = self.graph.get_ready_tasks()
        result = []
        for node in ready_nodes:
            if node.task_id in self._tasks:
                task = self._tasks[node.task_id]
                if task.role == role:
                    result.append(task)
        return result

    def stats(self) -> Dict[str, Any]:
        return {
            "graph": self.graph.get_status_summary(),
            "memory": self.memory.stats(),
            "tasks": len(self._tasks),
        }

    def export_state(self) -> str:
        path = f"data/orchestrator_export_{self.graph_id}.json"
        data = {
            "graph_id": self.graph_id,
            "tasks": {
                tid: {
                    "task_id": t.task_id,
                    "target": t.target,
                    "role": t.role.value,
                    "description": t.description,
                    "technique": t.technique,
                    "status": t.status,
                    "result": t.result,
                    "created_at": t.created_at,
                    "updated_at": t.updated_at,
                }
                for tid, t in self._tasks.items()
            },
            "stats": self.stats(),
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return path
