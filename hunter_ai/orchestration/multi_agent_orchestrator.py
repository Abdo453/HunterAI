"""
منسق الوكلاء المتعدد لـ HunterAI مع دعم TDG والذاكرة الثلاثية.
يدعم غير المتزامن (async)، السجلات، والتكوينات المركزية
"""
from __future__ import annotations

import asyncio
import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.config.settings import config
from core.exceptions import (
    OrchestratorError,
    TDGError,
    MemoryError,
    HunterAIError,
)
from core.logging.logger import logger
from core.planning.task_graph import TaskDependencyGraph, TaskStatus, TaskNode
from core.memory.triple_memory import TripleMemory, MemoryType


class AgentRole(str, Enum):
    ORCHESTRATOR = "orchestrator"
    EXECUTOR = "executor"
    REVIEWER = "reviewer"


@dataclass
class AgentResult:
    agent_name: str
    target: str
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    timestamp: float = field(default_factory=time.time)


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
        self.graph_id = graph_id
        self.graph = TaskDependencyGraph(graph_id=graph_id)
        self.memory = TripleMemory()
        self._tasks: Dict[str, OrchestrationTask] = {}
        self._lock = asyncio.Lock()
        logger.info(f"[Orchestrator] تم تهيئة المنسق: {graph_id}")

    async def _load_state_async(self) -> None:
        """تحميل الحالة بشكل غير متزامن."""
        self.graph._load_state()

    def _save_state(self) -> None:
        """حفظ حالة المنسق."""
        self.graph.save()

    async def create_task_async(
        self,
        target: str,
        role: AgentRole,
        description: str,
        technique: str,
        dependencies: Optional[List[str]] = None,
    ) -> OrchestrationTask:
        """إنشاء مهمة بشكل غير متزامن."""
        async with self._lock:
            return self._create_task_sync(target, role, description, technique, dependencies)

    def create_task(
        self,
        target: str,
        role: AgentRole,
        description: str,
        technique: str,
        dependencies: Optional[List[str]] = None,
    ) -> OrchestrationTask:
        """إنشاء مهمة بشكل متزامن."""
        return self._create_task_sync(target, role, description, technique, dependencies)

    def _create_task_sync(
        self,
        target: str,
        role: AgentRole,
        description: str,
        technique: str,
        dependencies: Optional[List[str]] = None,
    ) -> OrchestrationTask:
        task_id = f"orch-{uuid.uuid4().hex[:8]}"
        try:
            self.graph.add_task(
                name=description,
                technique=technique,
                target=target,
                dependencies=dependencies,
                task_id=task_id,
            )
        except TDGError as e:
            raise OrchestratorError(str(e), agent_role=role.value, details={"task_id": task_id})

        task = OrchestrationTask(
            task_id=task_id,
            target=target,
            role=role,
            description=description,
            technique=technique,
        )
        self._tasks[task_id] = task
        self._save_state()
        logger.debug(
            f"[Orchestrator] أنشئت مهمة '{task_id}': الدور={role.value}, التقنية={technique}, الهدف={target}"
        )
        return task

    async def get_next_pending_task_async(
        self, role: Optional[AgentRole] = None
    ) -> Optional[OrchestrationTask]:
        """إرجاع المهمة التالية الجاهزة للتنفيذ بشكل غير متزامن."""
        async with self._lock:
            return self._get_next_pending_task_sync(role)

    def get_next_pending_task(self, role: Optional[AgentRole] = None) -> Optional[OrchestrationTask]:
        """إرجاع المهمة التالية الجاهزة للتنفيذ بشكل متزامن."""
        return self._get_next_pending_task_sync(role)

    def _get_next_pending_task_sync(self, role: Optional[AgentRole] = None) -> Optional[OrchestrationTask]:
        ready_nodes = self.graph.get_ready_tasks()
        for node in ready_nodes:
            if node.task_id in self._tasks:
                task = self._tasks[node.task_id]
                if role is None or task.role == role:
                    return task
        return None

    async def complete_task_async(
        self,
        task_id: str,
        evidence: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """إكمال مهمة بشكل غير متزامن."""
        async with self._lock:
            return self._complete_task_sync(task_id, evidence)

    def complete_task(
        self,
        task_id: str,
        evidence: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """إكمال مهمة بشكل متزامن."""
        return self._complete_task_sync(task_id, evidence)

    def _complete_task_sync(
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
        logger.info(f"[Orchestrator] أكملت مهمة '{task_id}': {task.technique}")
        return True

    async def fail_task_async(
        self,
        task_id: str,
        reason: str,
        retry: bool = True,
    ) -> bool:
        """تحديد مهمة كفاشلة بشكل غير متزامن."""
        async with self._lock:
            return self._fail_task_sync(task_id, reason, retry)

    def fail_task(
        self,
        task_id: str,
        reason: str,
        retry: bool = True,
    ) -> bool:
        """تحديد مهمة كفاشلة بشكل متزامن."""
        return self._fail_task_sync(task_id, reason, retry)

    def _fail_task_sync(
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
        logger.warning(
            f"[Orchestrator] مهمة '{task_id}' فشلت: {reason}, إعادة المحاولة={retried}"
        )
        return retried

    def bypass_task(
        self,
        task_id: str,
        bypass_method: str,
    ) -> bool:
        """تجاوز مهمة."""
        if task_id not in self._tasks:
            return False
        self.graph.mark_bypassed(task_id, bypass_method)
        self._tasks[task_id].status = "bypassed"
        self._tasks[task_id].updated_at = time.time()
        self._save_state()
        logger.info(f"[Orchestrator] تجاوزت مهمة '{task_id}' عبر: {bypass_method}")
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
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        logger.info(f"[Orchestrator] تم تصدير الحالة إلى: {path}")
        return path
