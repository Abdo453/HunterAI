"""
HunterAI Mission Planner
نظام تخطيط المهام (Todo list) لكل وكيل — مقتبس من فكرة BlacksmithAI

كل وكيل يخطط مهامه محليًا قبل التنفيذ، مع تتبع التقدم والحالة
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum

log = logging.getLogger("hunter_ai.mission_planner")


class TaskPriority(str):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PlannerTaskStatus(str):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"


@dataclass
class PlannerTask:
    task_id: str
    title: str
    description: str
    priority: str = TaskPriority.MEDIUM
    status: str = PlannerTaskStatus.PENDING
    dependencies: List[str] = field(default_factory=list)  # task IDs التي تعتمد عليها
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    retry_count: int = 0
    max_retries: int = 3

    def can_start(self, completed_task_ids: set) -> bool:
        """هل يمكن بدء المهمة (모든 التبعيات مكتملة)"""
        return all(dep in completed_task_ids for dep in self.dependencies)

    def start(self):
        self.status = PlannerTaskStatus.IN_PROGRESS
        self.started_at = time.time()

    def complete(self, result: Optional[Dict[str, Any]] = None):
        self.status = PlannerTaskStatus.COMPLETED
        self.completed_at = time.time()
        if result:
            self.result = result

    def fail(self, error: str):
        self.status = PlannerTaskStatus.FAILED
        self.completed_at = time.time()
        self.error = error

    def block(self, reason: str):
        self.status = PlannerTaskStatus.BLOCKED
        self.error = reason

    def to_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "title": self.title,
            "description": self.description,
            "priority": self.priority,
            "status": self.status,
            "dependencies": self.dependencies,
            "result": self.result,
            "error": self.error,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries,
        }


class MissionPlanner:
    """
    نظام تخطيط المهام — يخطط لمهام الوكيل قبل التنفيذ ويتبع التقدم
    يمكن استخدامه من قبل أي وكيل لتنظيم مهامه الداخلية
    """

    def __init__(self, agent_name: str):
        self.agent_name = agent_name
        self.tasks: Dict[str, PlannerTask] = {}
        self.completed_ids: set = set()
        self.failed_ids: set = set()

    def add_task(
        self,
        title: str,
        description: str = "",
        priority: str = TaskPriority.MEDIUM,
        dependencies: Optional[List[str]] = None,
    ) -> str:
        task_id = f"task_{uuid.uuid4().hex[:8]}"
        task = PlannerTask(
            task_id=task_id,
            title=title,
            description=description,
            priority=priority,
            dependencies=dependencies or [],
        )
        self.tasks[task_id] = task
        log.debug(f"[MissionPlanner:{self.agent_name}] Added task: {title} ({task_id})")
        return task_id

    def get_task(self, task_id: str) -> Optional[PlannerTask]:
        return self.tasks.get(task_id)

    def get_ready_tasks(self) -> List[PlannerTask]:
        """إرجاع المهام الجاهزة للتنفيذ (모든 التبعيات مكتملة ولم تبدأ بعد)"""
        ready = []
        for task in self.tasks.values():
            if task.status == PlannerTaskStatus.PENDING and task.can_start(self.completed_ids):
                ready.append(task)
        # فرز حسب الأولوية
        priority_order = {TaskPriority.CRITICAL: 0, TaskPriority.HIGH: 1, TaskPriority.MEDIUM: 2, TaskPriority.LOW: 3}
        ready.sort(key=lambda t: priority_order.get(t.priority, 99))
        return ready

    def start_task(self, task_id: str) -> bool:
        task = self.get_task(task_id)
        if not task:
            return False
        if not task.can_start(self.completed_ids):
            log.warning(f"[MissionPlanner:{self.agent_name}] Task {task_id} dependencies not met")
            return False
        task.start()
        return True

    def complete_task(self, task_id: str, result: Optional[Dict[str, Any]] = None) -> bool:
        task = self.get_task(task_id)
        if not task:
            return False
        task.complete(result)
        self.completed_ids.add(task_id)
        self.failed_ids.discard(task_id)
        log.debug(f"[MissionPlanner:{self.agent_name}] Task completed: {task.title}")
        return True

    def fail_task(self, task_id: str, error: str) -> bool:
        task = self.get_task(task_id)
        if not task:
            return False
        task.fail(error)
        self.failed_ids.add(task_id)
        self.completed_ids.discard(task_id)
        log.warning(f"[MissionPlanner:{self.agent_name}] Task failed: {task.title} — {error}")
        return True

    def get_progress(self) -> dict:
        total = len(self.tasks)
        completed = len(self.completed_ids)
        failed = len(self.failed_ids)
        in_progress = sum(1 for t in self.tasks.values() if t.status == PlannerTaskStatus.IN_PROGRESS)
        pending = sum(1 for t in self.tasks.values() if t.status == PlannerTaskStatus.PENDING)
        blocked = sum(1 for t in self.tasks.values() if t.status == PlannerTaskStatus.BLOCKED)

        return {
            "agent": self.agent_name,
            "total": total,
            "completed": completed,
            "failed": failed,
            "in_progress": in_progress,
            "pending": pending,
            "blocked": blocked,
            "completion_percentage": round((completed / total * 100) if total > 0 else 0, 1),
        }

    def get_all_tasks(self) -> List[dict]:
        return [t.to_dict() for t in self.tasks.values()]

    def clear(self):
        self.tasks.clear()
        self.completed_ids.clear()
        self.failed_ids.clear()
