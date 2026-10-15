"""
HunterAI Task Automation Engine (Phase 13)
==========================================
Automates workflows with conditional logic:
  1. TaskScheduler parses tasks.json rule files
  2. ConditionalRule evaluates if/then/else logic
  3. All executions logged to task_logs/ directory
"""
from __future__ import annotations

import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("hunter_ai.task_automation")


class TaskStatus(str, Enum):
    PENDING  = "PENDING"
    RUNNING  = "RUNNING"
    SUCCESS  = "SUCCESS"
    FAILED   = "FAILED"
    SKIPPED  = "SKIPPED"
    BLOCKED  = "BLOCKED"


@dataclass
class ConditionalRule:
    rule_id: str
    condition_key: str
    condition_value: Any
    then_action: str
    else_action: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def evaluate(self, context: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Returns (condition_met, action_to_run).
        """
        actual = context.get(self.condition_key)
        met = (actual == self.condition_value) or (bool(actual) == bool(self.condition_value) and not isinstance(self.condition_value, (str, int, float)))
        return met, (self.then_action if met else (self.else_action or "noop"))


@dataclass
class AutomationTask:
    task_id: str
    name: str
    action: str
    target: str = ""
    priority: int = 5
    depends_on: List[str] = field(default_factory=list)
    rules: List[ConditionalRule] = field(default_factory=list)
    status: TaskStatus = TaskStatus.PENDING
    result: Optional[Dict[str, Any]] = None
    created_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "name": self.name,
            "action": self.action,
            "target": self.target,
            "priority": self.priority,
            "depends_on": self.depends_on,
            "status": self.status.value,
            "result": self.result,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
        }


class TaskScheduler:
    """
    Parses tasks.json rule files, builds dependency graph,
    and executes tasks with conditional logic and logging.
    """
    def __init__(self, tasks_file: str | Path = "config/tasks.json", logs_dir: str | Path = "task_logs"):
        self.tasks_file = Path(tasks_file)
        self.logs_dir = Path(logs_dir)
        self.logs_dir.mkdir(parents=True, exist_ok=True)

        self._tasks: Dict[str, AutomationTask] = {}
        self._handlers: Dict[str, Callable[..., Any]] = {}
        self._context: Dict[str, Any] = {}
        self._subagent_registry: Dict[str, str] = {}  # task_id -> subagent_id

        self._load_tasks()

    def _load_tasks(self) -> None:
        if not self.tasks_file.exists():
            return
        try:
            data = json.loads(self.tasks_file.read_text(encoding="utf-8"))
            tasks_list = data if isinstance(data, list) else data.get("tasks", [])
            for item in tasks_list:
                task = self._parse_task(item)
                self._tasks[task.task_id] = task
        except Exception as e:
            logger.warning("Failed loading tasks.json from %s: %s", self.tasks_file, e)

    def _parse_task(self, item: Dict[str, Any]) -> AutomationTask:
        task_id = item.get("id") or item.get("task_id") or f"TASK-{uuid.uuid4().hex[:6].upper()}"
        rules = []
        for r in item.get("rules", []):
            rules.append(ConditionalRule(
                rule_id=r.get("rule_id", f"RULE-{uuid.uuid4().hex[:6]}"),
                condition_key=r.get("if", {}).get("key", ""),
                condition_value=r.get("if", {}).get("value"),
                then_action=r.get("then", "noop"),
                else_action=r.get("else"),
            ))
        return AutomationTask(
            task_id=task_id,
            name=item.get("name", task_id),
            action=item.get("action", "noop"),
            target=item.get("target", ""),
            priority=int(item.get("priority", 5)),
            depends_on=list(item.get("depends_on", [])),
            rules=rules,
        )

    def register_handler(self, action: str, handler: Callable[..., Any]) -> None:
        self._handlers[action] = handler

    def register_subagent(self, task_id: str, subagent_id: str) -> None:
        self._subagent_registry[task_id] = subagent_id

    def add_task(
        self,
        name: str,
        action: str,
        target: str = "",
        priority: int = 5,
        depends_on: Optional[List[str]] = None,
        rules: Optional[List[ConditionalRule]] = None,
        task_id: Optional[str] = None,
    ) -> AutomationTask:
        tid = task_id or f"TASK-{uuid.uuid4().hex[:6].upper()}"
        task = AutomationTask(
            task_id=tid,
            name=name,
            action=action,
            target=target,
            priority=priority,
            depends_on=depends_on or [],
            rules=rules or [],
        )
        self._tasks[tid] = task
        return task

    def set_context(self, key: str, value: Any) -> None:
        self._context[key] = value

    def _are_dependencies_met(self, task: AutomationTask) -> bool:
        for dep_id in task.depends_on:
            dep = self._tasks.get(dep_id)
            if dep is None or dep.status != TaskStatus.SUCCESS:
                return False
        return True

    def execute_task(self, task_id: str) -> Dict[str, Any]:
        """
        Executes a task by ID, evaluating conditional rules, checking
        dependencies, and logging the result.
        """
        task = self._tasks.get(task_id)
        if not task:
            return {"success": False, "error": f"Task '{task_id}' not found."}

        # Dependency check
        if task.depends_on and not self._are_dependencies_met(task):
            task.status = TaskStatus.BLOCKED
            return {"success": False, "task_id": task_id, "status": "BLOCKED", "error": "Dependencies not met."}

        task.status = TaskStatus.RUNNING

        # Evaluate conditional rules against current context
        effective_action = task.action
        for rule in task.rules:
            met, resolved_action = rule.evaluate(self._context)
            if resolved_action != "noop":
                effective_action = resolved_action
                break

        # Execute handler
        handler = self._handlers.get(effective_action)
        result: Dict[str, Any]
        try:
            if handler:
                raw = handler(task=task, context=self._context)
                result = raw if isinstance(raw, dict) else {"output": raw}
                task.status = TaskStatus.SUCCESS
            else:
                result = {"warning": f"No handler registered for action '{effective_action}'. Simulated as NOOP."}
                task.status = TaskStatus.SUCCESS
        except Exception as e:
            result = {"error": str(e)}
            task.status = TaskStatus.FAILED

        task.result = result
        task.completed_at = time.time()

        self._log_task(task)
        return {
            "success": task.status == TaskStatus.SUCCESS,
            "task_id": task_id,
            "action": effective_action,
            "status": task.status.value,
            "result": result,
        }

    def _log_task(self, task: AutomationTask) -> None:
        log_file = self.logs_dir / f"{task.task_id}_{int(task.completed_at or time.time())}.json"
        try:
            log_file.write_text(json.dumps(task.to_dict(), indent=2, default=str), encoding="utf-8")
        except Exception as e:
            logger.warning("Failed writing task log: %s", e)

    def execute_all_pending(self) -> List[Dict[str, Any]]:
        """
        Executes all PENDING tasks in priority order (lower priority int = higher priority).
        """
        pending = sorted(
            [t for t in self._tasks.values() if t.status == TaskStatus.PENDING],
            key=lambda t: t.priority,
        )
        results = []
        for task in pending:
            res = self.execute_task(task.task_id)
            results.append(res)
        return results

    def list_tasks(self) -> List[Dict[str, Any]]:
        return [t.to_dict() for t in self._tasks.values()]
