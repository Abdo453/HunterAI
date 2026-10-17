"""
HunterAI Task Automation & Multi-Agent Scheduler V2 (P0)
=========================================================
Implements MoAI-ADK inspired task orchestration:
  1. Strict Lifecycle: PENDING -> READY -> RUNNING -> REVIEW -> DONE (+ BLOCKED, FAILED, CANCELLED)
  2. Independent Review: Task cannot complete until independent reviewer approves
  3. Anti-Stall & Anti-Freeze Detection: Identifies stuck tasks and re-queues them
  4. Persistent State & Crash Recovery: Serializes pending queue to disk
  5. Full backward compatibility with AutomationTask & ConditionalRule
"""
from __future__ import annotations

import json
import logging
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from core.contracts.task_contracts import (
    AgentTeam,
    TaskContract,
    TaskLifecycleStatus,
    ToolExecutionResult,
)

logger = logging.getLogger("hunter_ai.task_scheduler")

# Backward compatibility alias
TaskStatus = TaskLifecycleStatus


@dataclass
class ConditionalRule:
    rule_id: str
    condition_key: str
    condition_value: Any
    then_action: str
    else_action: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def evaluate(self, context: Dict[str, Any]) -> Tuple[bool, str]:
        actual = context.get(self.condition_key)
        met = (actual == self.condition_value) or (
            bool(actual) == bool(self.condition_value) and not isinstance(self.condition_value, (str, int, float))
        )
        return met, (self.then_action if met else (self.else_action or "noop"))


# Backward-compatible wrapper
AutomationTask = TaskContract


class TaskScheduler:
    """
    Orchestrates specialized agent teams with deterministic task contracts,
    dependency resolution, independent review, and crash recovery.
    """
    def __init__(
        self,
        tasks_file: str | Path = "config/tasks.json",
        logs_dir: str | Path = "task_logs",
        state_file: str | Path = "data/task_scheduler_state.json",
    ):
        self.tasks_file = Path(tasks_file)
        self.logs_dir = Path(logs_dir)
        self.state_file = Path(state_file)
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.state_file.parent.mkdir(parents=True, exist_ok=True)

        self._tasks: Dict[str, TaskContract] = {}
        self._handlers: Dict[str, Callable[..., Any]] = {}
        self._context: Dict[str, Any] = {}
        self._conditional_rules: Dict[str, List[ConditionalRule]] = {}

        self._load_from_state()
        self._load_from_config()

    # ── Task Creation ──────────────────────────────────────────────────────────

    def add_task(
        self,
        name: str,
        action: str,
        target: str = "",
        team: AgentTeam = AgentTeam.RECON,
        priority: int = 5,
        depends_on: Optional[List[str]] = None,
        success_criteria: Optional[List[str]] = None,
        rules: Optional[List[ConditionalRule]] = None,
        parameters: Optional[Dict[str, Any]] = None,
        task_id: Optional[str] = None,
    ) -> TaskContract:
        tid = task_id or f"TASK-{uuid.uuid4().hex[:6].upper()}"
        task = TaskContract(
            task_id=tid,
            title=name,
            team=team,
            action=action,
            target=target,
            priority=priority,
            parameters=parameters or {},
            depends_on=depends_on or [],
            success_criteria=success_criteria or [],
            status=TaskLifecycleStatus.PENDING if (depends_on and len(depends_on) > 0) else TaskLifecycleStatus.READY,
        )
        self._tasks[tid] = task
        if rules:
            self._conditional_rules[tid] = rules

        self._update_readiness()
        self._persist_state()
        return task

    # ── State Machine & Transitions ───────────────────────────────────────────

    def _update_readiness(self) -> None:
        """Promotes PENDING tasks to READY when all dependencies are DONE."""
        for task in self._tasks.values():
            if task.status == TaskLifecycleStatus.PENDING:
                if self._are_dependencies_met(task):
                    task.status = TaskLifecycleStatus.READY

    def _are_dependencies_met(self, task: TaskContract) -> bool:
        for dep_id in task.depends_on:
            dep = self._tasks.get(dep_id)
            if dep is None or dep.status != TaskLifecycleStatus.DONE:
                return False
        return True

    def get_ready_tasks(self, team: Optional[AgentTeam] = None) -> List[TaskContract]:
        self._update_readiness()
        ready = [t for t in self._tasks.values() if t.status == TaskLifecycleStatus.READY]
        if team:
            ready = [t for t in ready if t.team == team]
        return sorted(ready, key=lambda t: t.priority)

    def dispatch_task(self, task_id: str, owner_agent: str) -> Optional[TaskContract]:
        """Locks a task into RUNNING state for a specific owner agent."""
        task = self._tasks.get(task_id)
        if not task or task.status not in (TaskLifecycleStatus.READY, TaskLifecycleStatus.PENDING):
            return None
        task.mark_running(owner_agent)
        self._persist_state()
        return task

    def submit_result(self, task_id: str, result: ToolExecutionResult) -> bool:
        """Owner agent submits output; transitions task to REVIEW."""
        task = self._tasks.get(task_id)
        if not task:
            return False
        ok = task.submit_for_review(result)
        if ok:
            self._persist_state()
            self._log_task_execution(task)
        return ok

    def review_task(self, task_id: str, reviewer_agent: str, approved: bool, notes: str = "") -> bool:
        """
        Independent review: ensures self-grading is strictly prohibited.
        If approved -> DONE; if rejected -> re-queues to READY or marks FAILED.
        """
        task = self._tasks.get(task_id)
        if not task or task.status != TaskLifecycleStatus.REVIEW:
            return False

        if task.owner_agent == reviewer_agent:
            logger.error("Self-grading prevented: Agent '%s' cannot review its own task '%s'", reviewer_agent, task_id)
            return False

        if approved:
            task.approve_review(reviewer_agent, notes)
            self._update_readiness()
        else:
            task.reject_review(reviewer_agent, notes)

        self._persist_state()
        self._log_task_execution(task)
        return True

    # ── Anti-Stall & Anti-Freeze Detection ─────────────────────────────────────

    def detect_and_recover_stalled(self, timeout_seconds: float = 300.0) -> List[str]:
        """
        Identifies tasks stuck in RUNNING beyond timeout without completion,
        and re-queues them to READY or marks FAILED.
        """
        recovered = []
        now = time.time()
        for task in self._tasks.values():
            if task.status == TaskLifecycleStatus.RUNNING and task.started_at:
                elapsed = now - task.started_at
                if elapsed > timeout_seconds:
                    logger.warning("Task %s stalled (%ds elapsed). Recovering...", task.task_id, int(elapsed))
                    if task.retry_count < task.max_retries:
                        task.retry_count += 1
                        task.status = TaskLifecycleStatus.READY
                        task.owner_agent = ""
                        recovered.append(task.task_id)
                    else:
                        task.status = TaskLifecycleStatus.FAILED
                        recovered.append(task.task_id)
        if recovered:
            self._persist_state()
        return recovered

    # ── Execution Handlers ────────────────────────────────────────────────────

    def register_handler(self, action: str, handler: Callable[..., Any]) -> None:
        self._handlers[action] = handler

    def set_context(self, key: str, value: Any) -> None:
        self._context[key] = value

    def execute_task(
        self,
        task_id: str,
        owner_agent: str = "Executor",
        reviewer_agent: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Executes a task synchronously (evaluates rules, invokes handler, runs auto-review).

        The auto-review goes through :meth:`review_task` so the anti-self-grading
        invariant is always enforced. A task is never sealed ``DONE`` by its own
        owner, and an action with no registered handler is *not* reported as a
        success (it used to pass through as a "simulated noop").
        """
        task = self._tasks.get(task_id)
        if not task:
            return {"success": False, "error": f"Task '{task_id}' not found."}

        self._update_readiness()
        if task.status == TaskLifecycleStatus.PENDING:
            task.status = TaskLifecycleStatus.BLOCKED
            return {"success": False, "task_id": task_id, "status": "BLOCKED", "error": "Dependencies not satisfied"}

        task.mark_running(owner_agent)

        # Evaluate conditional rules
        effective_action = task.action
        for rule in self._conditional_rules.get(task_id, []):
            met, resolved_action = rule.evaluate(self._context)
            if resolved_action != "noop":
                effective_action = resolved_action
                break

        # Execute registered handler — an unregistered action is a real failure,
        # never a silently-successful "simulated noop".
        handler = self._handlers.get(effective_action)
        t0 = time.time()
        result_data: Dict[str, Any]
        success = True
        err = []

        try:
            if handler:
                raw = handler(task=task, context=self._context)
                result_data = raw if isinstance(raw, dict) else {"output": raw}
            else:
                success = False
                err = [f"NO_HANDLER: no handler registered for action '{effective_action}'."]
                result_data = {"error": err[0]}
        except Exception as e:
            success = False
            err = [str(e)]
            result_data = {"error": str(e)}

        duration_ms = round((time.time() - t0) * 1000, 2)

        # Wrap into universal ToolExecutionResult
        tool_result = ToolExecutionResult(
            task_id=task_id,
            tool_name=effective_action,
            action=effective_action,
            target=task.target,
            parameters=dict(task.parameters),
            success=success,
            duration_ms=duration_ms,
            raw_output=json.dumps(result_data),
            normalized_data=result_data,
            errors=err,
        )

        task.submit_for_review(tool_result)

        # Automatic review through the guarded path (anti-self-grading enforced).
        reviewer = reviewer_agent or f"Reviewer_{task.team.value}"
        if reviewer == owner_agent:
            logger.error(
                "Auto-review skipped: owner '%s' cannot review its own task '%s'.",
                owner_agent, task_id,
            )
        else:
            self.review_task(
                task_id,
                reviewer_agent=reviewer,
                approved=success,
                notes="Execution verified successfully." if success else f"Execution failed: {err}",
            )

        self._persist_state()
        self._log_task_execution(task)

        return {
            "success": task.status == TaskLifecycleStatus.DONE,
            "task_id": task_id,
            "status": task.status.value,
            "action": effective_action,
            "result": result_data,
        }

    # ── Persistence ───────────────────────────────────────────────────────────

    def _persist_state(self) -> None:
        try:
            data = [t.to_dict() for t in self._tasks.values()]
            self.state_file.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        except Exception as e:
            logger.warning("Failed saving task scheduler state: %s", e)

    def _load_from_state(self) -> None:
        if not self.state_file.exists():
            return
        try:
            data = json.loads(self.state_file.read_text(encoding="utf-8"))
            for item in data:
                task = TaskContract(
                    task_id=item["task_id"],
                    title=item.get("title", item.get("name", "")),
                    team=AgentTeam(item.get("team", AgentTeam.RECON.value)),
                    owner_agent=item.get("owner_agent", ""),
                    reviewer_agent=item.get("reviewer_agent", ""),
                    target=item.get("target", ""),
                    action=item.get("action", "noop"),
                    priority=int(item.get("priority", 5)),
                    parameters=dict(item.get("parameters", {}) or {}),
                    depends_on=list(item.get("depends_on", [])),
                    status=TaskLifecycleStatus(item.get("status", TaskLifecycleStatus.PENDING.value)),
                )
                self._tasks[task.task_id] = task
        except Exception as e:
            logger.warning("Failed loading scheduler state: %s", e)

    def _load_from_config(self) -> None:
        if not self.tasks_file.exists():
            return
        try:
            data = json.loads(self.tasks_file.read_text(encoding="utf-8"))
            tasks_list = data if isinstance(data, list) else data.get("tasks", [])
            for item in tasks_list:
                tid = item.get("id") or item.get("task_id")
                if tid not in self._tasks:
                    self.add_task(
                        name=item.get("name", tid),
                        action=item.get("action", "noop"),
                        target=item.get("target", ""),
                        priority=int(item.get("priority", 5)),
                        parameters=dict(item.get("parameters", {}) or {}),
                        depends_on=list(item.get("depends_on", [])),
                        task_id=tid,
                    )
        except Exception as e:
            logger.warning("Failed loading tasks.json: %s", e)

    def _log_task_execution(self, task: TaskContract) -> None:
        log_file = self.logs_dir / f"{task.task_id}_{int(task.completed_at or time.time())}.json"
        try:
            log_file.write_text(json.dumps(task.to_dict(), indent=2, default=str), encoding="utf-8")
        except Exception as e:
            logger.warning("Failed writing task execution log: %s", e)

    def list_tasks(self) -> List[Dict[str, Any]]:
        return [t.to_dict() for t in self._tasks.values()]
