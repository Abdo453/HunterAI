"""
ثلاثي الوكلاء لـ HunterAI:
  Orchestrator — يخطط ويدير TDG
  Executor — ينفذ المهام عبر المستشعرات
  Reviewer — يراجع النتائج ويقرر النجاح/الفشل/التجاوز
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

from hunter_ai.orchestration.multi_agent_orchestrator import (
    MultiAgentOrchestrator,
    AgentRole,
    OrchestrationTask,
)


class Verdict(str, Enum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    NEEDS_BYPASS = "needs_bypass"


@dataclass
class ExecutionResult:
    task_id: str
    role: AgentRole
    status: str
    evidence: Optional[Dict[str, Any]] = None
    verdict: Optional[Verdict] = None
    bypass_method: Optional[str] = None
    message: str = ""


class TripleAgentSystem:
    """
    نظام ثلاثي الوكلاء يعمل مع الحفاظ على محكمة الأدلة (Evidence Court).
    """

    def __init__(self, graph_id: str = "triple_default"):
        self.orchestrator = MultiAgentOrchestrator(graph_id=graph_id)

    def plan_and_execute(
        self,
        target: str,
        technique: str,
        description: str,
    ) -> Dict[str, Any]:
        """
        1. Orchestrator يخطط ويدرج المهمة في TDG
        2. Executor ينفذ المهمة عبر المستشعرات (يتم الربط لاحقاً)
        3. Reviewer يراجع النتيجة ويقرر
        """
        # المرحلة 1: التخطيط
        plan_task = self.orchestrator.create_task(
            target=target,
            role=AgentRole.ORCHESTRATOR,
            description=description,
            technique=technique,
        )

        # المرحلة 2: التنفيذ (يعتمد على المهمة التخطيطية)
        exec_task = self.orchestrator.create_task(
            target=target,
            role=AgentRole.EXECUTOR,
            description=f"Execute: {description}",
            technique=technique,
            dependencies=[plan_task.task_id],
        )

        # المرحلة 3: المراجعة (تعتمد على التنفيذ)
        review_task = self.orchestrator.create_task(
            target=target,
            role=AgentRole.REVIEWER,
            description=f"Review: {description}",
            technique=technique,
            dependencies=[exec_task.task_id],
        )

        return {
            "orchestrator_task": plan_task.task_id,
            "executor_task": exec_task.task_id,
            "reviewer_task": review_task.task_id,
            "status": "planned",
            "target": target,
            "technique": technique,
        }

    def execute_task(
        self,
        task_id: str,
        sensor_output: Optional[Dict[str, Any]] = None,
    ) -> ExecutionResult:
        """
        تنفيذ مهمة من قبل Executor مع ربط بمستشعرات HunterAI الحالية.
        """
        task = self.orchestrator._tasks.get(task_id)
        if not task:
            return ExecutionResult(
                task_id=task_id,
                role=AgentRole.EXECUTOR,
                status="error",
                message=f"Task {task_id} not found",
            )

        # محاكاة التنفيذ (في الإنتاج، يتم الربط مع Burp Sensor، browser sensor، إلخ)
        if sensor_output:
            evidence = sensor_output
        else:
            evidence = {
                "technique": task.technique,
                "target": task.target,
                "executed_at": time.time(),
                "note": "Simulated execution — connect real sensors",
            }

        self.orchestrator.complete_task(task_id, evidence)
        return ExecutionResult(
            task_id=task_id,
            role=AgentRole.EXECUTOR,
            status="completed",
            evidence=evidence,
            verdict=Verdict.ALLOWED,
            message="Execution completed successfully",
        )

    def review_task(
        self,
        task_id: str,
        court_verdict: Optional[str] = None,
        bypass_method: Optional[str] = None,
    ) -> ExecutionResult:
        """
        مراجعة مهمة من قبل Reviewer باستخدام محكمة الأدلة.
        """
        task = self.orchestrator._tasks.get(task_id)
        if not task:
            return ExecutionResult(
                task_id=task_id,
                role=AgentRole.REVIEWER,
                status="error",
                message=f"Task {task_id} not found",
            )

        # تحديد الحكم بناءً على قرار المحكمة أو الأدلة
        if court_verdict == "blocked":
            verdict = Verdict.BLOCKED
            self.orchestrator.fail_task(
                task_id, "Court verdict: blocked", retry=True
            )
            message = "Finding blocked by Evidence Court"
        elif court_verdict == "bypass" or bypass_method:
            verdict = Verdict.NEEDS_BYPASS
            self.orchestrator.bypass_task(task_id, bypass_method or "unknown")
            message = f"Finding requires WAF bypass: {bypass_method}"
        else:
            verdict = Verdict.ALLOWED
            self.orchestrator.complete_task(
                task_id, {"review": "approved", "bypass_method": bypass_method}
            )
            message = "Finding approved by Evidence Court"

        return ExecutionResult(
            task_id=task_id,
            role=AgentRole.REVIEWER,
            status="completed",
            verdict=verdict,
            bypass_method=bypass_method,
            message=message,
        )

    def get_pending_for_role(self, role: AgentRole) -> List[OrchestrationTask]:
        return self.orchestrator.get_ready_tasks_for_role(role)

    def stats(self) -> Dict[str, Any]:
        return self.orchestrator.stats()

    def export_state(self) -> str:
        return self.orchestrator.export_state()
