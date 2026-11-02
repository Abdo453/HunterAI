"""
ثلاثي الوكلاء لـ HunterAI:
  Orchestrator — يخطط ويدير TDG
  Executor — ينفذ المهام عبر المستشعرات
  Reviewer — يراجع النتائج ويقرر النجاح/الفشل/التجاوز
يدعم غير المتزامن (async)، السجلات، والتكامل مع جميع المكونات
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

from core.config.settings import config
from core.exceptions import OrchestratorError, HunterAIError
from core.logging.logger import logger
from hunter_ai.evidence.evidence_court import EvidenceCourt, CourtVerdict
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
        self.graph_id = graph_id
        self.orchestrator = MultiAgentOrchestrator(graph_id=graph_id)
        self.court = EvidenceCourt()
        self._lock = asyncio.Lock()

    async def plan_and_execute_async(
        self,
        target: str,
        technique: str,
        description: str,
    ) -> Dict[str, Any]:
        """
        تخطيط وتنفيذ غير متزامن:
        1. Orchestrator يخطط ويدرج المهمة في TDG
        2. Executor ينفذ المهمة عبر المستشعرات
        3. Reviewer يراجع النتيجة ويقرر
        """
        async with self._lock:
            return self._plan_and_execute_sync(target, technique, description)

    def plan_and_execute(
        self,
        target: str,
        technique: str,
        description: str,
    ) -> Dict[str, Any]:
        """نسخة متزامنة."""
        return self._plan_and_execute_sync(target, technique, description)

    def _plan_and_execute_sync(
        self,
        target: str,
        technique: str,
        description: str,
    ) -> Dict[str, Any]:
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

        result = {
            "orchestrator_task": plan_task.task_id,
            "executor_task": exec_task.task_id,
            "reviewer_task": review_task.task_id,
            "status": "planned",
            "target": target,
            "technique": technique,
            "description": description,
            "graph_id": self.graph_id,
        }
        logger.info(
            f"[Triple] خطة جديدة للهدف {target}: التقنية={technique}, "
            f"المهام={plan_task.task_id}, {exec_task.task_id}, {review_task.task_id}"
        )
        return result

    async def execute_task_async(
        self,
        task_id: str,
        sensor_output: Optional[Dict[str, Any]] = None,
    ) -> ExecutionResult:
        """تنفيذ مهمة بشكل غير متزامن."""
        async with self._lock:
            return self._execute_task_sync(task_id, sensor_output)

    def execute_task(
        self,
        task_id: str,
        sensor_output: Optional[Dict[str, Any]] = None,
    ) -> ExecutionResult:
        """نسخة متزامنة."""
        return self._execute_task_sync(task_id, sensor_output)

    def _execute_task_sync(
        self,
        task_id: str,
        sensor_output: Optional[Dict[str, Any]] = None,
    ) -> ExecutionResult:
        task = self.orchestrator._tasks.get(task_id)
        if not task:
            raise OrchestratorError(f"المهمة '{task_id}' غير موجودة", agent_role=AgentRole.EXECUTOR.value)

        # تنفيذ المهمة (في الإنتاج، يتم الربط مع Burp Sensor، browser sensor، إلخ)
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
        logger.info(f"[Triple] تنفيذ مهمة '{task_id}' بواسطة Executor: {task.status}")
        return ExecutionResult(
            task_id=task_id,
            role=AgentRole.EXECUTOR,
            status="completed",
            evidence=evidence,
            verdict=Verdict.ALLOWED,
            message="Execution completed successfully",
        )

    async def review_task_async(
        self,
        task_id: str,
        court_verdict: Optional[str] = None,
        bypass_method: Optional[str] = None,
    ) -> ExecutionResult:
        """مراجعة مهمة بشكل غير متزامن."""
        async with self._lock:
            return self._review_task_sync(task_id, court_verdict, bypass_method)

    def review_task(
        self,
        task_id: str,
        court_verdict: Optional[str] = None,
        bypass_method: Optional[str] = None,
    ) -> ExecutionResult:
        """نسخة متزامنة."""
        return self._review_task_sync(task_id, court_verdict, bypass_method)

    def _review_task_sync(
        self,
        task_id: str,
        court_verdict: Optional[str] = None,
        bypass_method: Optional[str] = None,
    ) -> ExecutionResult:
        task = self.orchestrator._tasks.get(task_id)
        if not task:
            raise OrchestratorError(f"المهمة '{task_id}' غير موجودة", agent_role=AgentRole.REVIEWER.value)

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

        logger.info(
            f"[Triple] مراجعة مهمة '{task_id}' بواسطة Reviewer: الحكم={verdict.value}, الرسالة={message}"
        )
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
