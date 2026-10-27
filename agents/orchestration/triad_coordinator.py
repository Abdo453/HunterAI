"""
Triad Coordinator — حلقة التنسيق بين الوكلاء الثلاثة
=====================================================
يدير دورة العمل الكاملة:

  Orchestrator  →  Executor  →  (نجاح؟)  →  Orchestrator (مهمة تالية)
                              ↘ (فشل؟)
                        Failure-Oriented Reviewer
                              →  Backtracking / Replan / Skip / Escalate

هو واجهة التشغيل الموحّدة للطبقة 3 من السكاффولد.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

from core.attack_graph.task_graph import (
    TaskDependencyGraph,
    TaskNode,
    TaskStatus,
)
from agents.security_intelligence.memory_manager import MemoryManager
from agents.orchestration.global_orchestrator import GlobalOrchestrator
from agents.orchestration.context_executor import ContextIntensiveExecutor, ToolResult
from agents.orchestration.failure_reviewer import FailureOrientedReviewer, ReviewAction

log = logging.getLogger("agents.orchestration.triad_coordinator")


@dataclass
class CoordinationResult:
    """نتيجة دورة تنسيق واحدة"""
    cycle: int
    task_id: Optional[str]
    task_title: str
    executor_success: bool
    executor_output: str
    review_action: Optional[str] = None
    next_task_id: Optional[str] = None
    graph_stats: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cycle": self.cycle,
            "task_id": self.task_id,
            "task_title": self.task_title,
            "executor_success": self.executor_success,
            "executor_output": self.executor_output,
            "review_action": self.review_action,
            "next_task_id": self.next_task_id,
            "graph_stats": self.graph_stats,
        }


@dataclass
class TriadSessionResult:
    """نتيجة جلسة تنسيق كاملة"""
    target: str
    total_cycles: int
    tasks_completed: int
    tasks_failed: int
    tasks_skipped: int
    backtracks: int
    final_stats: Dict[str, Any]
    history: List[CoordinationResult] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "total_cycles": self.total_cycles,
            "tasks_completed": self.tasks_completed,
            "tasks_failed": self.tasks_failed,
            "tasks_skipped": self.tasks_skipped,
            "backtracks": self.backtracks,
            "final_stats": self.final_stats,
            "history": [h.to_dict() for h in self.history],
        }


class TriadCoordinator:
    """
    المنسق الرئيسي للوكلاء الثلاثة.
    يُنشأ مع TDG و MemoryManager ويدير حلقة التخطيط → التنفيذ → المراجعة.
    """

    def __init__(
        self,
        tdg: TaskDependencyGraph,
        memory: MemoryManager,
        target: str = "unknown",
        max_cycles: int = 100,
    ):
        self.tdg = tdg
        self.memory = memory
        self.target = target
        self.max_cycles = max_cycles

        # تهيئة الوكلاء الثلاثة
        self.orchestrator = GlobalOrchestrator(tdg, memory, target=target)
        self.executor = ContextIntensiveExecutor(memory, target=target)
        self.reviewer = FailureOrientedReviewer(tdg, memory, target=target)

        self.history: List[CoordinationResult] = []
        self.backtracks = 0

    # ------------------------------------------------------------------ #
    # دورة واحدة
    # ------------------------------------------------------------------ #
    async def run_cycle(self) -> Optional[CoordinationResult]:
        """
        تنفيذ دورة تنسيق واحدة:
        1. يختار Orchestrator المهمة التالية الجاهزة.
        2. ينفذ Executor المهمة.
        3. إذا نجح → يُعلّمها Orchestrator مكتملة.
        4. إذا Failed → يراجعها Reviewer ويطبّق إجراءه (backtrack، skip، replan، escalate).
        ترجع None إذا لم توجد مهام جاهزة للتنفيذ.
        """
        self.orchestrator.tick()
        cycle = self.orchestrator.cycles

        # ── الخطوة 1: اختيار المهمة ──
        task = self.orchestrator.next_ready_task()
        if task is None:
            log.info(f"[COORD] Cycle {cycle}: no ready tasks — hunt complete or blocked")
            return None

        self.orchestrator.assign_task(task, assigned_agent="Executor")

        # ── الخطوة 2: التنفيذ ──
        tool_result = await self.executor.execute_task(
            task_title=task.title,
            task_description=task.description,
            tool_hint=None,
            target=self.target,
            context={"task_id": task.id},
        )

        # ── الخطوة 3: معالجة النتيجة ──
        if tool_result.success:
            self.orchestrator.complete_task(
                task_id=task.id,
                summary=tool_result.output[:200],
                evidence=tool_result.evidence,
            )
            result = CoordinationResult(
                cycle=cycle,
                task_id=task.id,
                task_title=task.title,
                executor_success=True,
                executor_output=tool_result.output,
                graph_stats=self.tdg.get_completion_stats(),
            )
            self.history.append(result)
            log.info(
                f"[COORD] Cycle {cycle}: {task.title} → SUCCESS"
            )
            return result

        # ── الخطوة 4: الفشل → مراجعة失败 ──
        review_action = self.reviewer.review_failure(
            task_id=task.id,
            reason=tool_result.error or "execution failed",
            context={"task_title": task.title, "output": tool_result.output},
        )

        # تطبيق إجراء المراجعة
        next_task_id = self.reviewer.apply_action(review_action)

        # إذا كان الإجراء backtracking إلى بديل، احتسبه
        if review_action.action == "retry_alternative":
            self.backtracks += 1

        result = CoordinationResult(
            cycle=cycle,
            task_id=task.id,
            task_title=task.title,
            executor_success=False,
            executor_output=tool_result.output or tool_result.error or "",
            review_action=review_action.action,
            next_task_id=next_task_id,
            graph_stats=self.tdg.get_completion_stats(),
        )
        self.history.append(result)
        log.warning(
            f"[COORD] Cycle {cycle}: {task.title} → FAILED ({tool_result.error}) "
            f"-> Review: {review_action.action}"
        )
        return result

    # ------------------------------------------------------------------ #
    # جلسة كاملة حتى الانتهاء أو بلوغ الحد الأقصى
    # ------------------------------------------------------------------ #
    async def run_until_completion(self) -> TriadSessionResult:
        """
        تشغيل حلقات التنسيق حتى:
        - لا توجد مهام جاهزة (اكتمل الرسم البياني أو تعطل)، أو
        - بلوغ max_cycles.
        """
        cycle_count = 0
        completed = 0
        failed = 0
        skipped = 0

        while cycle_count < self.max_cycles:
            result = await self.run_cycle()
            if result is None:
                break

            cycle_count += 1

            if result.executor_success:
                completed += 1
            else:
                failed += 1
                if result.review_action == "skip_task":
                    skipped += 1

            # الأمان: إذا لم تتقدم الجلسة (نفس الفشل يتكرر)، أوقف
            if cycle_count > 3 and self._is_stuck():
                break

        final_stats = self.tdg.get_completion_stats()
        session = TriadSessionResult(
            target=self.target,
            total_cycles=cycle_count,
            tasks_completed=completed,
            tasks_failed=failed,
            tasks_skipped=skipped,
            backtracks=self.backtracks,
            final_stats=final_stats,
            history=self.history,
        )
        log.info(
            f"[COORD] Session complete for {self.target}: "
            f"{completed} done, {failed} failed, {skipped} skipped, {self.backtracks} backtracks"
        )
        return session

    def _is_stuck(self) -> bool:
        """
        كشف التعطل: إذا كانت آخر 3 دورات كلها فشل دون أي تقدم (بدون بديل مفعل).
        """
        if len(self.history) < 3:
            return False
        last_three = self.history[-3:]
        no_progress = all(
            not r.executor_success and r.review_action != "retry_alternative"
            for r in last_three
        )
        return no_progress

    # ------------------------------------------------------------------ #
    # تصدير وطرائق مساعدة
    # ------------------------------------------------------------------ #
    def get_session_summary(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "cycles": self.orchestrator.cycles,
            "backtracks": self.backtracks,
            "graph_stats": self.tdg.get_completion_stats(),
            "memory_summary": self.memory.summary(),
            "review_history": self.reviewer.get_review_history(),
        }
