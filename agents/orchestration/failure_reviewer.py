"""
Failure-Oriented Reviewer — وكيل مراجعة الفشل
=============================================
يحلل كل فشل، يستخرج الدروس، ويعدل الخطة. هو "الضمير" الذي يمنع
تكرار الأخطاء ويقرر متى يُفعّل backtracking عبر المهام البديلة (alternatives).
"""

from __future__ import annotations

import logging
import time
from typing import Optional, List, Dict, Any

from core.attack_graph.task_graph import (
    TaskDependencyGraph,
    TaskNode,
    TaskStatus,
    TaskPriority,
)
from agents.security_intelligence.memory_manager import MemoryManager

log = logging.getLogger("agents.orchestration.failure_reviewer")


class ReviewAction:
    """إجراء مقترح من Reviewer بعد تحليل فشل"""
    RETRY_ALTERNATIVE = "retry_alternative"   # جرّب المهمة البديلة في TDG
    ADJUST_PRIORITY = "adjust_priority"       # غيّر أولوية مهمة مرتبطة
    SKIP_TASK = "skip_task"                   # تخطّ هذه المهمة وانتقل للأخرى
    REPLAN = "replan"                         # أعد رسم التبعيات للرسم البياني
    ESCALATE = "escalate"                     # فشل حتمي — أوقف المسار

    def __init__(
        self,
        action: str,
        target_task_id: Optional[str] = None,
        reason: str = "",
        confidence: float = 0.0,
    ):
        self.action = action
        self.target_task_id = target_task_id
        self.reason = reason
        self.confidence = confidence

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "target_task_id": self.target_task_id,
            "reason": self.reason,
            "confidence": self.confidence,
        }


class FailureOrientedReviewer:
    """
    مسؤوليات:
    1. استلام إشعار فشل من GlobalOrchestrator أو Executor.
    2. تحليل سبب الفشل باستخدام FailureEpisodicMemory (هل تكرر؟ هل نمط معروف؟).
    3. اتخاذ قرار: بديل، تعديل أولوية، تخطٍ، إعادة تخطيط، أو تصعيد.
    4. تنفيذ القرار على TDG و TaskClueCache.
    """

    def __init__(
        self,
        tdg: TaskDependencyGraph,
        memory: MemoryManager,
        target: str = "unknown",
    ):
        self.tdg = tdg
        self.memory = memory
        self.target = target
        self.reviews: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    # المراجعة الرئيسية
    # ------------------------------------------------------------------ #
    def review_failure(
        self,
        task_id: str,
        reason: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> ReviewAction:
        """
        تحليل فشل مهمة واتخاذ الإجراء المناسب.
        """
        task = self.tdg.get_task(task_id)
        if not task:
            return ReviewAction(
                ReviewAction.ESCALATE,
                reason=f"Task {task_id} not found in TDG",
                confidence=1.0,
            )

        # تسجيل المراجعة
        review_record = {
            "task_id": task_id,
            "task_title": task.title,
            "reason": reason,
            "timestamp": time.time(),
        }

        # ── الخطوة 1: فحص أنماط الفشل المتكررة ──
        repeated = self.memory.failure_episodic.get_repeated_failures(min_repeats=2)
        same_tool_failures = [
            f for f in repeated if f.tool == task.title or f.task_id == task_id
        ]

        # ── الخطوة 2: هل هناك بديل متاح؟ ──
        alternatives = task.alternatives
        available_alts = [
            alt_id for alt_id in alternatives
            if self.tdg.get_task(alt_id) and self.tdg.get_task(alt_id).status == TaskStatus.PENDING
        ]

        if available_alts:
            # هناك بديل لم يُجرّب بعد → backtracking
            action = ReviewAction(
                ReviewAction.RETRY_ALTERNATIVE,
                target_task_id=available_alts[0],
                reason=f"Task {task_id} failed ({reason}); switching to alternative {available_alts[0]}",
                confidence=0.9,
            )
            review_record["action"] = "retry_alternative"
            review_record["alternative"] = available_alts[0]
            self.reviews.append(review_record)
            log.warning(f"[REVIEW] {action.reason}")
            return action

        # ── الخطوة 3: فشل متكرر لنفس الأداة → اقتراح تخطٍ أو إعادة تخطيط ──
        if same_tool_failures:
            action = ReviewAction(
                ReviewAction.SKIP_TASK,
                target_task_id=task_id,
                reason=f"Repeated failures for {task.title}; skipping to avoid loop",
                confidence=0.85,
            )
            review_record["action"] = "skip_task"
            self.reviews.append(review_record)
            log.warning(f"[REVIEW] {action.reason}")
            return action

        # ── الخطوة 4: فشل أولي وبدون بديل → تعديل أولوية مهام متعلقة أو إعادة تخطيط ──
        dependents = self._get_dependents(task_id)
        if dependents:
            # خفّض أولوية المهام التي تعتمد على الفاشلة
            for dep_id in dependents:
                self.tdg.set_priority(dep_id, TaskPriority.LOW)
            action = ReviewAction(
                ReviewAction.REPLAN,
                target_task_id=task_id,
                reason=f"No alternative for {task_id}; lowering priority of {len(dependents)} dependent tasks",
                confidence=0.7,
            )
            review_record["action"] = "replan"
            review_record["dependents"] = dependents
            self.reviews.append(review_record)
            log.info(f"[REVIEW] {action.reason}")
            return action

        # ── الخطوة 5: فشل حتمي بدون تبعيات → تصعيد ──
        action = ReviewAction(
            ReviewAction.ESCALATE,
            target_task_id=task_id,
            reason=f"Task {task_id} failed definitively: {reason}",
            confidence=1.0,
        )
        review_record["action"] = "escalate"
        self.reviews.append(review_record)
        log.error(f"[REVIEW] {action.reason}")
        return action

    # ------------------------------------------------------------------ #
    # تنفيذ الإجراء المقترح
    # ------------------------------------------------------------------ #
    def apply_action(self, action: ReviewAction) -> Optional[str]:
        """
        تطبيق إجراء المراجعة على TDG و TaskClueCache.
        ترجع معرّف المهمة الجديدة التي يجب تنفيذها (إن وجدت)، أو None.
        """
        if action.action == ReviewAction.RETRY_ALTERNATIVE and action.target_task_id:
            alt = self.tdg.get_task(action.target_task_id)
            if alt:
                alt.status = TaskStatus.PENDING
                self.memory.task_clue.upsert_task_state(
                    task_id=action.target_task_id,
                    title=alt.title,
                    status="pending",
                    assigned_agent=None,
                )
                log.info(f"[REVIEW] Activated alternative task {action.target_task_id}: {alt.title}")
                return action.target_task_id

        elif action.action == ReviewAction.SKIP_TASK and action.target_task_id:
            self.tdg.mark_blocked(action.target_task_id, reason=action.reason)
            state = self.memory.task_clue.get_task_state(action.target_task_id)
            if state:
                state.status = "skipped"
            log.info(f"[REVIEW] Skipped task {action.target_task_id}")

        elif action.action == ReviewAction.REPLAN:
            # إعادة تخطيط: المهام التابعة تُخفض أولويتها وتظل pending
            log.info(f"[REVIEW] Replan triggered for {action.target_task_id}")

        elif action.action == ReviewAction.ESCALATE:
            if action.target_task_id:
                self.tdg.mark_failed(action.target_task_id, action.reason, try_alternative=False)

        return None

    # ------------------------------------------------------------------ #
    # مساعدات
    # ------------------------------------------------------------------ #
    def _get_dependents(self, task_id: str) -> List[str]:
        """إرجاع المهام التي تعتمد على task_id"""
        dependents: List[str] = []
        for edge in self.tdg.edges.get(task_id, []):
            dependents.append(edge.target_task_id)
        return dependents

    def get_review_history(self) -> List[Dict[str, Any]]:
        return list(self.reviews)
