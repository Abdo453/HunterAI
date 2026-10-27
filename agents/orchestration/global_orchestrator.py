"""
Global Orchestrator — وكيل التنسيق العام
=========================================
يدير Task Dependency Graph (TDG)، يوزع المهام على Executor،
ويقرر متى يغير المسار عند الفشل. هو "العقل" الذي لا ينفذ أدوات بنفسه،
بل يخطط ويراقب ويعيد التخطيط.
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

log = logging.getLogger("agents.orchestration.global_orchestrator")


class GlobalOrchestrator:
    """
    مسؤوليات:
    1. قراءة المهام الجاهزة للتنفيذ من TDG (get_ready_tasks).
    2. إسناد المهمة إلى ContextIntensiveExecutor وتحديث TaskClueCache.
    3. عند إبلاغ Executor بفشل مهمة → استدعاء mark_failed في TDG
       وتفعيل alternative (backtracking) إذا وجد.
    4. تحديث أولويات المهام ديناميكياً بناءً على الاكتشافات الجديدة.
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
        self.cycles = 0

    # ------------------------------------------------------------------ #
    # التخطيط والتوزيع
    # ------------------------------------------------------------------ #
    def next_ready_task(self) -> Optional[TaskNode]:
        """
        إرجاع المهمة التالية الجاهزة للتنفيذ من TDG.
        ترجع None إذا لم توجد مهام جاهزة (كلها pending مع dependents غير منتهية
        أو في進行或 failed).
        """
        ready = self.tdg.get_ready_tasks()
        if not ready:
            return None
        # 선택 المهمة ذات الأولوية الأعلى (مFRزّعة بالفعل في get_ready_tasks)
        task = ready[0]
        log.info(
            f"[ORCH] Selected task {task.id}: {task.title} (priority={task.priority.name})"
        )
        return task

    def assign_task(self, task: TaskNode, assigned_agent: str = "Executor") -> None:
        """
        تعيين مهمة للتنفيذ وتحديث حالة TaskClueCache.
        """
        self.tdg.mark_started(task.id)
        self.memory.task_clue.upsert_task_state(
            task_id=task.id,
            title=task.title,
            status="in_progress",
            assigned_agent=assigned_agent,
        )
        log.info(f"[ORCH] Assigned {task.id} to {assigned_agent}")

    # ------------------------------------------------------------------ #
    # إنجاز وفشل
    # ------------------------------------------------------------------ #
    def complete_task(self, task_id: str, summary: str = "", evidence: Optional[List[str]] = None) -> None:
        self.tdg.mark_done(task_id, summary=summary, evidence=evidence)
        state = self.memory.task_clue.get_task_state(task_id)
        if state:
            state.mark_task_completed(summary)
        log.info(f"[ORCH] Task {task_id} completed: {summary[:80]}")

    def fail_task(self, task_id: str, reason: str) -> Optional[str]:
        """
        وضع مهمة كفاشلة في TDG ومحاولة backtracking عبر alternative.
        ترجع معرّف المهمة البديلة إذا وجد، أو None إذا استنفدت الخيارات.
        """
        alt_id = self.tdg.mark_failed(task_id, reason, try_alternative=True)

        # تحديث TaskClueCache
        state = self.memory.task_clue.get_task_state(task_id)
        if state:
            state.mark_task_failed(reason)

        # تسجيل في FailureEpisodicMemory للمراجعة اللاحقة
        task = self.tdg.get_task(task_id)
        if task:
            self.memory.failure_episodic.record_failure(
                task_id=task_id,
                target=self.target,
                tool=task.title,
                command=f"task:{task.id}",
                reason=reason,
                context={"task_title": task.title},
            )

        if alt_id:
            log.warning(f"[ORCH] Backtracking: {task_id} failed -> alternative {alt_id}")
        else:
            log.error(f"[ORCH] Task {task_id} failed with no alternative: {reason}")

        return alt_id

    # ------------------------------------------------------------------ #
    # إعادة التخطيط الديناميكي
    # ------------------------------------------------------------------ #
    def reprioritize(self, task_id: str, new_priority: TaskPriority) -> None:
        task = self.tdg.get_task(task_id)
        if task:
            task.priority = new_priority
            task.updated_at = time.time()
            log.info(f"[ORCH] Reprioritized {task_id} to {new_priority.name}")

    def link_task_to_attack_node(self, task_id: str, attack_node_id: str) -> None:
        self.tdg.link_to_attack_node(task_id, attack_node_id)

    # ------------------------------------------------------------------ #
    # حالة الدورة الحالية
    # ------------------------------------------------------------------ #
    def tick(self) -> None:
        self.cycles += 1

    def get_graph_stats(self) -> Dict[str, Any]:
        return self.tdg.get_completion_stats()
