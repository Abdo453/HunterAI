"""
منسق المهام (Task Coordinator) — Phase C.

يكون مسؤولاً عن دورة حياة كل مهمة:
  1. قبول مهمة مع نطاق وقيود صريحين
  2. إنشاء سجل مهمة (run ID فريد) عبر TaskLifecycle
  3. طلب المخطط (Planner) لتحليل المهمة إلى مهام فرعية
  4. تحويل الخطة إلى عناصر عمل محدودة قابلة للتتبع
  5. تخصيص عناصر العمل لعمال متوافقين عبر WorkerRegistry
  6. تشغيل الأعمال المستقلة بشكل متزامن مع حدود توازي
  7. منع عمال متضاربين من تعديل نفس الموارد معًا (أقفال SharedEvidenceGraph)
  8. تتبع تبعيات المهام وحالة العمال والتقدم
  9. كشف الفشل المتكرر والحلقات غير المنتجة
  10. إلغاء العمل الزائد عند اللزوم
  11. طلب مدخلات بشرية عند الحاجة (حالة WAITING_FOR_APPROVAL)
  12. إنتاج ملخص نهائي مدعوم بالإثاثات المخزنة
  13. الحفاظ على تاريخ أحداث قابل لإعادة التشغيل لكل run

يufصل المنسق عن تفاصيل التنفيذ الفعلي عبر استدعاء executor 콜백 يُحقن من الخارج
(تُملأ تنفيذه في Phase E/F مع AgentRuntime). هذا يحافظ علىプلية المكونات.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set

from core.task_lifecycle import TaskLifecycle, TaskRecord, TaskStatus
from core.worker_registry import WorkerRegistry, WorkerInfo, WorkerStatus
from core.run_control import RunController, RunState
from core.shared_evidence import SharedEvidenceGraph
from core.planner.interface import Planner, DefaultPlanner

logger = logging.getLogger(__name__)


@dataclass
class RunContext:
    """سياق تنفيذ Run واحد."""
    run_id: str
    goal: str
    scope: Dict[str, Any]
    plan: Any = None  # Plan من core.planner
    status: str = RunState.RUNNING
    created_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# نوع دالة المنفّذ: تُستدعى لتنفيذ مهمة فرعية على عامل محدد.
TaskExecutor = Callable[[str, WorkerInfo, Any], asyncio.Future]


@dataclass
class CoordinatorConfig:
    max_concurrent_tasks: int = 5
    max_task_execution_s: float = 3600.0
    max_attempts_per_task: int = 3
    enable_resource_locks: bool = True


class Coordinator:
    """
    منسق المهام الرئيسي.

    لا يحتفظ بحالة عامة إلزامية — كل Run يُعزل في RunContext خاص به.
    """

    def __init__(
        self,
        *,
        lifecycle: Optional[TaskLifecycle] = None,
        worker_registry: Optional[WorkerRegistry] = None,
        run_controller: Optional[RunController] = None,
        evidence_graph: Optional[SharedEvidenceGraph] = None,
        planner: Optional[Planner] = None,
        config: Optional[CoordinatorConfig] = None,
    ):
        self.lifecycle = lifecycle or TaskLifecycle()
        self.workers = worker_registry or WorkerRegistry()
        self.run_controller = run_controller
        self.evidence = evidence_graph or SharedEvidenceGraph()
        self.planner = planner or DefaultPlanner()
        self.config = config or CoordinatorConfig()

        self._runs: Dict[str, RunContext] = {}
        self._lock = asyncio.Lock()
        self._executor: Optional[TaskExecutor] = None
        self._event_log: Dict[str, List[Dict[str, Any]]] = {}  # run_id -> events

    # ── التهيئة ──────────────────────────────────────────────────────────
    def set_executor(self, executor: TaskExecutor) -> None:
        """يُ Rightن دالة تنفيذ المهام الخارجية (تُحقق في Phase E/F)."""
        self._executor = executor

    # ── الأحداث ─────────────────────────────────────────────────────────
    def _event(self, run_id: str, event_type: str,
               payload: Dict[str, Any]) -> None:
        ev = {
            "event_id": f"ev-{time.time_ns()}",
            "run_id": run_id,
            "event_type": event_type,
            "timestamp": time.time(),
            "payload": payload,
        }
        self._event_log.setdefault(run_id, []).append(ev)
        logger.debug("حدث run=%s: %s %s", run_id, event_type, payload)

    def events(self, run_id: str) -> List[Dict[str, Any]]:
        return list(self._event_log.get(run_id, []))

    # ── استقبال مهمة جديدة ─────────────────────────────────────────────
    async def submit_run(
        self,
        *,
        goal: str,
        scope: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        استلام مهمة جديدة وإنشاء سجل تشغيل. يعيد run_id.
        """
        run_id = f"run-{time.time_ns()}"
        scope = dict(scope or {})

        if self.run_controller is not None:
            task = asyncio.create_task(self._execute_run(run_id))
            self.run_controller.register(
                run_id, task, kind="coordinator",
                meta={"goal": goal, "scope": scope})

        ctx = RunContext(
            run_id=run_id, goal=goal, scope=scope,
            metadata=dict(metadata or {}))
        self._runs[run_id] = ctx
        self._event(run_id, "RUN_CREATED", {"goal": goal, "scope": scope})

        if self.run_controller is None:
            asyncio.create_task(self._execute_run(run_id))

        return run_id

    async def _execute_run(self, run_id: str) -> None:
        ctx = self._runs.get(run_id)
        if ctx is None:
            return
        try:
            ctx.status = RunState.RUNNING
            self._event(run_id, "RUN_STARTED", {"goal": ctx.goal})

            plan = self.planner.plan(run_id=run_id, goal=ctx.goal,
                                     scope=ctx.scope)
            ctx.plan = plan
            self._event(run_id, "PLAN_COMPUTED",
                        {"subtasks": len(plan.subtasks)})

            await self._run_plan(ctx)

            summary = self._summarize(ctx)
            self._event(run_id, "RUN_FINISHED", summary)
        except asyncio.CancelledError:
            ctx.status = RunState.STOPPED
            self._event(run_id, "RUN_CANCELLED", {})
            raise
        except Exception as exc:  # noqa: BLE001
            ctx.status = RunState.STOPPED
            ctx.error = str(exc)[:300]
            self._event(run_id, "RUN_FAILED", {"error": ctx.error})
            logger.exception("Run %s failed", run_id)
        finally:
            ctx.finished_at = time.time()
            if self.run_controller is not None:
                handle = self.run_controller.get(run_id)
                if handle is not None:
                    handle.state = RunState.COMPLETED
                    handle.finished_at = time.time()

    # ── تنفيذ خطة ──────────────────────────────────────────────────────
    async def _run_plan(self, ctx: RunContext) -> None:
        plan = ctx.plan
        subtasks = plan.subtasks
        if not subtasks:
            self._event(ctx.run_id, "RUN_FINISHED",
                        {"summary": "no subtasks"})
            return

        # إنشاء سجلات مهام في TaskLifecycle
        task_id_by_index: Dict[int, str] = {}
        for i, st in enumerate(subtasks):
            tr = self.lifecycle.create(
                run_id=ctx.run_id, goal=st.description,
                dependencies=list(st.dependencies),
                scope=st.scope, max_attempts=st.max_attempts,
                metadata={"role": st.role, "subtask_index": i})
            task_id_by_index[i] = tr.task_id
            self.lifecycle.transition(tr.task_id, TaskStatus.READY)
            self._event(ctx.run_id, "TASK_CREATED",
                        {"task_id": tr.task_id, "description": st.description,
                         "dependencies": st.dependencies})

        max_concurrent = self.config.max_concurrent_tasks
        semaphore = asyncio.Semaphore(max_concurrent)
        completed: Set[str] = set()
        running: Dict[str, asyncio.Task] = {}

        def deps_done(i: int) -> bool:
            st = subtasks[i]
            return all(
                task_id_by_index[j] in completed
                for j, s in enumerate(subtasks)
                if s.description in st.dependencies
            )

        async def run_one(i: int) -> None:
            task_id = task_id_by_index[i]
            st = subtasks[i]

            async with semaphore:
                # اختيار عامل متوافق
                worker = self._select_worker(st)
                if worker is None:
                    self.lifecycle.transition(task_id, TaskStatus.BLOCKED,
                                              error="no compatible worker")
                    self._event(ctx.run_id, "TASK_BLOCKED",
                                {"task_id": task_id, "reason": "no worker"})
                    completed.add(task_id)
                    return

                if not self.workers.assign(task_id, worker.worker_id):
                    self.lifecycle.transition(task_id, TaskStatus.BLOCKED,
                                              error="worker busy")
                    self._event(ctx.run_id, "TASK_BLOCKED",
                                {"task_id": task_id, "reason": "worker busy"})
                    completed.add(task_id)
                    return

                self.lifecycle.transition(task_id, TaskStatus.RUNNING,
                                          assigned_worker=worker.worker_id)
                self._event(ctx.run_id, "TASK_ASSIGNED",
                            {"task_id": task_id, "worker": worker.worker_id})

                # قفل مورد للتarget (منع تضارب العمال)
                lock_resource = f"target:{st.target}" if st.target else ""
                lock_acquired = False
                if self.config.enable_resource_locks and lock_resource:
                    lock_acquired = self.evidence.acquire_lock(
                        lock_resource, worker.worker_id)
                    if not lock_acquired:
                        holder = self.evidence.lock_holder(lock_resource)
                        self.lifecycle.transition(
                            task_id, TaskStatus.BLOCKED,
                            error=f"resource locked by {holder}")
                        self._event(ctx.run_id, "TASK_BLOCKED",
                                    {"task_id": task_id,
                                     "reason": f"resource locked by {holder}"})
                        self.workers.complete(task_id)
                        completed.add(task_id)
                        return

                # موافقة بشرية إذا لزم الأمر
                if st.metadata.get("needs_approval"):
                    self.lifecycle.transition(task_id, TaskStatus.WAITING_FOR_APPROVAL)
                    self._event(ctx.run_id, "HUMAN_INPUT_REQUIRED",
                                {"task_id": task_id})
                    while (self.lifecycle.get(task_id)
                           and self.lifecycle.get(task_id).status
                           == TaskStatus.WAITING_FOR_APPROVAL):
                        if self._is_stopped(ctx.run_id):
                            self._release_lock(lock_resource, worker.worker_id,
                                               lock_acquired)
                            self.workers.complete(task_id)
                            completed.add(task_id)
                            return
                        await asyncio.sleep(0.5)

                # التنفيذ الفعلي
                try:
                    if self._executor is None:
                        raise RuntimeError("no task executor configured")
                    result = await asyncio.wait_for(
                        self._executor(task_id, worker, st),
                        timeout=self.config.max_task_execution_s)
                    self.lifecycle.transition(task_id, TaskStatus.SUCCEEDED,
                                              result=result)
                    self._event(ctx.run_id, "TASK_SUCCEEDED",
                                {"task_id": task_id,
                                 "worker": worker.worker_id})
                except asyncio.CancelledError:
                    self.lifecycle.transition(task_id, TaskStatus.CANCELLED)
                    self._event(ctx.run_id, "TASK_CANCELLED",
                                {"task_id": task_id})
                    raise
                except Exception as exc:  # noqa: BLE001
                    tr = self.lifecycle.get(task_id)
                    if tr and tr.attempt_count < tr.max_attempts:
                        self.lifecycle.transition(task_id, TaskStatus.READY)
                        self._event(ctx.run_id, "TASK_RETRY",
                                    {"task_id": task_id,
                                     "attempt": tr.attempt_count})
                        await run_one(i)  # إعادة محاولة
                        return
                    self.lifecycle.transition(task_id, TaskStatus.FAILED,
                                              error=str(exc)[:300])
                    self._event(ctx.run_id, "TASK_FAILED",
                                {"task_id": task_id,
                                 "error": str(exc)[:200]})
                finally:
                    self._release_lock(lock_resource, worker.worker_id,
                                       lock_acquired)
                    self.workers.complete(task_id)
                    completed.add(task_id)

        # حلقة الإطلاق الديناميكي
        pending_indices: Set[int] = set(range(len(subtasks)))
        active_tasks: Dict[asyncio.Task, int] = {}

        def launch_ready() -> None:
            nonlocal pending_indices
            to_launch = [i for i in list(pending_indices) if deps_done(i)]
            for i in to_launch:
                pending_indices.discard(i)
                t = asyncio.create_task(run_one(i))
                active_tasks[t] = i

        launch_ready()

        while active_tasks:
            done, _ = await asyncio.wait(
                list(active_tasks.keys()),
                return_when=asyncio.FIRST_COMPLETED)
            for t in done:
                i = active_tasks.pop(t)
                try:
                    await t
                except asyncio.CancelledError:
                    pass
                except Exception:  # لا يُسقط المراقب
                    logger.exception("subtask runner %d failed", i)
            launch_ready()

    # ── التحكم من المشغل ───────────────────────────────────────────────
    def _is_stopped(self, run_id: str) -> bool:
        if self.run_controller is None:
            return False
        handle = self.run_controller.get(run_id)
        return bool(handle and handle.state not in RunState.ACTIVE)

    def _release_lock(self, resource: str, worker_id: str,
                      acquired: bool) -> None:
        if acquired and resource:
            try:
                self.evidence.release_lock(resource, worker_id)
            except Exception:  # noqa: BLE001
                pass

    def approve_task(self, task_id: str, approved: bool) -> bool:
        """المشغل يوافق أو يرفض مهمة قيد WAITING_FOR_APPROVAL."""
        tr = self.lifecycle.get(task_id)
        if tr is None or tr.status != TaskStatus.WAITING_FOR_APPROVAL:
            return False
        if approved:
            self.lifecycle.transition(task_id, TaskStatus.RUNNING)
            self._event(tr.run_id, "TASK_APPROVED", {"task_id": task_id})
        else:
            self.lifecycle.transition(task_id, TaskStatus.FAILED,
                                      error="rejected by operator")
            self._event(tr.run_id, "TASK_REJECTED", {"task_id": task_id})
        return True

    def cancel_run(self, run_id: str) -> bool:
        if self.run_controller is not None:
            return self.run_controller.stop(run_id)
        return False

    def get_run(self, run_id: str) -> Optional[RunContext]:
        return self._runs.get(run_id)

    def list_runs(self) -> List[Dict[str, Any]]:
        out = []
        for rid, ctx in self._runs.items():
            out.append({
                "run_id": rid, "goal": ctx.goal, "status": ctx.status,
                "created_at": ctx.created_at, "finished_at": ctx.finished_at,
                "error": ctx.error,
            })
        return sorted(out, key=lambda x: x["created_at"], reverse=True)

    def task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        tr = self.lifecycle.get(task_id)
        return tr.to_dict() if tr else None

    # ── الملخص النهائي ─────────────────────────────────────────────────
    def _summarize(self, ctx: RunContext) -> Dict[str, Any]:
        snap = self.lifecycle.snapshot()
        worker_snap = self.workers.snapshot()
        evidence_snap = self.evidence.snapshot()
        return {
            "run_id": ctx.run_id,
            "goal": ctx.goal,
            "status": ctx.status,
            "tasks": snap,
            "workers": worker_snap,
            "evidence": evidence_snap,
            "events_count": len(self._event_log.get(ctx.run_id, [])),
        }

    # ── اختيار عامل ────────────────────────────────────────────────────
    def _select_worker(self, subtask: Any) -> Optional[WorkerInfo]:
        candidates = self.workers.available_workers(role=subtask.role)
        if not candidates:
            # fallback: أي عامل غير مشغول
            candidates = self.workers.available_workers()
        for w in candidates:
            if subtask.role and w.role == subtask.role:
                return w
        return candidates[0] if candidates else None
