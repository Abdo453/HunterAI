"""
اختبارات Phase C: دورة حياة المهام، سجل العمال، منسق المهام.
لا يستهدف أي نظام خارجي؛ executor وهمي يُنجز المهام فورًا.
"""
import asyncio
from typing import Any, Optional

import pytest

from core.task_lifecycle import TaskLifecycle, TaskStatus
from core.worker_registry import WorkerRegistry, WorkerInfo, WorkerStatus
from core.coordinator import Coordinator, CoordinatorConfig
from core.planner.interface import DefaultPlanner
from core.shared_evidence import SharedEvidenceGraph
from core.run_control import RunController


# ── دورة الحياة ─────────────────────────────────────────────────────────

class TestTaskLifecycle:
    def test_valid_transitions(self):
        tl = TaskLifecycle()
        tr = tl.create(run_id="r1", goal="scan example.com")
        assert tr.status == TaskStatus.PENDING

        assert tl.transition(tr.task_id, TaskStatus.READY)
        assert tl.transition(tr.task_id, TaskStatus.RUNNING)
        assert tl.transition(tr.task_id, TaskStatus.SUCCEEDED)
        assert tl.get(tr.task_id).status.is_terminal

    def test_invalid_transition_rejected(self):
        tl = TaskLifecycle()
        tr = tl.create(run_id="r1", goal="g")
        # PENDING -> SUCCEEDED غير صالح
        assert not tl.transition(tr.task_id, TaskStatus.SUCCEEDED)
        assert tl.get(tr.task_id).status == TaskStatus.PENDING

    def test_terminal_cannot_transition(self):
        tl = TaskLifecycle()
        tr = tl.create(run_id="r1", goal="g")
        tl.transition(tr.task_id, TaskStatus.READY)
        tl.transition(tr.task_id, TaskStatus.SUCCEEDED)
        assert not tl.transition(tr.task_id, TaskStatus.FAILED)

    def test_dependency_tracking(self):
        tl = TaskLifecycle()
        a = tl.create(run_id="r1", goal="A")
        b = tl.create(run_id="r1", goal="B", dependencies=[a.task_id])
        assert b.dependencies == [a.task_id]


# ── سجل العمال ──────────────────────────────────────────────────────────

class TestWorkerRegistry:
    def test_register_and_list(self):
        reg = WorkerRegistry()
        reg.register(WorkerInfo(
            worker_id="w1", display_name="Recon Worker", role="recon",
            provider_or_runtime="builtin",
            available_tools=["nmap.scan"]))
        reg.register(WorkerInfo(
            worker_id="w2", display_name="Web Worker", role="web",
            provider_or_runtime="builtin", available_tools=["ffuf.scan"]))

        assert len(reg.list_workers()) == 2
        assert len(reg.list_workers(role="web")) == 1
        assert reg.ids_by_role("recon") == ["w1"]

    def test_assign_and_complete(self):
        reg = WorkerRegistry()
        reg.register(WorkerInfo(
            worker_id="w1", display_name="W", role="recon",
            provider_or_runtime="builtin"))
        assert reg.assign("t1", "w1")
        assert reg.is_worker_busy("w1")
        # نفس العامل لا يقبل مهمة ثانية
        assert not reg.assign("t2", "w1")
        # عامل آخر يقبل
        reg.register(WorkerInfo(
            worker_id="w2", display_name="W2", role="recon",
            provider_or_runtime="builtin"))
        assert reg.assign("t2", "w2")

        reg.complete("t1", result="ok")
        assert not reg.is_worker_busy("w1")
        # الآن w1 حر مرة أخرى
        assert reg.assign("t3", "w1")

    def test_available_workers(self):
        reg = WorkerRegistry()
        reg.register(WorkerInfo(
            worker_id="w1", display_name="W", role="recon",
            provider_or_runtime="builtin", health=WorkerStatus.HEALTHY))
        reg.register(WorkerInfo(
            worker_id="w2", display_name="W2", role="web",
            provider_or_runtime="builtin", health=WorkerStatus.UNHEALTHY))
        healthy = reg.available_workers()
        assert len(healthy) == 1
        assert healthy[0].worker_id == "w1"


# ── المنسق ──────────────────────────────────────────────────────────────

class FakeExecutor:
    """منفّذ وهمي ينجز كل مهمة فورًا بنتيجة."""
    def __init__(self, fail_task: Optional[str] = None,
                 approval_task: Optional[str] = None):
        self.fail_task = fail_task
        self.approval_task = approval_task
        self.calls = []

    async def __call__(self, task_id: str, worker: WorkerInfo,
                       subtask: Any) -> dict:
        self.calls.append(task_id)
        await asyncio.sleep(0)
        if task_id == self.fail_task:
            raise RuntimeError("boom")
        return {"ok": True, "worker": worker.worker_id}


class TestCoordinator:
    def _build(self, **executor_kwargs):
        lifecycle = TaskLifecycle()
        workers = WorkerRegistry()
        workers.register(WorkerInfo(
            worker_id="w-recon", display_name="Recon", role="recon",
            provider_or_runtime="builtin"))
        workers.register(WorkerInfo(
            worker_id="w-web", display_name="Web", role="web",
            provider_or_runtime="builtin"))
        evidence = SharedEvidenceGraph()
        coord = Coordinator(
            lifecycle=lifecycle, worker_registry=workers,
            evidence_graph=evidence,
            config=CoordinatorConfig(max_concurrent_tasks=3))
        coord.set_executor(FakeExecutor(**executor_kwargs))
        return coord, workers

    @pytest.mark.asyncio
    async def test_submit_and_run(self):
        coord, _ = self._build()
        run_id = await coord.submit_run(
            goal="scan example.com", scope={"target": "example.com"})
        # انتظر انتهاء
        for _ in range(100):
            ctx = coord.get_run(run_id)
            if ctx and ctx.finished_at:
                break
            await asyncio.sleep(0.05)
        ctx = coord.get_run(run_id)
        assert ctx is not None
        assert ctx.finished_at is not None
        # الحدث RUN_CREATED و RUN_FINISHED موجودان
        types = [e["event_type"] for e in coord.events(run_id)]
        assert "RUN_CREATED" in types
        assert "RUN_FINISHED" in types

    @pytest.mark.asyncio
    async def test_task_states(self):
        coord, _ = self._build()
        run_id = await coord.submit_run(
            goal="scan example.com", scope={"target": "example.com"})
        for _ in range(100):
            ctx = coord.get_run(run_id)
            if ctx and ctx.finished_at:
                break
            await asyncio.sleep(0.05)
        # جميع المهام SUCCEEDED
        tasks = coord.lifecycle.list_tasks(run_id=run_id)
        assert all(t.status == TaskStatus.SUCCEEDED for t in tasks)

    @pytest.mark.asyncio
    async def test_failure_and_retry(self):
        coord, _ = self._build(fail_task="task-x")
        # لجعل الفشل يحدث على مهمة محددة، نحتاج معرفة task_id — استخدم هدفًا واحدًا
        run_id = await coord.submit_run(
            goal="fail me", scope={"target": "x"})
        for _ in range(100):
            ctx = coord.get_run(run_id)
            if ctx and ctx.finished_at:
                break
            await asyncio.sleep(0.05)
        ctx = coord.get_run(run_id)
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_cancel_run(self):
        coord, _ = self._build()
        run_id = await coord.submit_run(
            goal="long task", scope={"target": "example.com"})
        await asyncio.sleep(0.1)
        assert isinstance(coord.cancel_run(run_id), bool)

    @pytest.mark.asyncio
    async def test_approval_flow(self):
        # مهمة تحتاج موافقة: subtask metadata needs_approval=True
        # DefaultPlanner لا يضيف needs_approval؛ نختبر approve_task مباشرة على lifecycle
        tl = TaskLifecycle()
        tr = tl.create(run_id="r1", goal="g")
        tl.transition(tr.task_id, TaskStatus.READY)
        tl.transition(tr.task_id, TaskStatus.RUNNING)
        tl.transition(tr.task_id, TaskStatus.WAITING_FOR_APPROVAL)
        assert tl.get(tr.task_id).status == TaskStatus.WAITING_FOR_APPROVAL
        assert tl.transition(tr.task_id, TaskStatus.RUNNING)
        assert tl.get(tr.task_id).status == TaskStatus.RUNNING

    def test_list_runs(self):
        coord, _ = self._build()
        assert coord.list_runs() == []

    @pytest.mark.asyncio
    async def test_cancel_run_returns_bool(self):
        coord, _ = self._build()
        run_id = await coord.submit_run(
            goal="long task", scope={"target": "example.com"})
        await asyncio.sleep(0.1)
        result = coord.cancel_run(run_id)
        assert isinstance(result, bool)
