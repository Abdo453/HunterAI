"""Concurrency-bounded AgentManager with Flow->Task->Subtask dependency tracking & CAS HITL resume.

Atomic CAS ``InputReply`` and bounded cancellation-safe finalization patterns adapted from:
- vxcontrol/pentagi ``backend/pkg/controller/{assistant,flow}.go``
  (commit ``cffed9485aa1cca70762cd08a57ac62a80406258``, MIT;
  see ``THIRD_PARTY_LICENSES/PENTAGI_MIT.txt`` and ``NOTICE``)
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from typing import Any, Awaitable, Callable, Dict, List, Optional, Sequence

from core.platform_store import PlatformStore, get_platform_store, new_id
from core.runtime.event_bus import PersistentEventBus
from core.runtime.state_machine import (
    LifecycleState,
    SubtaskNode,
    TaskNode,
    TERMINAL_STATES,
)

logger = logging.getLogger("hunter_ai.runtime.agent_manager")


async def run_without_cancel(
    coro_or_fn: Callable[..., Any] | Awaitable[Any],
    *args: Any,
    timeout_s: float = 5.0,
    **kwargs: Any,
) -> Any:
    """Execute a bounded finalization write shielded from outer task cancellation.

    Python equivalent of Go's ``context.WithoutCancel(ctx)`` paired with a
    short deadline so shutdown/cancellation never strands rows in ``RUNNING``.
    """

    async def _invoke() -> Any:
        if callable(coro_or_fn):
            res = coro_or_fn(*args, **kwargs)
            if asyncio.iscoroutine(res) or isinstance(res, Awaitable):
                return await res
            return res
        return await coro_or_fn

    inner_task = asyncio.create_task(_invoke())
    try:
        return await asyncio.wait_for(asyncio.shield(inner_task), timeout=timeout_s)
    except asyncio.CancelledError:
        # Outer caller was cancelled; still let the bounded finalization write settle.
        try:
            return await asyncio.wait_for(inner_task, timeout=timeout_s)
        except Exception as fin_exc:
            logger.warning("Shielded finalization write failed after cancellation: %s", fin_exc)
            raise
    except asyncio.TimeoutError:
        inner_task.cancel()
        logger.warning("Bounded finalization write timed out after %.2fs", timeout_s)
        raise


class InputReply:
    """Atomic compare-and-swap (CAS) one-shot reply box for WAITING HITL resume.

    Guarantees that under concurrent replies or cancellation, at most ONE
    caller wins delivery; all subsequent calls return ``False`` cleanly.
    """

    def __init__(self, *, run_id: str, prompt: str = "", request_id: Optional[str] = None) -> None:
        self.request_id = request_id or new_id("hitl")
        self.run_id = run_id
        self.prompt = prompt
        self.created_at = time.time()
        self._lock = threading.Lock()
        self._settled = False
        self._cancelled = False
        self._value: Any = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._future: Optional[asyncio.Future[Any]] = None

    @property
    def is_settled(self) -> bool:
        with self._lock:
            return self._settled

    def deliver(self, value: Any) -> bool:
        """Atomically deliver *value* once (CAS). Returns True iff this caller won."""
        with self._lock:
            if self._settled:
                return False
            self._settled = True
            self._value = value
            fut = self._future
            loop = self._loop

        if fut is not None and not fut.done():
            if loop is not None and not loop.is_closed():
                loop.call_soon_threadsafe(self._resolve_future, fut, value)
            else:
                self._resolve_future(fut, value)
        return True

    def cancel(self, reason: str = "Cancelled") -> bool:
        """Atomically cancel an unsettled reply box. Returns True iff this caller won."""
        with self._lock:
            if self._settled:
                return False
            self._settled = True
            self._cancelled = True
            fut = self._future
            loop = self._loop

        if fut is not None and not fut.done():
            if loop is not None and not loop.is_closed():
                loop.call_soon_threadsafe(self._cancel_future, fut, reason)
            else:
                self._cancel_future(fut, reason)
        return True

    @staticmethod
    def _resolve_future(fut: asyncio.Future[Any], value: Any) -> None:
        if not fut.done():
            fut.set_result(value)

    @staticmethod
    def _cancel_future(fut: asyncio.Future[Any], reason: str) -> None:
        if not fut.done():
            fut.cancel(reason)

    async def wait(self, timeout: Optional[float] = None) -> Any:
        """Await the atomic reply value (or raise ``CancelledError`` / ``TimeoutError``)."""
        loop = asyncio.get_running_loop()
        with self._lock:
            if self._settled:
                if self._cancelled:
                    raise asyncio.CancelledError("HITL input reply was cancelled")
                return self._value
            if self._future is None:
                self._loop = loop
                self._future = loop.create_future()
            fut = self._future

        if timeout is not None:
            return await asyncio.wait_for(fut, timeout=timeout)
        return await fut


class AgentManager:
    """Bounded async task/subtask coordinator with semaphore concurrency & HITL resume."""

    def __init__(
        self,
        *,
        max_concurrent_agents: int = 5,
        store: Optional[PlatformStore] = None,
        event_bus: Optional[PersistentEventBus] = None,
    ) -> None:
        self.max_concurrent_agents = max(1, int(max_concurrent_agents))
        self._store = store
        self._event_bus = event_bus
        self._semaphore_loop: Optional[asyncio.AbstractEventLoop] = None
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._active_slots = 0
        self._peak_active_slots = 0

        self._tasks: Dict[str, TaskNode] = {}
        self._subtasks: Dict[str, SubtaskNode] = {}
        self._run_asyncio_tasks: Dict[str, set[asyncio.Task[Any]]] = {}
        self._completion_events: Dict[str, asyncio.Event] = {}
        self._waiting_replies: Dict[str, InputReply] = {}
        self._lock = threading.RLock()

    @property
    def store(self) -> PlatformStore:
        return self._store if self._store is not None else get_platform_store()

    def _get_semaphore(self) -> asyncio.Semaphore:
        loop = asyncio.get_running_loop()
        if self._semaphore is None or self._semaphore_loop is not loop:
            self._semaphore = asyncio.Semaphore(self.max_concurrent_agents)
            self._semaphore_loop = loop
        return self._semaphore

    @property
    def active_count(self) -> int:
        with self._lock:
            return self._active_slots

    @property
    def peak_active_count(self) -> int:
        with self._lock:
            return self._peak_active_slots

    # ── Task & Subtask Registration ──────────────────────────────────────────

    def create_task(
        self,
        *,
        run_id: str,
        title: str,
        role: str = "worker",
        priority: int = 5,
        depends_on: Optional[Sequence[str]] = None,
        input_data: Optional[Dict[str, Any]] = None,
        task_id: Optional[str] = None,
    ) -> TaskNode:
        tid = task_id or new_id("task")
        node = TaskNode(
            task_id=tid,
            run_id=run_id,
            title=title,
            role=role,
            priority=priority,
            depends_on=list(depends_on or ()),
            input_data=dict(input_data or {}),
        )
        with self._lock:
            self._tasks[tid] = node
            self._completion_events[tid] = asyncio.Event()
        self.store.upsert_task_node(
            task_id=node.task_id,
            run_id=node.run_id,
            title=node.title,
            role=node.role,
            status=node.state.value,
            priority=node.priority,
            depends_on=node.depends_on,
            input_data=node.input_data,
        )
        return node

    def create_subtask(
        self,
        *,
        run_id: str,
        task_id: str,
        title: str,
        depends_on: Optional[Sequence[str]] = None,
        input_data: Optional[Dict[str, Any]] = None,
        subtask_id: Optional[str] = None,
    ) -> SubtaskNode:
        sid = subtask_id or new_id("sub")
        node = SubtaskNode(
            subtask_id=sid,
            task_id=task_id,
            run_id=run_id,
            title=title,
            depends_on=list(depends_on or ()),
            input_data=dict(input_data or {}),
        )
        with self._lock:
            self._subtasks[sid] = node
            self._completion_events[sid] = asyncio.Event()
            if task_id in self._tasks:
                self._tasks[task_id].subtasks[sid] = node
        self.store.upsert_subtask_node(
            subtask_id=node.subtask_id,
            task_id=node.task_id,
            run_id=node.run_id,
            title=node.title,
            status=node.state.value,
            depends_on=node.depends_on,
            input_data=node.input_data,
        )
        return node

    def _get_node_state(self, node_id: str) -> Optional[LifecycleState]:
        with self._lock:
            if node_id in self._tasks:
                return self._tasks[node_id].state
            if node_id in self._subtasks:
                return self._subtasks[node_id].state
        return None

    async def _await_dependencies(self, depends_on: Sequence[str]) -> None:
        for dep_id in depends_on:
            while True:
                state = self._get_node_state(dep_id)
                if state is None:
                    raise KeyError(f"Unknown dependency node '{dep_id}'")
                if state == LifecycleState.COMPLETED:
                    break
                if state in {LifecycleState.FAILED, LifecycleState.CANCELLED}:
                    raise RuntimeError(f"Dependency '{dep_id}' ended in {state.value}")
                ev = self._completion_events.get(dep_id)
                if ev is None:
                    await asyncio.sleep(0.01)
                else:
                    await ev.wait()

    def _signal_completion(self, node_id: str) -> None:
        ev = self._completion_events.get(node_id)
        if ev is not None:
            ev.set()

    # ── Bounded Execution & Cancellation Propagation ─────────────────────────

    def spawn_subtask(
        self,
        subtask: SubtaskNode,
        coro_fn: Callable[[SubtaskNode], Awaitable[Any]],
    ) -> asyncio.Task[Any]:
        """Schedule a SubtaskNode bounded by ``asyncio.Semaphore(max_concurrent_agents)``."""

        async def _runner() -> Any:
            try:
                await self._await_dependencies(subtask.depends_on)
                sem = self._get_semaphore()
                async with sem:
                    with self._lock:
                        self._active_slots += 1
                        if self._active_slots > self._peak_active_slots:
                            self._peak_active_slots = self._active_slots
                    try:
                        subtask.transition_to(LifecycleState.RUNNING)
                        await asyncio.to_thread(
                            self.store.upsert_subtask_node,
                            subtask_id=subtask.subtask_id,
                            task_id=subtask.task_id,
                            run_id=subtask.run_id,
                            title=subtask.title,
                            status=subtask.state.value,
                            depends_on=subtask.depends_on,
                            input_data=subtask.input_data,
                            attempt=subtask.attempt,
                            started_at=subtask.started_at,
                        )
                        result = await coro_fn(subtask)
                        if isinstance(result, dict):
                            subtask.output_data.update(result)
                        else:
                            subtask.output_data["result"] = result
                        subtask.transition_to(LifecycleState.COMPLETED)
                        await run_without_cancel(
                            asyncio.to_thread,
                            self.store.upsert_subtask_node,
                            subtask_id=subtask.subtask_id,
                            task_id=subtask.task_id,
                            run_id=subtask.run_id,
                            title=subtask.title,
                            status=subtask.state.value,
                            depends_on=subtask.depends_on,
                            output_data=subtask.output_data,
                            attempt=subtask.attempt,
                            finished_at=subtask.finished_at,
                        )
                        return result
                    finally:
                        with self._lock:
                            self._active_slots = max(0, self._active_slots - 1)
            except asyncio.CancelledError:
                if subtask.state not in TERMINAL_STATES:
                    subtask.transition_to(LifecycleState.CANCELLED, error="Cancelled")
                    await run_without_cancel(
                        asyncio.to_thread,
                        self.store.upsert_subtask_node,
                        subtask_id=subtask.subtask_id,
                        task_id=subtask.task_id,
                        run_id=subtask.run_id,
                        title=subtask.title,
                        status=subtask.state.value,
                        error=subtask.error,
                        attempt=subtask.attempt,
                        finished_at=subtask.finished_at,
                    )
                raise
            except Exception as exc:
                if subtask.state not in TERMINAL_STATES:
                    subtask.transition_to(LifecycleState.FAILED, error=str(exc)[:500])
                    await run_without_cancel(
                        asyncio.to_thread,
                        self.store.upsert_subtask_node,
                        subtask_id=subtask.subtask_id,
                        task_id=subtask.task_id,
                        run_id=subtask.run_id,
                        title=subtask.title,
                        status=subtask.state.value,
                        error=subtask.error,
                        attempt=subtask.attempt,
                        finished_at=subtask.finished_at,
                    )
                raise
            finally:
                self._signal_completion(subtask.subtask_id)

        task = asyncio.create_task(_runner())
        with self._lock:
            self._run_asyncio_tasks.setdefault(subtask.run_id, set()).add(task)
        task.add_done_callback(
            lambda t, rid=subtask.run_id: self._discard_run_task(rid, t)
        )
        return task

    def _discard_run_task(self, run_id: str, task: asyncio.Task[Any]) -> None:
        with self._lock:
            bucket = self._run_asyncio_tasks.get(run_id)
            if bucket is not None:
                bucket.discard(task)
                if not bucket:
                    self._run_asyncio_tasks.pop(run_id, None)

    async def cancel_run(self, run_id: str, *, reason: str = "Run cancelled") -> int:
        """Propagate cancellation across all active tasks, subtasks, and WAITING HITL replies."""
        cancelled = 0
        with self._lock:
            tasks_to_cancel = list(self._run_asyncio_tasks.get(run_id, ()))
            reply_box = self._waiting_replies.pop(run_id, None)
            owned_tasks = [t for t in self._tasks.values() if t.run_id == run_id]
            owned_subtasks = [s for s in self._subtasks.values() if s.run_id == run_id]

        if reply_box is not None and reply_box.cancel(reason):
            cancelled += 1

        for t in tasks_to_cancel:
            if not t.done():
                t.cancel()
                cancelled += 1

        if tasks_to_cancel:
            await asyncio.gather(*tasks_to_cancel, return_exceptions=True)

        for node in owned_subtasks:
            if node.state not in TERMINAL_STATES:
                node.transition_to(LifecycleState.CANCELLED, error=reason)
                await run_without_cancel(
                    asyncio.to_thread,
                    self.store.upsert_subtask_node,
                    subtask_id=node.subtask_id,
                    task_id=node.task_id,
                    run_id=node.run_id,
                    title=node.title,
                    status=node.state.value,
                    error=reason,
                    finished_at=node.finished_at,
                )
                self._signal_completion(node.subtask_id)

        for tnode in owned_tasks:
            if tnode.state not in TERMINAL_STATES:
                tnode.transition_to(LifecycleState.CANCELLED, error=reason)
                await run_without_cancel(
                    asyncio.to_thread,
                    self.store.upsert_task_node,
                    task_id=tnode.task_id,
                    run_id=tnode.run_id,
                    title=tnode.title,
                    role=tnode.role,
                    status=tnode.state.value,
                    error=reason,
                    finished_at=tnode.finished_at,
                )
                self._signal_completion(tnode.task_id)

        return cancelled

    # ── WAITING HITL Resume (Atomic CAS InputReply) ──────────────────────────

    async def request_human_input(
        self,
        run_id: str,
        prompt: str,
        *,
        task_id: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> Any:
        """Transition a run into ``WAITING`` and block until atomic CAS ``reply_input`` resumes it."""
        reply = InputReply(run_id=run_id, prompt=prompt)
        with self._lock:
            prev = self._waiting_replies.get(run_id)
            if prev is not None and not prev.is_settled:
                raise RuntimeError(f"Run '{run_id}' already has an active WAITING input request")
            self._waiting_replies[run_id] = reply

        await asyncio.to_thread(
            self.store.update_run,
            run_id,
            status="waiting",
            meta={"waiting_prompt": prompt, "waiting_request_id": reply.request_id},
        )
        if self._event_bus is not None:
            await self._event_bus.publish(
                "run.waiting",
                {"run_id": run_id, "request_id": reply.request_id, "prompt": prompt},
                run_id=run_id,
                task_id=task_id,
                source="agent_manager",
            )
        try:
            answer = await reply.wait(timeout=timeout)
            await asyncio.to_thread(
                self.store.update_run,
                run_id,
                status="running",
                meta={"waiting_prompt": None, "waiting_request_id": None},
            )
            return answer
        finally:
            with self._lock:
                if self._waiting_replies.get(run_id) is reply:
                    self._waiting_replies.pop(run_id, None)

    def reply_input(self, run_id: str, value: Any) -> bool:
        """Atomically deliver an operator reply to a ``WAITING`` run (returns True once)."""
        with self._lock:
            reply = self._waiting_replies.get(run_id)
        if reply is None:
            return False
        return reply.deliver(value)

    def pending_input_request(self, run_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            reply = self._waiting_replies.get(run_id)
            if reply is None or reply.is_settled:
                return None
            return {
                "request_id": reply.request_id,
                "run_id": reply.run_id,
                "prompt": reply.prompt,
                "created_at": reply.created_at,
            }
