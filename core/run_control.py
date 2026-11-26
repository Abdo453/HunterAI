"""متحكّم موحّد للتشغيلات (Run Controller) — Phase 3.

يحل مشكلة الـ fire-and-forget: كل مهمة asyncio تُسجَّل هنا مع:
- معرف فريد، حالة (running/paused/stopped/completed/failed)
- إمكانية pause / resume / stop فورية
- جسر WebSocket اختياري لبثّ التغييرات للواجهة

الاستخدام:
    ctl = RunController()
    handle = ctl.register("mission-42", asyncio.create_task(...))
    await ctl.stop("mission-42")
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class RunState:
    # Legacy statuses (preserved for backward compatibility)
    PENDING = "pending"
    RUNNING = "running"
    WAITING = "waiting"
    PAUSED = "paused"
    STOPPING = "stopping"
    STOPPED = "stopped"
    COMPLETED = "completed"
    FAILED = "failed"

    # Canonical 7-state constants
    QUEUED = "QUEUED"
    CANCELLED = "CANCELLED"

    ACTIVE = (PENDING, QUEUED, RUNNING, WAITING, PAUSED, STOPPING)
    TERMINAL = (COMPLETED, FAILED, STOPPED, CANCELLED)

    @classmethod
    def to_canonical(cls, state: str) -> str:
        from core.runtime.state_machine import to_canonical_status

        canon, _ = to_canonical_status(state)
        return canon.value

    @classmethod
    def to_legacy(cls, state: str, *, recoverable: bool = False) -> str:
        from core.runtime.state_machine import to_legacy_status

        return to_legacy_status(state, recoverable=recoverable)


@dataclass
class RunHandle:
    """ملف تشغيل واحد."""

    run_id: str
    kind: str                      # mission | pipeline | engine | swarm
    task: Optional[asyncio.Task] = None
    state: str = RunState.PENDING
    recoverable: bool = False
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    stop_event: Optional[asyncio.Event] = None
    pause_event: Optional[asyncio.Event] = None
    meta: Dict[str, Any] = field(default_factory=dict)
    error: str = ""

    @property
    def canonical_state(self) -> str:
        return RunState.to_canonical(self.state)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "kind": self.kind,
            "state": self.state,
            "canonical_state": self.canonical_state,
            "recoverable": self.recoverable,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_s": round(
                (self.finished_at or time.time()) - (self.started_at or self.created_at), 2
            ) if self.state in RunState.TERMINAL or self.started_at else None,
            "meta": self.meta,
            "error": self.error,
        }


class RunController:
    """مسجّل ومتحكّم في كل التشغيلات النشطة (thread-safe بقدر معقول)."""

    def __init__(self, on_state_change: Optional[Callable[[RunHandle], None]] = None):
        self._runs: Dict[str, RunHandle] = {}
        self._lock = asyncio.Lock()
        self.on_state_change = on_state_change

    # ── التسجيل ───────────────────────────────────────────────────────────
    def register(
        self,
        run_id: str,
        task: Optional[asyncio.Task] = None,
        *,
        kind: str = "generic",
        meta: Optional[Dict[str, Any]] = None,
    ) -> RunHandle:
        handle = RunHandle(
            run_id=run_id, kind=kind, task=task,
            stop_event=asyncio.Event(), pause_event=asyncio.Event(),
            meta=dict(meta or {}),
        )
        handle.pause_event.set()  # الوضع الافتراضي: غير متوقف مؤقتًا
        if task is not None:
            handle.state = RunState.RUNNING
            handle.started_at = time.time()
            task.add_done_callback(lambda t, rid=run_id: self._on_task_done(rid, t))
        self._runs[run_id] = handle
        self._notify(handle)
        return handle

    def _on_task_done(self, run_id: str, task: asyncio.Task) -> None:
        handle = self._runs.get(run_id)
        if handle is None:
            return
        if handle.state in (RunState.STOPPING, RunState.STOPPED):
            handle.state = RunState.STOPPED
        elif task.cancelled():
            handle.state = RunState.STOPPED
        elif task.exception():
            handle.state = RunState.FAILED
            handle.error = str(task.exception())[:300]
        else:
            handle.state = RunState.COMPLETED
        handle.finished_at = time.time()
        self._notify(handle)

    # ── التحكم ────────────────────────────────────────────────────────────
    async def stop(self, run_id: str, *, force: bool = True) -> bool:
        """إيقاف فوري للتشغيل؛ يعود True إذا كان هناك ما يُوقف."""
        handle = self._runs.get(run_id)
        if handle is None or handle.state in RunState.TERMINAL:
            return False
        handle.state = RunState.STOPPING
        if handle.stop_event:
            handle.stop_event.set()
        if handle.pause_event:
            handle.pause_event.set()  # يفك التوقف ليخرج من الحلقة
        if handle.task is not None and force and not handle.task.done():
            handle.task.cancel()
        self._notify(handle)
        return True

    def pause(self, run_id: str) -> bool:
        """طلب إيقاف مؤقت — تُفعّل عند نقطة تحقق تعاونية."""
        handle = self._runs.get(run_id)
        if handle is None or handle.state not in (RunState.RUNNING, RunState.PENDING):
            return False
        if handle.pause_event:
            handle.pause_event.clear()
        handle.state = RunState.PAUSED
        self._notify(handle)
        return True

    def mark_waiting(self, run_id: str, reason: str = "") -> bool:
        """Transition a running handle into WAITING (HITL input/approval wait)."""
        handle = self._runs.get(run_id)
        if handle is None or handle.state not in (RunState.RUNNING, RunState.PENDING, RunState.QUEUED):
            return False
        handle.state = RunState.WAITING
        if reason:
            handle.meta["waiting_reason"] = reason
        self._notify(handle)
        return True

    def resume(self, run_id: str) -> bool:
        handle = self._runs.get(run_id)
        if handle is None or handle.state not in (RunState.PAUSED, RunState.WAITING):
            return False
        if handle.pause_event:
            handle.pause_event.set()
        handle.state = RunState.RUNNING
        handle.recoverable = False
        self._notify(handle)
        return True

    # ── نقاط تحقق تعاونية (يستخدمها المهمة نفسها) ────────────────────────
    def should_stop(self, run_id: str) -> bool:
        handle = self._runs.get(run_id)
        return bool(handle and handle.stop_event and handle.stop_event.is_set())

    async def checkpoint(self, run_id: str) -> bool:
        """نقطة تحقق: تنتظر إذا متوقف مؤقتًا؛ تعود False إذا طُلب الإيقاف."""
        handle = self._runs.get(run_id)
        if handle is None:
            return True
        if self.should_stop(run_id):
            return False
        if handle.pause_event and not handle.pause_event.is_set():
            while not handle.pause_event.is_set():
                if self.should_stop(run_id):
                    return False
                await asyncio.sleep(0.2)
        return not self.should_stop(run_id)

    # ── الاستعلام ─────────────────────────────────────────────────────────
    def get(self, run_id: str) -> Optional[RunHandle]:
        return self._runs.get(run_id)

    def list_runs(
        self,
        *,
        kind: Optional[str] = None,
        active_only: bool = False,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        items = list(self._runs.values())
        if kind:
            items = [h for h in items if h.kind == kind]
        if active_only:
            items = [h for h in items if h.state in RunState.ACTIVE]
        items.sort(key=lambda h: h.created_at, reverse=True)
        return [h.to_dict() for h in items[:limit]]

    def stop_all(self) -> int:
        """إيقاف كل التشغيلات النشطة (للإغلاق الآمن)."""
        n = 0
        for rid, handle in list(self._runs.items()):
            if handle.state in RunState.ACTIVE:
                if handle.stop_event:
                    handle.stop_event.set()
                if handle.task and not handle.task.done():
                    handle.task.cancel()
                handle.state = RunState.STOPPED
                handle.finished_at = time.time()
                n += 1
        return n

    def _notify(self, handle: RunHandle) -> None:
        if self.on_state_change is not None:
            try:
                self.on_state_change(handle)
            except Exception as exc:  # noqa: BLE001
                logger.warning("RunController state-change callback failed for %s: %s", handle.run_id, exc)


# نسخة مشتركة للتطبيق (تُحقن في router)
GLOBAL_RUN_CONTROLLER = RunController()
