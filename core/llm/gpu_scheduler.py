"""Process-wide GPU/VRAM Scheduler with interactive priority queue and pressure eviction.

Guarantees single-model VRAM discipline across all local Ollama/LM Studio callers:
- Process-wide singleton ``get_gpu_scheduler()`` serialized by an ``asyncio.Lock``
  paired with a strict priority waitlist (interactive Copilot requests preempt
  queued background scan/pipeline jobs).
- Configurable ``keep_alive`` (seconds) to avoid unnecessary unload/reload thrash
  on consecutive calls to the same model while immediately unloading on model
  switch, ``keep_alive=0``, or detected VRAM pressure.
- Loop-safe synchronization across multiple ``asyncio.run()`` lifecycles.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass
import heapq
import logging
import os
import threading
import time
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("hunter_ai.llm.gpu_scheduler")

PRIORITY_INTERACTIVE: int = 0
PRIORITY_NORMAL: int = 5
PRIORITY_BACKGROUND: int = 10

UnloadCallback = Callable[[str], Awaitable[Any]]
PressureCheckFn = Callable[[], Optional[float]]


@dataclass
class GPULease:
    """Active lease returned inside ``async with scheduler.acquire(...)``."""

    model_name: str
    priority: int
    keep_alive: int
    acquired_at: float
    previous_model: Optional[str] = None
    evicted_previous: bool = False


class GPUScheduler:
    """Process-wide local GPU/VRAM lease coordinator with priority scheduling."""

    def __init__(
        self,
        *,
        default_keep_alive_s: Optional[int] = None,
        vram_pressure_threshold_pct: float = 85.0,
        pressure_checker: Optional[PressureCheckFn] = None,
    ) -> None:
        env_ka = os.getenv("HUNTER_OLLAMA_KEEP_ALIVE_SEC")
        if default_keep_alive_s is not None:
            self._default_keep_alive_s = max(0, int(default_keep_alive_s))
        elif env_ka is not None and env_ka.strip():
            try:
                self._default_keep_alive_s = max(0, int(env_ka.strip()))
            except ValueError:
                self._default_keep_alive_s = 120
        else:
            self._default_keep_alive_s = 120

        self.vram_pressure_threshold_pct = float(vram_pressure_threshold_pct)
        self._pressure_checker = pressure_checker

        self._meta_lock = threading.RLock()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._gpu_lock: Optional[asyncio.Lock] = None
        self._waiters: List[Tuple[int, int, asyncio.Event]] = []
        self._seq: int = 0
        self._holder_active: bool = False

        # Observable runtime telemetry
        self._locked: bool = False
        self._current_model: Optional[str] = None
        self._loaded_model: Optional[str] = None
        self._active_priority: Optional[int] = None
        self._lock_acquired_at: float = 0.0
        self._total_runs: int = 0
        self._total_unloads: int = 0
        self._pressure_unloads: int = 0
        self._interactive_waiting: int = 0
        self._background_waiting: int = 0

    def _ensure_loop_primitives(self) -> asyncio.Lock:
        loop = asyncio.get_running_loop()
        with self._meta_lock:
            if self._gpu_lock is None or self._loop is not loop:
                self._loop = loop
                self._gpu_lock = asyncio.Lock()
                self._waiters = []
                self._holder_active = False
            return self._gpu_lock

    @property
    def default_keep_alive(self) -> int:
        return self._default_keep_alive_s

    @property
    def currently_loaded_model(self) -> Optional[str]:
        with self._meta_lock:
            return self._loaded_model or self._current_model

    def set_loaded_model(self, model_name: Optional[str]) -> None:
        with self._meta_lock:
            self._loaded_model = model_name

    def is_locked(self) -> bool:
        with self._meta_lock:
            return self._locked

    def _check_vram_pressure_pct(self) -> Optional[float]:
        if self._pressure_checker is not None:
            try:
                return self._pressure_checker()
            except Exception:  # noqa: BLE001
                return None
        try:
            from core.llm.hardware_monitor import get_hardware_monitor

            snap = get_hardware_monitor().gpu_snapshot()
            if snap.get("available") and snap.get("vram_total_mb", 0) > 0:
                return float(snap.get("vram_used_pct", 0.0))
        except Exception:  # noqa: BLE001
            return None
        return None

    async def _invoke_unload(
        self,
        model_name: str,
        *,
        unload_fn: Optional[UnloadCallback],
        ollama_manager: Any,
    ) -> bool:
        if not model_name:
            return False
        try:
            if unload_fn is not None:
                await unload_fn(model_name)
                return True
            if ollama_manager is not None and hasattr(ollama_manager, "unload_model"):
                await ollama_manager.unload_model(model_name)
                return True
        except Exception as exc:  # noqa: BLE001
            logger.debug("[GPUScheduler] Unload callback failed for %s: %s", model_name, exc)
        return False

    async def _enter_priority_gate(self, priority: int) -> None:
        """Queue behind the active holder ordered by (priority, fifo_seq)."""
        lock = self._ensure_loop_primitives()
        waiter_entry: Optional[Tuple[int, int, asyncio.Event]] = None
        is_interactive = priority <= PRIORITY_INTERACTIVE

        with self._meta_lock:
            if not self._holder_active and not self._waiters:
                self._holder_active = True
            else:
                self._seq += 1
                ev = asyncio.Event()
                waiter_entry = (priority, self._seq, ev)
                heapq.heappush(self._waiters, waiter_entry)
                if is_interactive:
                    self._interactive_waiting += 1
                else:
                    self._background_waiting += 1

        if waiter_entry is not None:
            try:
                await waiter_entry[2].wait()
            except asyncio.CancelledError:
                with self._meta_lock:
                    if waiter_entry in self._waiters:
                        self._waiters.remove(waiter_entry)
                        heapq.heapify(self._waiters)
                    else:
                        # We were already woken and handed the baton; pass it along.
                        self._release_priority_gate_locked()
                    if is_interactive:
                        self._interactive_waiting = max(0, self._interactive_waiting - 1)
                    else:
                        self._background_waiting = max(0, self._background_waiting - 1)
                raise
            finally:
                with self._meta_lock:
                    if is_interactive:
                        self._interactive_waiting = max(0, self._interactive_waiting - 1)
                    else:
                        self._background_waiting = max(0, self._background_waiting - 1)

        await lock.acquire()

    def _release_priority_gate_locked(self) -> None:
        if self._waiters:
            _prio, _seq, next_ev = heapq.heappop(self._waiters)
            self._holder_active = True
            next_ev.set()
        else:
            self._holder_active = False

    def _exit_priority_gate(self) -> None:
        lock = self._gpu_lock
        if lock is not None and lock.locked():
            lock.release()
        with self._meta_lock:
            self._release_priority_gate_locked()

    @asynccontextmanager
    async def acquire(
        self,
        model_name: str,
        *,
        priority: int = PRIORITY_BACKGROUND,
        keep_alive: Optional[int] = None,
        unload_fn: Optional[UnloadCallback] = None,
        ollama_manager: Any = None,
        unload_on_release: Optional[bool] = None,
    ) -> AsyncIterator[GPULease]:
        """Acquire exclusive GPU access for ``model_name``.

        - Interactive priority (``PRIORITY_INTERACTIVE = 0``, e.g. Copilot) is
          woken ahead of queued background scan tasks.
        - Switching from another loaded model triggers immediate eviction of
          the previous model before running the new one.
        - Releasing with ``keep_alive == 0``, ``unload_on_release=True``, or
          under VRAM pressure triggers automatic unload.
        """
        eff_keep_alive = self._default_keep_alive_s if keep_alive is None else max(0, int(keep_alive))
        await self._enter_priority_gate(priority)

        prev_model: Optional[str] = None
        evicted_prev = False
        try:
            with self._meta_lock:
                prev_model = self._loaded_model
                self._locked = True
                self._current_model = model_name
                self._active_priority = priority
                self._lock_acquired_at = time.time()
                self._total_runs += 1

            # Evict previous model when switching to a different model.
            if prev_model and prev_model != model_name:
                if await self._invoke_unload(prev_model, unload_fn=unload_fn, ollama_manager=ollama_manager):
                    evicted_prev = True
                    with self._meta_lock:
                        self._total_unloads += 1
                        self._loaded_model = None

            with self._meta_lock:
                self._loaded_model = model_name

            lease = GPULease(
                model_name=model_name,
                priority=priority,
                keep_alive=eff_keep_alive,
                acquired_at=self._lock_acquired_at,
                previous_model=prev_model,
                evicted_previous=evicted_prev,
            )
            yield lease
        finally:
            pressure_pct = self._check_vram_pressure_pct()
            under_pressure = (
                pressure_pct is not None and pressure_pct >= self.vram_pressure_threshold_pct
            )
            should_unload = (
                (unload_on_release is True)
                or (unload_on_release is None and eff_keep_alive == 0)
                or under_pressure
            )
            if should_unload:
                unloaded = await self._invoke_unload(
                    model_name,
                    unload_fn=unload_fn,
                    ollama_manager=ollama_manager,
                )
                with self._meta_lock:
                    if unloaded or eff_keep_alive == 0:
                        self._loaded_model = None
                    if unloaded:
                        self._total_unloads += 1
                        if under_pressure:
                            self._pressure_unloads += 1
            with self._meta_lock:
                self._locked = False
                self._current_model = None
                self._active_priority = None
            self._exit_priority_gate()

    async def unload_active(
        self,
        *,
        unload_fn: Optional[UnloadCallback] = None,
        ollama_manager: Any = None,
    ) -> bool:
        """Explicitly unload whichever local model is currently tracked as resident."""
        target = self.currently_loaded_model
        if not target:
            return False
        ok = await self._invoke_unload(target, unload_fn=unload_fn, ollama_manager=ollama_manager)
        if ok:
            with self._meta_lock:
                self._loaded_model = None
                self._total_unloads += 1
        return ok

    def status(self) -> Dict[str, Any]:
        with self._meta_lock:
            elapsed = (
                round(time.time() - self._lock_acquired_at, 2)
                if self._locked and self._lock_acquired_at > 0
                else 0.0
            )
            queue_len = self._interactive_waiting + self._background_waiting
            return {
                "locked": self._locked,
                "current_model": self._current_model,
                "currently_loaded_model": self._loaded_model,
                "active_priority": self._active_priority,
                "elapsed_seconds": elapsed,
                "queue_length": queue_len,
                "interactive_waiting": self._interactive_waiting,
                "background_waiting": self._background_waiting,
                "default_keep_alive_s": self._default_keep_alive_s,
                "vram_pressure_threshold_pct": self.vram_pressure_threshold_pct,
                "total_runs": self._total_runs,
                "total_unloads": self._total_unloads,
                "pressure_unloads": self._pressure_unloads,
            }


_scheduler_singleton: Optional[GPUScheduler] = None
_scheduler_lock = threading.Lock()


def get_gpu_scheduler() -> GPUScheduler:
    """Return the process-wide ``GPUScheduler`` singleton."""
    global _scheduler_singleton
    with _scheduler_lock:
        if _scheduler_singleton is None:
            _scheduler_singleton = GPUScheduler()
        return _scheduler_singleton


def reset_gpu_scheduler_for_tests(scheduler: Optional[GPUScheduler] = None) -> GPUScheduler:
    """Replace the process-wide singleton (for isolated unit tests)."""
    global _scheduler_singleton
    with _scheduler_lock:
        _scheduler_singleton = scheduler or GPUScheduler()
        return _scheduler_singleton


__all__ = [
    "GPULease",
    "GPUScheduler",
    "PRIORITY_BACKGROUND",
    "PRIORITY_INTERACTIVE",
    "PRIORITY_NORMAL",
    "get_gpu_scheduler",
    "reset_gpu_scheduler_for_tests",
]
