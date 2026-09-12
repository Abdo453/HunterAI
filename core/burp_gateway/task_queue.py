"""
Burp Task Queue
===============
Manages and executes scan, plan, and probe tasks triggered via Burp Suite context menus.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("hunter_ai.task_queue")


class TaskStatus(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class TaskAction(str, Enum):
    SCAN = "SCAN"
    PLAN = "PLAN"
    PROBE = "PROBE"
    ADD_SCOPE = "ADD_SCOPE"


@dataclass
class BurpTask:
    task_id: str
    action: TaskAction
    target_url: str
    status: TaskStatus = TaskStatus.QUEUED
    payload: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=lambda: time.time())
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["action"] = self.action.value
        d["status"] = self.status.value
        return d


class TaskQueue:
    """Async task dispatcher for incoming Burp Suite instructions"""

    def __init__(self, executor_fn: Optional[Callable[[BurpTask], Any]] = None):
        self._tasks: Dict[str, BurpTask] = {}
        self._queue: asyncio.Queue[BurpTask] = asyncio.Queue()
        self.executor_fn = executor_fn
        self._worker_task: Optional[asyncio.Task] = None
        self._running: bool = False

    def enqueue(self, action: TaskAction, target_url: str, payload: Optional[Dict[str, Any]] = None) -> BurpTask:
        payload = payload or {}
        tid = f"task_{hashlib.sha256(f'{action}:{target_url}:{time.time()}'.encode()).hexdigest()[:8]}"
        task = BurpTask(task_id=tid, action=action, target_url=target_url, payload=payload)
        self._tasks[tid] = task
        self._queue.put_nowait(task)
        logger.info(f"[TASK_QUEUE] Enqueued task {tid} [{action.value}] -> {target_url}")
        return task

    def get_task(self, task_id: str) -> Optional[BurpTask]:
        return self._tasks.get(task_id)

    def list_tasks(self, limit: int = 50) -> List[Dict[str, Any]]:
        return [t.to_dict() for t in list(self._tasks.values())[-limit:]]

    async def start(self):
        if self._running:
            return
        self._running = True
        self._worker_task = asyncio.create_task(self._worker_loop())

    async def stop(self):
        self._running = False
        if self._worker_task:
            self._worker_task.cancel()

    async def _worker_loop(self):
        while self._running:
            try:
                task = await self._queue.get()
                task.status = TaskStatus.RUNNING
                task.started_at = time.time()
                logger.info(f"[TASK_QUEUE] Running {task.task_id} on {task.target_url}...")

                if self.executor_fn:
                    try:
                        res = self.executor_fn(task)
                        if asyncio.iscoroutine(res):
                            res = await res
                        task.result = res
                        task.status = TaskStatus.COMPLETED
                    except Exception as e:
                        logger.error(f"[TASK_QUEUE] Error running task {task.task_id}: {e}")
                        task.status = TaskStatus.FAILED
                        task.error = str(e)
                else:
                    task.status = TaskStatus.COMPLETED
                    task.result = {"message": "Queued task acknowledged (no executor attached)"}

                task.completed_at = time.time()
                self._queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[TASK_QUEUE] Worker exception: {e}")
                await asyncio.sleep(0.5)
