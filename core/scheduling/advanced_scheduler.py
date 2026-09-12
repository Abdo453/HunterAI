"""
Advanced Multi-Target Scheduler & Rate-Limit Engine
"Resource-Aware Assessment Queueing & Adaptive Rate Limiting"

ينظم ويجدول مهام الفحص المتعدد بذكاء:
1. احترام حدود معدل الطلبات (Rate Limiting & 429 Exponential Backoff)
2. طابور أولويات غير متزامن (Priority Async Task Queue)
3. إدارة التزامن والموارد الحسابية للـ GPU والشبكة
4. تتبع حالة كل هدف (Queued, Running, Throttled, Completed)
"""
import asyncio
import logging
import random
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

log = logging.getLogger("scheduling.advanced_scheduler")


class TargetStatus(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    THROTTLED = "THROTTLED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


@dataclass(order=True)
class TargetAssessmentTask:
    priority: int
    target: str = field(compare=False)
    mode: str = field(compare=False, default="standard")
    task_id: str = field(compare=False, default="")
    status: TargetStatus = field(compare=False, default=TargetStatus.QUEUED)
    findings_count: int = field(compare=False, default=0)
    created_at: float = field(compare=False, default_factory=time.time)
    started_at: Optional[float] = field(compare=False, default=None)
    completed_at: Optional[float] = field(compare=False, default=None)
    error: Optional[str] = field(compare=False, default=None)


class AdaptiveRateLimiter:
    """متحكم معدل الطلبات والتراجع الأسي عند الحظر"""

    def __init__(self, base_delay: float = 0.2, max_delay: float = 30.0):
        self.base_delay = base_delay
        self.max_delay = max_delay
        self._target_delays: Dict[str, float] = {}
        self._consecutive_throttles: Dict[str, int] = {}

    def get_delay(self, target_host: str) -> float:
        """استرجاع التأخير الزمني المناسب للهدف"""
        return self._target_delays.get(target_host, self.base_delay)

    def record_success(self, target_host: str):
        """تقليل التأخير تدريجياً عند نجاح الطلبات"""
        self._consecutive_throttles[target_host] = 0
        current = self._target_delays.get(target_host, self.base_delay)
        # Gradually decrease back towards base_delay
        self._target_delays[target_host] = max(self.base_delay, current * 0.9)

    def record_throttle(self, target_host: str, retry_after: Optional[float] = None) -> float:
        """زيادة التأخير بشكل أسي عند مواجهة 429 Too Many Requests"""
        count = self._consecutive_throttles.get(target_host, 0) + 1
        self._consecutive_throttles[target_host] = count

        if retry_after and retry_after > 0:
            delay = min(retry_after, self.max_delay)
        else:
            # Exponential backoff + jitter
            jitter = random.uniform(0.5, 1.5)
            delay = min(self.base_delay * (2 ** count) * jitter, self.max_delay)

        self._target_delays[target_host] = delay
        log.warning(f"[RateLimiter] Throttling on {target_host}: backed off to {delay:.2f}s")
        return delay


class AdvancedScheduler:
    """جدولة وإدارة فحص الأهداف المتعددة"""

    def __init__(self, max_concurrent_targets: int = 3):
        self.max_concurrent = max_concurrent_targets
        self.rate_limiter = AdaptiveRateLimiter()
        self._task_queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self._tasks: Dict[str, TargetAssessmentTask] = {}
        self._semaphore = asyncio.Semaphore(max_concurrent_targets)
        self._running = False

    def enqueue_target(
        self,
        target: str,
        mode: str = "standard",
        priority: int = 5
    ) -> str:
        """إضافة هدف جديد إلى طابور الفحص"""
        task_id = f"task_{int(time.time()*1000)}_{random.randint(100, 999)}"
        task = TargetAssessmentTask(
            priority=priority,
            target=target,
            mode=mode,
            task_id=task_id,
            status=TargetStatus.QUEUED
        )
        self._tasks[task_id] = task
        self._task_queue.put_nowait(task)
        log.info(f"[Scheduler] Queued target {target} (task_id: {task_id}, priority: {priority})")
        return task_id

    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """الاستعلام عن حالة مهمة معينة"""
        task = self._tasks.get(task_id)
        if not task:
            return None
        return {
            "task_id": task.task_id,
            "target": task.target,
            "mode": task.mode,
            "priority": task.priority,
            "status": task.status.value,
            "findings_count": task.findings_count,
            "duration": round(task.completed_at - task.started_at, 2) if (task.completed_at and task.started_at) else None,
            "error": task.error
        }

    def list_all_tasks(self) -> List[Dict[str, Any]]:
        """استعراض جميع المهام المجدولة والحالية"""
        return [self.get_task_status(tid) for tid in self._tasks.keys()]

    async def run_worker(self, execute_fn: Callable[[TargetAssessmentTask], Any]):
        """معالج الطابور الرئيسي لتنفيذ المهام بالتوازي مع احترام التزامن"""
        self._running = True
        while self._running:
            try:
                task: TargetAssessmentTask = await asyncio.wait_for(self._task_queue.get(), timeout=2.0)
            except asyncio.TimeoutError:
                continue

            async with self._semaphore:
                task.status = TargetStatus.RUNNING
                task.started_at = time.time()
                log.info(f"[Scheduler] Starting assessment for {task.target}")
                try:
                    result = await execute_fn(task)
                    task.status = TargetStatus.COMPLETED
                    task.findings_count = len(result.get("findings", [])) if isinstance(result, dict) else 0
                except Exception as e:
                    task.status = TargetStatus.FAILED
                    task.error = str(e)
                    log.error(f"[Scheduler] Task {task.task_id} failed: {e}")
                finally:
                    task.completed_at = time.time()
                    self._task_queue.task_done()
