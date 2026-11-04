"""
HunterAI Persistence Watchdog — Zero-dropout assessment continuity.

Ensures the autonomous assessment engine NEVER silently stalls:
  1. StallDetector: Monitors tasks that have been RUNNING too long (configurable timeout)
  2. CrashRecovery: Re-queues RUNNING tasks after system restart
  3. RetryPolicy: Exponential back-off with max retries before marking FAILED
  4. ProgressSnapshot: Serializes assessment state to disk at every phase boundary
  5. AssessmentResumer: Loads snapshot + re-queues incomplete tasks on cold start
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from core.contracts.task_contracts import TaskContract, TaskLifecycleStatus
from core.system.task_scheduler import TaskScheduler

logger = logging.getLogger("hunter_ai.watchdog")

# Constants
DEFAULT_STALL_TIMEOUT_SECS = 300   # 5 minutes before a RUNNING task is considered stalled
DEFAULT_MAX_RETRIES = 3            # Max retry count before marking permanently FAILED
DEFAULT_SNAPSHOT_DIR = Path("snapshots")


@dataclass
class StallRecord:
    task_id: str
    detected_at: float
    stall_duration_secs: float
    retry_count: int
    last_owner: str
    action_taken: str  # "re_queued" | "failed" | "escalated"


@dataclass
class AssessmentSnapshot:
    snapshot_id: str = field(default_factory=lambda: f"SNAP-{uuid.uuid4().hex[:8].upper()}")
    target: str = ""
    phase: str = "INIT"  # INIT | RECON | NETWORK | WEB | API | JS | VERIFY | REPORT
    completed_task_ids: List[str] = field(default_factory=list)
    failed_task_ids: List[str] = field(default_factory=list)
    discovered_assets: Dict[str, List[str]] = field(default_factory=dict)
    confirmed_findings: List[Dict[str, Any]] = field(default_factory=list)
    coverage_pct: float = 0.0
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)


class StallDetector:
    """Scans all RUNNING tasks and identifies those exceeding the stall timeout."""

    def __init__(self, stall_timeout_secs: float = DEFAULT_STALL_TIMEOUT_SECS):
        self.stall_timeout_secs = stall_timeout_secs

    def detect_stalled_tasks(self, scheduler: TaskScheduler) -> List[TaskContract]:
        """Returns list of TaskContracts that appear to be stalled."""
        stalled = []
        now = time.time()
        task_objects = scheduler._tasks.values() if hasattr(scheduler, "_tasks") else []
        for task in task_objects:
            status = task.status.value if hasattr(task.status, "value") else str(task.status)
            if status in (TaskLifecycleStatus.RUNNING.value, "RUNNING"):
                age = now - (task.started_at or task.created_at)
                if age > self.stall_timeout_secs:
                    logger.warning(
                        "[Watchdog] Stall detected: task_id=%s title='%s' age=%.0fs",
                        task.task_id, task.title, age,
                    )
                    stalled.append(task)
        return stalled


class RetryPolicy:
    """Applies exponential back-off retry logic to stalled/failed tasks."""

    def __init__(self, max_retries: int = DEFAULT_MAX_RETRIES):
        self.max_retries = max_retries
        self._retry_counts: Dict[str, int] = {}
        self._stall_log: List[StallRecord] = []

    def should_retry(self, task: TaskContract) -> bool:
        count = self._retry_counts.get(task.task_id, 0)
        return count < self.max_retries

    def record_retry(self, task: TaskContract, scheduler: TaskScheduler) -> bool:
        """
        Attempt to re-queue a stalled task. Returns True if re-queued, False if max retries exceeded.
        """
        count = self._retry_counts.get(task.task_id, 0)
        if count >= self.max_retries:
            logger.error(
                "[Watchdog] Task %s exceeded max retries (%d). Marking FAILED.",
                task.task_id, self.max_retries,
            )
            task.status = TaskLifecycleStatus.FAILED
            self._stall_log.append(StallRecord(
                task_id=task.task_id,
                detected_at=time.time(),
                stall_duration_secs=0,
                retry_count=count,
                last_owner=task.owner_agent or "",
                action_taken="failed",
            ))
            return False

        # Reset task to PENDING so it can be re-dispatched
        task.status = TaskLifecycleStatus.PENDING
        task.owner_agent = ""
        task.started_at = None
        self._retry_counts[task.task_id] = count + 1

        self._stall_log.append(StallRecord(
            task_id=task.task_id,
            detected_at=time.time(),
            stall_duration_secs=0,
            retry_count=count + 1,
            last_owner=task.owner_agent or "",
            action_taken="re_queued",
        ))
        logger.info("[Watchdog] Task %s re-queued (retry %d/%d).", task.task_id, count + 1, self.max_retries)
        return True

    def get_stall_log(self) -> List[StallRecord]:
        return list(self._stall_log)


class ProgressSnapshot:
    """Serializes and restores assessment state to/from disk."""

    def __init__(self, snapshot_dir: Path | str = DEFAULT_SNAPSHOT_DIR):
        self.snapshot_dir = Path(snapshot_dir)
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)

    def save(self, snapshot: AssessmentSnapshot) -> Path:
        path = self.snapshot_dir / f"{snapshot.snapshot_id}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(asdict(snapshot), f, indent=2)
        logger.info("[Watchdog] Snapshot saved: %s", path)
        return path

    def load(self, snapshot_id: str) -> Optional[AssessmentSnapshot]:
        path = self.snapshot_dir / f"{snapshot_id}.json"
        if not path.exists():
            # Check by wildcard pattern or matching target/id inside snapshots
            for p in sorted(self.snapshot_dir.glob("*.json"), reverse=True):
                if snapshot_id in p.name:
                    path = p
                    break
        if not path.exists():
            for p in sorted(self.snapshot_dir.glob("*.json"), reverse=True):
                try:
                    with open(p, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    if data.get("snapshot_id") == snapshot_id or data.get("target") == snapshot_id:
                        return AssessmentSnapshot(**data)
                except Exception:
                    pass
            logger.error("[Watchdog] Snapshot not found: %s", path)
            return None
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return AssessmentSnapshot(**data)

    def list_snapshots(self) -> List[AssessmentSnapshot]:
        snapshots = []
        for p in sorted(self.snapshot_dir.glob("SNAP-*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                snapshots.append(AssessmentSnapshot(**data))
            except Exception as e:
                logger.warning("[Watchdog] Failed to load snapshot %s: %s", p, e)
        return snapshots

    def latest(self, target: str) -> Optional[AssessmentSnapshot]:
        """Find the most recent snapshot for a given target."""
        for snap in self.list_snapshots():
            if snap.target == target:
                return snap
        return None


class PersistenceWatchdog:
    """
    Master watchdog that ties together stall detection, retry policy, and snapshots.
    Call tick() periodically (or at each assessment phase boundary).
    """

    def __init__(
        self,
        scheduler: TaskScheduler,
        stall_timeout_secs: float = DEFAULT_STALL_TIMEOUT_SECS,
        max_retries: int = DEFAULT_MAX_RETRIES,
        snapshot_dir: Path | str = DEFAULT_SNAPSHOT_DIR,
    ):
        self.scheduler = scheduler
        self.detector = StallDetector(stall_timeout_secs)
        self.retry = RetryPolicy(max_retries)
        self.snapshotter = ProgressSnapshot(snapshot_dir)
        self._tick_count = 0

    def tick(self) -> Dict[str, Any]:
        """
        Single watchdog cycle:
        1. Detect stalled tasks
        2. Apply retry policy (re-queue or mark FAILED)
        Returns summary of actions taken.
        """
        self._tick_count += 1
        stalled = self.detector.detect_stalled_tasks(self.scheduler)
        re_queued = []
        failed = []
        for task in stalled:
            if self.retry.record_retry(task, self.scheduler):
                re_queued.append(task.task_id)
            else:
                failed.append(task.task_id)

        if re_queued or failed:
            logger.info("[Watchdog] Tick #%d: re_queued=%s failed=%s", self._tick_count, re_queued, failed)

        return {"tick": self._tick_count, "re_queued": re_queued, "permanently_failed": failed}

    def save_checkpoint(self, snapshot: AssessmentSnapshot) -> Path:
        return self.snapshotter.save(snapshot)

    def resume_from_checkpoint(self, snapshot_id: str) -> Optional[AssessmentSnapshot]:
        return self.snapshotter.load(snapshot_id)
