"""Canonical 7-state lifecycle state machine and Flow -> Task -> Subtask hierarchy.

Lifecycle recovery and node state hierarchy patterns adapted from:
- vxcontrol/pentagi (commit ``cffed9485aa1cca70762cd08a57ac62a80406258``, MIT;
  see ``THIRD_PARTY_LICENSES/PENTAGI_MIT.txt`` and ``NOTICE``)
- PentesterFlow/agent (commit ``0759d873a07350a70283c9751f7d136905f777c7``, Apache-2.0;
  see ``THIRD_PARTY_LICENSES/PENTESTERFLOW_APACHE2.txt`` and ``NOTICE``)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Tuple


class LifecycleState(str, Enum):
    """Canonical 7-state runtime lifecycle shared across Flow, Task, and Subtask."""

    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    WAITING = "WAITING"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


ACTIVE_STATES: FrozenSet[LifecycleState] = frozenset(
    {
        LifecycleState.QUEUED,
        LifecycleState.RUNNING,
        LifecycleState.WAITING,
        LifecycleState.PAUSED,
    }
)

IN_FLIGHT_STATES: FrozenSet[LifecycleState] = frozenset(
    {
        LifecycleState.QUEUED,
        LifecycleState.RUNNING,
        LifecycleState.WAITING,
    }
)

TERMINAL_STATES: FrozenSet[LifecycleState] = frozenset(
    {
        LifecycleState.COMPLETED,
        LifecycleState.FAILED,
        LifecycleState.CANCELLED,
    }
)

VALID_TRANSITIONS: Dict[LifecycleState, FrozenSet[LifecycleState]] = {
    LifecycleState.QUEUED: frozenset(
        {
            LifecycleState.RUNNING,
            LifecycleState.PAUSED,
            LifecycleState.CANCELLED,
            LifecycleState.FAILED,
        }
    ),
    LifecycleState.RUNNING: frozenset(
        {
            LifecycleState.WAITING,
            LifecycleState.PAUSED,
            LifecycleState.COMPLETED,
            LifecycleState.FAILED,
            LifecycleState.CANCELLED,
        }
    ),
    LifecycleState.WAITING: frozenset(
        {
            LifecycleState.RUNNING,
            LifecycleState.PAUSED,
            LifecycleState.COMPLETED,
            LifecycleState.FAILED,
            LifecycleState.CANCELLED,
        }
    ),
    LifecycleState.PAUSED: frozenset(
        {
            LifecycleState.QUEUED,
            LifecycleState.RUNNING,
            LifecycleState.WAITING,
            LifecycleState.CANCELLED,
            LifecycleState.FAILED,
        }
    ),
    LifecycleState.COMPLETED: frozenset(),
    LifecycleState.FAILED: frozenset(),
    LifecycleState.CANCELLED: frozenset(),
}


class InvalidStateTransitionError(ValueError):
    """Raised when an illegal lifecycle state transition is attempted."""

    def __init__(self, src: LifecycleState, dst: LifecycleState, entity_id: str = "") -> None:
        prefix = f"[{entity_id}] " if entity_id else ""
        super().__init__(f"{prefix}Invalid lifecycle transition: {src.value} -> {dst.value}")
        self.src = src
        self.dst = dst
        self.entity_id = entity_id


_LEGACY_TO_CANONICAL: Dict[str, Tuple[LifecycleState, Dict[str, Any]]] = {
    "pending": (LifecycleState.QUEUED, {}),
    "queued": (LifecycleState.QUEUED, {}),
    "created": (LifecycleState.QUEUED, {}),
    "init": (LifecycleState.QUEUED, {}),
    "running": (LifecycleState.RUNNING, {}),
    "in_progress": (LifecycleState.RUNNING, {}),
    "active": (LifecycleState.RUNNING, {}),
    "waiting": (LifecycleState.WAITING, {}),
    "awaiting_input": (LifecycleState.WAITING, {}),
    "awaiting_approval": (LifecycleState.WAITING, {}),
    "paused": (LifecycleState.PAUSED, {}),
    "interrupted": (
        LifecycleState.PAUSED,
        {"recoverable": True, "legacy_status": "interrupted"},
    ),
    "completed": (LifecycleState.COMPLETED, {}),
    "finished": (LifecycleState.COMPLETED, {}),
    "done": (LifecycleState.COMPLETED, {}),
    "success": (LifecycleState.COMPLETED, {}),
    "failed": (LifecycleState.FAILED, {}),
    "error": (LifecycleState.FAILED, {}),
    "stopped": (LifecycleState.CANCELLED, {}),
    "stopping": (LifecycleState.CANCELLED, {}),
    "cancelled": (LifecycleState.CANCELLED, {}),
    "canceled": (LifecycleState.CANCELLED, {}),
    "aborted": (LifecycleState.CANCELLED, {}),
}

_CANONICAL_TO_LEGACY: Dict[LifecycleState, str] = {
    LifecycleState.QUEUED: "pending",
    LifecycleState.RUNNING: "running",
    LifecycleState.WAITING: "waiting",
    LifecycleState.PAUSED: "paused",
    LifecycleState.COMPLETED: "completed",
    LifecycleState.FAILED: "failed",
    LifecycleState.CANCELLED: "stopped",
}


def to_canonical_status(raw: str | LifecycleState) -> Tuple[LifecycleState, Dict[str, Any]]:
    """Convert any canonical or legacy status string to ``(LifecycleState, metadata)``."""
    if isinstance(raw, LifecycleState):
        return raw, {}
    key = str(raw or "").strip().lower()
    if key in _LEGACY_TO_CANONICAL:
        state, meta = _LEGACY_TO_CANONICAL[key]
        return state, dict(meta)
    raise ValueError(f"Unknown lifecycle status: {raw!r}")


def to_legacy_status(
    state: str | LifecycleState,
    *,
    recoverable: bool = False,
    prefer_interrupted_alias: bool = False,
) -> str:
    """Convert canonical ``LifecycleState`` to its backward-compatible legacy status string."""
    canon, meta = to_canonical_status(state)
    if canon == LifecycleState.PAUSED and (recoverable or meta.get("recoverable")) and prefer_interrupted_alias:
        return "interrupted"
    return _CANONICAL_TO_LEGACY[canon]


def expand_status_filter(raw_status: str) -> Tuple[Tuple[str, ...], bool]:
    """Return ``(db_status_values_lower, match_recoverable_paused)`` for a status query filter.

    Preserves bidirectional compatibility:
    - ``pending`` / ``QUEUED`` -> matches ``('pending', 'queued')``
    - ``stopped`` / ``CANCELLED`` -> matches ``('stopped', 'cancelled', 'canceled', 'stopping')``
    - ``interrupted`` -> matches ``('interrupted',)`` PLUS recoverable ``paused`` runs
    - ``paused`` / ``PAUSED`` -> matches ``('paused', 'interrupted')``
    """
    norm = str(raw_status or "").strip().lower()
    if not norm:
        return (), False
    if norm == "interrupted":
        return ("interrupted",), True
    if norm in {"pending", "queued", "created"}:
        return ("pending", "queued", "created"), False
    if norm in {"stopped", "cancelled", "canceled", "stopping"}:
        return ("stopped", "cancelled", "canceled", "stopping"), False
    if norm == "paused":
        return ("paused", "interrupted"), False
    if norm in {"running", "active", "in_progress"}:
        return ("running", "active", "in_progress"), False
    if norm in {"waiting", "awaiting_input", "awaiting_approval"}:
        return ("waiting", "awaiting_input", "awaiting_approval"), False
    if norm in {"completed", "finished", "done"}:
        return ("completed", "finished", "done"), False
    if norm in {"failed", "error"}:
        return ("failed", "error"), False
    return (norm,), False


def can_transition(src: str | LifecycleState, dst: str | LifecycleState) -> bool:
    """Return True if transitioning from *src* to *dst* is permitted."""
    src_state, _ = to_canonical_status(src)
    dst_state, _ = to_canonical_status(dst)
    if src_state == dst_state:
        return True
    return dst_state in VALID_TRANSITIONS[src_state]


def assert_transition(
    src: str | LifecycleState,
    dst: str | LifecycleState,
    *,
    entity_id: str = "",
) -> LifecycleState:
    """Validate and return *dst* ``LifecycleState``, raising ``InvalidStateTransitionError`` if illegal."""
    src_state, _ = to_canonical_status(src)
    dst_state, _ = to_canonical_status(dst)
    if src_state == dst_state:
        return dst_state
    if dst_state not in VALID_TRANSITIONS[src_state]:
        raise InvalidStateTransitionError(src_state, dst_state, entity_id=entity_id)
    return dst_state


@dataclass
class SubtaskNode:
    """Leaf execution unit under a TaskNode."""

    subtask_id: str
    task_id: str
    run_id: str
    title: str
    state: LifecycleState = LifecycleState.QUEUED
    depends_on: List[str] = field(default_factory=list)
    input_data: Dict[str, Any] = field(default_factory=dict)
    output_data: Dict[str, Any] = field(default_factory=dict)
    error: str = ""
    attempt: int = 0
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def transition_to(self, target: str | LifecycleState, *, error: str = "") -> LifecycleState:
        next_state = assert_transition(self.state, target, entity_id=self.subtask_id)
        now = time.time()
        self.state = next_state
        self.updated_at = now
        if next_state == LifecycleState.RUNNING and self.started_at is None:
            self.started_at = now
            self.attempt += 1
        elif next_state in TERMINAL_STATES:
            self.finished_at = now
        if error:
            self.error = error
        return self.state

    def to_dict(self) -> Dict[str, Any]:
        return {
            "subtask_id": self.subtask_id,
            "task_id": self.task_id,
            "run_id": self.run_id,
            "title": self.title,
            "status": self.state.value,
            "legacy_status": to_legacy_status(self.state),
            "depends_on": list(self.depends_on),
            "input": dict(self.input_data),
            "output": dict(self.output_data),
            "error": self.error,
            "attempt": self.attempt,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass
class TaskNode:
    """Task unit under a FlowNode, owning zero or more SubtaskNodes."""

    task_id: str
    run_id: str
    title: str
    role: str = "worker"
    state: LifecycleState = LifecycleState.QUEUED
    priority: int = 5
    depends_on: List[str] = field(default_factory=list)
    input_data: Dict[str, Any] = field(default_factory=dict)
    output_data: Dict[str, Any] = field(default_factory=dict)
    error: str = ""
    recoverable: bool = False
    subtasks: Dict[str, SubtaskNode] = field(default_factory=dict)
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def transition_to(
        self,
        target: str | LifecycleState,
        *,
        error: str = "",
        recoverable: Optional[bool] = None,
    ) -> LifecycleState:
        next_state = assert_transition(self.state, target, entity_id=self.task_id)
        now = time.time()
        self.state = next_state
        self.updated_at = now
        if next_state == LifecycleState.RUNNING and self.started_at is None:
            self.started_at = now
        elif next_state in TERMINAL_STATES:
            self.finished_at = now
        if recoverable is not None:
            self.recoverable = bool(recoverable)
        if error:
            self.error = error
        return self.state

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "run_id": self.run_id,
            "title": self.title,
            "role": self.role,
            "status": self.state.value,
            "legacy_status": to_legacy_status(self.state, recoverable=self.recoverable),
            "priority": self.priority,
            "depends_on": list(self.depends_on),
            "input": dict(self.input_data),
            "output": dict(self.output_data),
            "error": self.error,
            "recoverable": self.recoverable,
            "subtasks": [st.to_dict() for st in self.subtasks.values()],
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass
class FlowNode:
    """Top-level run/flow lifecycle entity owning TaskNodes."""

    run_id: str
    kind: str
    target: str = ""
    engagement_id: Optional[str] = None
    state: LifecycleState = LifecycleState.QUEUED
    current_phase: str = "INIT"
    progress: float = 0.0
    recoverable: bool = False
    tasks: Dict[str, TaskNode] = field(default_factory=dict)
    meta: Dict[str, Any] = field(default_factory=dict)
    error: str = ""
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def transition_to(
        self,
        target: str | LifecycleState,
        *,
        phase: Optional[str] = None,
        progress: Optional[float] = None,
        error: str = "",
        recoverable: Optional[bool] = None,
    ) -> LifecycleState:
        next_state = assert_transition(self.state, target, entity_id=self.run_id)
        now = time.time()
        self.state = next_state
        self.updated_at = now
        if next_state == LifecycleState.RUNNING and self.started_at is None:
            self.started_at = now
        elif next_state in TERMINAL_STATES:
            self.finished_at = now
        if phase is not None:
            self.current_phase = phase
        if progress is not None:
            self.progress = float(progress)
        if recoverable is not None:
            self.recoverable = bool(recoverable)
        if error:
            self.error = error
        return self.state

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "kind": self.kind,
            "target": self.target,
            "engagement_id": self.engagement_id,
            "status": to_legacy_status(self.state, recoverable=self.recoverable),
            "canonical_status": self.state.value,
            "current_phase": self.current_phase,
            "progress": self.progress,
            "recoverable": self.recoverable,
            "tasks": [t.to_dict() for t in self.tasks.values()],
            "meta": dict(self.meta),
            "error": self.error,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }
