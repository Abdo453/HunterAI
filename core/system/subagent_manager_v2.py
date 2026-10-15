"""
HunterAI Subagents 2.0 — Task Delegation & Lifecycle Manager (Phase 6)
======================================================================
Manages spawning, lifecycle tracking, health monitoring, and workflow
orchestration of isolated worker subagents.
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("hunter_ai.subagents_v2")


class SubagentStatus(str, Enum):
    IDLE = "IDLE"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    STALLED = "STALLED"
    TERMINATED = "TERMINATED"


@dataclass
class SubagentInstance:
    subagent_id: str
    task: str
    model: str
    tools: List[str]
    status: SubagentStatus = SubagentStatus.IDLE
    parent_agent_id: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    last_heartbeat: float = field(default_factory=time.time)
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def ping_heartbeat(self) -> None:
        self.last_heartbeat = time.time()
        self.updated_at = self.last_heartbeat

    def mark_completed(self, result: Dict[str, Any]) -> None:
        self.status = SubagentStatus.COMPLETED
        self.result = result
        self.updated_at = time.time()

    def mark_failed(self, error: str) -> None:
        self.status = SubagentStatus.FAILED
        self.error = error
        self.updated_at = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "subagent_id": self.subagent_id,
            "task": self.task,
            "model": self.model,
            "tools": self.tools,
            "status": self.status.value,
            "parent_agent_id": self.parent_agent_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "last_heartbeat": self.last_heartbeat,
            "has_result": self.result is not None,
            "error": self.error,
        }


class SubagentManager:
    """
    Spawns, monitors, and supervises subagents with stall detection.
    """
    def __init__(self, task_scheduler: Optional[Any] = None, heartbeat_timeout_seconds: float = 300.0):
        self.task_scheduler = task_scheduler
        self.heartbeat_timeout = heartbeat_timeout_seconds
        self._subagents: Dict[str, SubagentInstance] = {}
        self._execution_handlers: Dict[str, Callable] = {}

    def register_execution_handler(self, task_type: str, handler: Callable) -> None:
        self._execution_handlers[task_type] = handler

    def launch_subagent(
        self,
        task: str,
        model: str = "qwen3:8b",
        tools: Optional[List[str]] = None,
        parent_agent_id: Optional[str] = None,
        task_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SubagentInstance:
        """Spawns an isolated subagent instance"""
        subagent_id = f"subagent-{uuid.uuid4().hex[:8]}"
        instance = SubagentInstance(
            subagent_id=subagent_id,
            task=task,
            model=model,
            tools=tools or [],
            status=SubagentStatus.RUNNING,
            parent_agent_id=parent_agent_id,
            metadata=metadata or {},
        )
        self._subagents[subagent_id] = instance
        logger.info("Subagent launched: id=%s task='%s' model=%s tools=%s", subagent_id, task, model, tools)
        
        # Link to task scheduler if available
        if self.task_scheduler and hasattr(self.task_scheduler, "register_subagent"):
            self.task_scheduler.register_subagent(task_id or subagent_id, subagent_id)
            
        return instance

    def get_subagent(self, subagent_id: str) -> Optional[SubagentInstance]:
        return self._subagents.get(subagent_id)

    def monitor_subagents(self) -> Dict[str, Any]:
        """
        Scans all subagents, detects stale heartbeats (marking STALLED),
        and returns a health status report.
        """
        now = time.time()
        counts: Dict[str, int] = {s.value: 0 for s in SubagentStatus}
        stalled_ids: List[str] = []

        for sid, sub in self._subagents.items():
            if sub.status == SubagentStatus.RUNNING:
                if now - sub.last_heartbeat > self.heartbeat_timeout:
                    sub.status = SubagentStatus.STALLED
                    sub.error = f"Heartbeat timed out after {self.heartbeat_timeout}s"
                    stalled_ids.append(sid)
            counts[sub.status.value] += 1

        return {
            "total_subagents": len(self._subagents),
            "counts": counts,
            "stalled_ids": stalled_ids,
            "active_subagents": [s.to_dict() for s in self._subagents.values() if s.status == SubagentStatus.RUNNING],
        }

    def terminate_subagent(self, subagent_id: str, reason: str = "Operator requested") -> bool:
        sub = self._subagents.get(subagent_id)
        if not sub:
            return False
        sub.status = SubagentStatus.TERMINATED
        sub.error = reason
        sub.updated_at = time.time()
        logger.info("Subagent terminated: %s (reason: %s)", subagent_id, reason)
        return True
