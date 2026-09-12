"""
HunterAI Task Lifecycle & Schema
Defines states: CREATED -> QUEUED -> PLANNING -> ANALYZING -> VALIDATING -> COMPLETED (or FAILED, WAITING_APPROVAL).
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from hunter_ai.agents.capabilities import AgentCapability


class TaskLifecycleState(str, Enum):
    CREATED = "created"
    QUEUED = "queued"
    PLANNING = "planning"
    ANALYZING = "analyzing"
    CRITIC_REVIEW = "critic_review"
    VALIDATING = "validating"
    COMPLETED = "completed"
    FAILED = "failed"
    RETRYING = "retrying"
    WAITING_APPROVAL = "waiting_approval"


@dataclass
class HunterTask:
    task_id: str = field(default_factory=lambda: f"task_{uuid.uuid4().hex[:8]}")
    origin_agent: str = "WebAgent"
    required_capabilities: Set[AgentCapability] = field(default_factory=set)
    target_url: str = ""
    raw_payload: Dict[str, Any] = field(default_factory=dict)
    state: TaskLifecycleState = TaskLifecycleState.CREATED
    state_history: List[TaskLifecycleState] = field(default_factory=list)
    risk_level: str = "low"  # low, medium, high, critical
    contains_sensitive_data: bool = False
    requires_human_approval: bool = False
    max_retries: int = 3
    retry_count: int = 0
    created_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None
    error_message: Optional[str] = None

    def transition_to(self, new_state: TaskLifecycleState):
        self.state_history.append(self.state)
        self.state = new_state
        if new_state in (TaskLifecycleState.COMPLETED, TaskLifecycleState.FAILED):
            self.completed_at = time.time()
