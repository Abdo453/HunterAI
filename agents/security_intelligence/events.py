"""
Security Intelligence Event Definitions & Asynchronous Dispatcher
Enforces full event taxonomy with correlation and operation tracking.
"""
import asyncio
import logging
import time
import uuid
from enum import Enum
from typing import Dict, List, Callable, Any, Awaitable, Optional
from pydantic import BaseModel, Field

log = logging.getLogger("security_intelligence.events")


class SecurityEventType(str, Enum):
    # Discovery & Burp Ingestion
    BURP_TRAFFIC_STORED = "burp.traffic.stored"
    BURP_TRAFFIC_INTERESTING = "burp.traffic.interesting"
    ASSET_DISCOVERED = "security.asset_discovered"
    ENDPOINT_DISCOVERED = "security.endpoint_discovered"
    TECHNOLOGY_DETECTED = "security.technology_detected"

    # Analysis & Reasoning
    OBSERVATION_CREATED = "security.observation.created"
    ANALYSIS_COMPLETED = "security.analysis.completed"
    HYPOTHESIS_CREATED = "security.hypothesis.created"
    HYPOTHESIS_EVALUATED = "security.hypothesis.evaluated"
    EVIDENCE_ADDED = "security.evidence.added"
    FINDING_CREATED = "security.finding.created"
    DECISION_CREATED = "security.decision.created"
    FALSE_POSITIVE_FLAGGED = "security.false_positive.flagged"

    # Research & Education
    RESEARCH_COMPLETED = "security.research.completed"
    LESSON_CREATED = "security.lesson.created"
    QUIZ_CREATED = "security.quiz.created"

    # Brain Orchestration
    BRAIN_ACTION_PROPOSED = "brain.action.proposed"
    BRAIN_ACTION_APPROVED = "brain.action.approved"
    BRAIN_ACTION_BLOCKED = "brain.action.blocked"
    BRAIN_ACTION_COMPLETED = "brain.action.completed"

    # Governance & Safety
    SCOPE_VIOLATION = "security.scope_violation"


class SecurityEvent(BaseModel):
    id: str = Field(default_factory=lambda: f"EVT-{uuid.uuid4().hex[:8]}")
    event_type: SecurityEventType
    project_id: str = "default_project"
    target: str
    source: str
    data: Dict[str, Any]
    evidence_ids: List[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)
    operation_id: Optional[str] = None
    correlation_id: Optional[str] = None
    parent_event_id: Optional[str] = None
    timestamp: float = Field(default_factory=time.time)


class SecurityEventBus:
    """Asynchronous Event Bus for the Security Intelligence Layer"""

    def __init__(self):
        self._subscribers: Dict[str, List[Callable[[SecurityEvent], Awaitable[None]]]] = {
            ev.value: [] for ev in SecurityEventType
        }

    def subscribe(self, event_type: Any, handler: Callable[[SecurityEvent], Awaitable[None]]):
        """Register an async handler for a security event"""
        key = event_type.value if hasattr(event_type, "value") else str(event_type)
        if key not in self._subscribers:
            self._subscribers[key] = []
        self._subscribers[key].append(handler)

    async def publish(self, event: SecurityEvent):
        """Dispatch event to all registered subscribers concurrently without blocking"""
        key = event.event_type.value if hasattr(event.event_type, "value") else str(event.event_type)
        handlers = self._subscribers.get(key, [])
        if not handlers:
            return

        tasks = [self._safe_invoke(h, event) for h in handlers]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _safe_invoke(self, handler: Callable[[SecurityEvent], Awaitable[None]], event: SecurityEvent):
        try:
            await handler(event)
        except Exception as e:
            log.error(f"[SecurityEventBus] Error executing subscriber {handler.__name__}: {e}", exc_info=True)
