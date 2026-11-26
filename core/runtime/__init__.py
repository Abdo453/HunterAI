"""Canonical runtime lifecycle, persistent event bus, bounded agent manager, and unified orchestrator."""

from __future__ import annotations

import threading
from typing import Optional

from core.runtime.agent_manager import AgentManager, InputReply, run_without_cancel
from core.runtime.event_bus import PersistentEventBus, parse_last_event_id
from core.runtime.orchestrator import RuntimeOrchestrator
from core.runtime.state_machine import (
    ACTIVE_STATES,
    IN_FLIGHT_STATES,
    TERMINAL_STATES,
    VALID_TRANSITIONS,
    FlowNode,
    InvalidStateTransitionError,
    LifecycleState,
    SubtaskNode,
    TaskNode,
    assert_transition,
    can_transition,
    expand_status_filter,
    to_canonical_status,
    to_legacy_status,
)

_ORCH_LOCK = threading.Lock()
_GLOBAL_EVENT_BUS: Optional[PersistentEventBus] = None
_GLOBAL_AGENT_MANAGER: Optional[AgentManager] = None
_GLOBAL_RUNTIME_ORCHESTRATOR: Optional[RuntimeOrchestrator] = None


def get_persistent_event_bus() -> PersistentEventBus:
    global _GLOBAL_EVENT_BUS
    with _ORCH_LOCK:
        if _GLOBAL_EVENT_BUS is None:
            _GLOBAL_EVENT_BUS = PersistentEventBus()
        return _GLOBAL_EVENT_BUS


def get_agent_manager() -> AgentManager:
    global _GLOBAL_AGENT_MANAGER
    with _ORCH_LOCK:
        if _GLOBAL_AGENT_MANAGER is None:
            from core.config.manager import get_config_manager

            max_agents = get_config_manager().get_int("max_concurrent_agents", 5)
            _GLOBAL_AGENT_MANAGER = AgentManager(
                max_concurrent_agents=max_agents,
                event_bus=get_persistent_event_bus(),
            )
        return _GLOBAL_AGENT_MANAGER


def get_runtime_orchestrator() -> RuntimeOrchestrator:
    global _GLOBAL_RUNTIME_ORCHESTRATOR
    with _ORCH_LOCK:
        if _GLOBAL_RUNTIME_ORCHESTRATOR is None:
            _GLOBAL_RUNTIME_ORCHESTRATOR = RuntimeOrchestrator(
                event_bus=get_persistent_event_bus(),
                agent_manager=get_agent_manager(),
            )
        return _GLOBAL_RUNTIME_ORCHESTRATOR


__all__ = [
    "ACTIVE_STATES",
    "AgentManager",
    "FlowNode",
    "IN_FLIGHT_STATES",
    "InputReply",
    "InvalidStateTransitionError",
    "LifecycleState",
    "PersistentEventBus",
    "RuntimeOrchestrator",
    "SubtaskNode",
    "TERMINAL_STATES",
    "TaskNode",
    "VALID_TRANSITIONS",
    "assert_transition",
    "can_transition",
    "expand_status_filter",
    "get_agent_manager",
    "get_persistent_event_bus",
    "get_runtime_orchestrator",
    "parse_last_event_id",
    "run_without_cancel",
    "to_canonical_status",
    "to_legacy_status",
]
