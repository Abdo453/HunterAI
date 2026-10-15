"""
HunterAI Recovery Engine (Phase 15)
====================================
Handles failures gracefully with adaptive recovery:
  1. System health monitoring via check_system_status()
  2. Automatic rerouting to fallback models on model errors
  3. Tool crash detection and restart orchestration
  4. Network outage detection with exponential-backoff retry
  5. All recovery events logged to recovery_events.json
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable

logger = logging.getLogger("hunter_ai.recovery_engine")


class RecoveryAction(str, Enum):
    REROUTE_MODEL = "REROUTE_MODEL"
    RESTART_TOOL  = "RESTART_TOOL"
    RETRY_NETWORK = "RETRY_NETWORK"
    STALL_AGENT   = "STALL_AGENT"
    SNAPSHOT      = "SNAPSHOT"
    NO_OP         = "NO_OP"


class HealthStatus(str, Enum):
    HEALTHY   = "HEALTHY"
    DEGRADED  = "DEGRADED"
    CRITICAL  = "CRITICAL"
    UNKNOWN   = "UNKNOWN"


@dataclass
class RecoveryEvent:
    event_id: str
    timestamp: float
    component: str
    error_type: str
    action_taken: RecoveryAction
    detail: str
    success: bool
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            **asdict(self),
            "action_taken": self.action_taken.value,
        }


class RecoveryEngine:
    """
    Adaptive failure recovery manager for the HunterAI agent system.
    """
    def __init__(
        self,
        recovery_log: str | Path = "recovery_events.json",
        fallback_models: Optional[List[str]] = None,
    ):
        self.recovery_log = Path(recovery_log)
        self.fallback_models = fallback_models or [
            "qwen3:8b",
            "qwen2.5-coder:14b-tools",
            "qwen2.5-coder:14b",
        ]
        self._events: List[RecoveryEvent] = []
        self._model_failures: Dict[str, int] = {}
        self._tool_failures: Dict[str, int] = {}
        self._network_retry_count: int = 0
        self._health: Dict[str, HealthStatus] = {}
        self._tool_restarters: Dict[str, Callable] = {}

    # ─── Health Monitoring ─────────────────────────────────────────────────────

    def check_system_status(self) -> Dict[str, Any]:
        """Returns a health overview of all registered components."""
        # Auto-update health based on accumulated failures
        for model, failures in self._model_failures.items():
            if failures >= 5:
                self._health[f"model:{model}"] = HealthStatus.CRITICAL
            elif failures >= 2:
                self._health[f"model:{model}"] = HealthStatus.DEGRADED
            else:
                self._health[f"model:{model}"] = HealthStatus.HEALTHY

        for tool, failures in self._tool_failures.items():
            if failures >= 3:
                self._health[f"tool:{tool}"] = HealthStatus.CRITICAL
            elif failures >= 1:
                self._health[f"tool:{tool}"] = HealthStatus.DEGRADED
            else:
                self._health[f"tool:{tool}"] = HealthStatus.HEALTHY

        critical_count = sum(1 for s in self._health.values() if s == HealthStatus.CRITICAL)
        degraded_count = sum(1 for s in self._health.values() if s == HealthStatus.DEGRADED)

        overall = (
            HealthStatus.CRITICAL if critical_count > 0 else
            HealthStatus.DEGRADED if degraded_count > 0 else
            HealthStatus.HEALTHY
        )

        return {
            "overall_status": overall.value,
            "components": {k: v.value for k, v in self._health.items()},
            "model_failures": dict(self._model_failures),
            "tool_failures": dict(self._tool_failures),
            "network_retries": self._network_retry_count,
            "total_recovery_events": len(self._events),
        }

    # ─── Model Recovery ────────────────────────────────────────────────────────

    def handle_model_error(self, failed_model: str, error: str, current_model_index: int = 0) -> Dict[str, Any]:
        """
        Reroutes to next available fallback model on failure.
        """
        self._model_failures[failed_model] = self._model_failures.get(failed_model, 0) + 1

        # Pick next fallback
        next_model: Optional[str] = None
        for m in self.fallback_models:
            if m != failed_model:
                next_model = m
                break

        success = next_model is not None
        event = self._record_event(
            component=f"model:{failed_model}",
            error_type="ModelInferenceError",
            action=RecoveryAction.REROUTE_MODEL,
            detail=f"Rerouting from '{failed_model}' to '{next_model}'. Error: {error[:200]}",
            success=success,
            metadata={"failed_model": failed_model, "fallback_model": next_model},
        )

        return {
            "action": RecoveryAction.REROUTE_MODEL.value,
            "fallback_model": next_model,
            "success": success,
            "event_id": event.event_id,
        }

    # ─── Tool Recovery ─────────────────────────────────────────────────────────

    def register_tool_restarter(self, tool_name: str, restarter: Callable) -> None:
        self._tool_restarters[tool_name] = restarter

    def handle_tool_crash(self, tool_name: str, error: str) -> Dict[str, Any]:
        """
        Detects tool crash and invokes registered restarter function.
        """
        self._tool_failures[tool_name] = self._tool_failures.get(tool_name, 0) + 1
        restarter = self._tool_restarters.get(tool_name)
        success = False

        if restarter:
            try:
                restarter()
                success = True
            except Exception as e:
                error = f"Restart failed: {e}"

        event = self._record_event(
            component=f"tool:{tool_name}",
            error_type="ToolCrash",
            action=RecoveryAction.RESTART_TOOL,
            detail=f"Tool '{tool_name}' crashed. {'Restarted.' if success else 'No restarter available.'} Error: {error[:200]}",
            success=success,
            metadata={"tool": tool_name, "failure_count": self._tool_failures[tool_name]},
        )

        return {
            "action": RecoveryAction.RESTART_TOOL.value,
            "tool": tool_name,
            "success": success,
            "failure_count": self._tool_failures[tool_name],
            "event_id": event.event_id,
        }

    # ─── Network Recovery ──────────────────────────────────────────────────────

    def handle_network_outage(self, endpoint: str, attempt: int = 1, max_retries: int = 3) -> Dict[str, Any]:
        """
        Implements exponential-backoff retry strategy for network failures.
        """
        self._network_retry_count += 1
        wait_seconds = min(2 ** attempt, 30)
        success = attempt <= max_retries

        event = self._record_event(
            component=f"network:{endpoint}",
            error_type="NetworkOutage",
            action=RecoveryAction.RETRY_NETWORK,
            detail=f"Network unreachable at '{endpoint}'. Attempt {attempt}/{max_retries}. Wait: {wait_seconds}s.",
            success=success,
            metadata={"endpoint": endpoint, "attempt": attempt, "wait_seconds": wait_seconds},
        )

        return {
            "action": RecoveryAction.RETRY_NETWORK.value,
            "endpoint": endpoint,
            "attempt": attempt,
            "max_retries": max_retries,
            "should_retry": success,
            "wait_seconds": wait_seconds,
            "event_id": event.event_id,
        }

    # ─── Event Persistence ─────────────────────────────────────────────────────

    def _record_event(
        self,
        component: str,
        error_type: str,
        action: RecoveryAction,
        detail: str,
        success: bool,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> RecoveryEvent:
        event = RecoveryEvent(
            event_id=f"REC-{uuid.uuid4().hex[:8].upper()}",
            timestamp=time.time(),
            component=component,
            error_type=error_type,
            action_taken=action,
            detail=detail,
            success=success,
            metadata=metadata or {},
        )
        self._events.append(event)
        self._persist_events()
        logger.info("Recovery event: %s -> %s [%s]", component, action.value, "OK" if success else "FAIL")
        return event

    def _persist_events(self) -> None:
        try:
            self.recovery_log.write_text(
                json.dumps([e.to_dict() for e in self._events], indent=2, default=str),
                encoding="utf-8",
            )
        except Exception as e:
            logger.warning("Failed persisting recovery events: %s", e)

    def get_events(self) -> List[Dict[str, Any]]:
        return [e.to_dict() for e in self._events]
