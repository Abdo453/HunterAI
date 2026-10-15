"""
Backward-compatibility aliases for Phase 12-15 system modules
"""
from core.system.mcp_a2a import MCPClient, MCPMessageBus
from core.system.task_scheduler import TaskScheduler, AutomationTask, ConditionalRule, TaskStatus
from core.system.information_gain_planner import InformationGainPlanner, TaskCandidate
from core.system.recovery_engine import RecoveryEngine, RecoveryEvent, RecoveryAction, HealthStatus

__all__ = [
    "MCPClient", "MCPMessageBus",
    "TaskScheduler", "AutomationTask", "ConditionalRule", "TaskStatus",
    "InformationGainPlanner", "TaskCandidate",
    "RecoveryEngine", "RecoveryEvent", "RecoveryAction", "HealthStatus",
]
