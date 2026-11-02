"""
Orchestration Package for HunterAI
"""
from hunter_ai.orchestration.multi_agent_orchestrator import (
    MultiAgentOrchestrator,
    OrchestrationTask,
    AgentResult,
    AgentRole,
    TaskStatus,
)
from hunter_ai.orchestration.triple_agents import TripleAgentSystem, Verdict, ExecutionResult

__all__ = [
    "MultiAgentOrchestrator",
    "OrchestrationTask",
    "AgentResult",
    "AgentRole",
    "TaskStatus",
    "TripleAgentSystem",
    "Verdict",
    "ExecutionResult",
]
