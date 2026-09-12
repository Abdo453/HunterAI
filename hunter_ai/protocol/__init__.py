"""
Hunter Agent Protocol v1 Package
"""
from hunter_ai.protocol.contract import AgentContract, ModelTierPreference
from hunter_ai.protocol.blackboard import (
    ThreeTierBlackboardMemory,
    Level1Summary,
    Level2EvidenceItem
)
from hunter_ai.protocol.handoff import HandoffEnvelope, HandoffPriority
from hunter_ai.protocol.result import StructuredTaskResult, StructuredFinding

__all__ = [
    "AgentContract",
    "ModelTierPreference",
    "ThreeTierBlackboardMemory",
    "Level1Summary",
    "Level2EvidenceItem",
    "HandoffEnvelope",
    "HandoffPriority",
    "StructuredTaskResult",
    "StructuredFinding"
]
