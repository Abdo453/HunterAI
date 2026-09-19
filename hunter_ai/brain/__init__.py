"""
Hunter Agent Brain & Orchestration Layer
"""
from hunter_ai.brain.model_router import AIModelRouter, RoutedModelSelection, TaskIntent
from hunter_ai.brain.memory_hierarchy import MemoryHierarchy
from hunter_ai.brain.agent_manager import HunterAgentManager, BaseContractAgent

from hunter_ai.brain.cognitive_council import (
    CognitiveCouncil,
    CouncilState,
    CouncilHypothesis,
    CouncilRole,
    ModelVote,
    VoteVerdict,
    HypothesisStatus,
    create_cognitive_council,
)

__all__ = [
    "AIModelRouter",
    "RoutedModelSelection",
    "TaskIntent",
    "MemoryHierarchy",
    "HunterAgentManager",
    "BaseContractAgent",
    "CognitiveCouncil",
    "CouncilState",
    "CouncilHypothesis",
    "CouncilRole",
    "ModelVote",
    "VoteVerdict",
    "HypothesisStatus",
    "create_cognitive_council",
]
