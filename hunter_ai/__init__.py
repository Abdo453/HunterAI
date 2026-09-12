"""
HunterAI — Agent AI Control Plane & Intelligence Layer
Unified intermediary cognitive architecture for security agents.
"""
from hunter_ai.schemas.task import HunterTask, TaskLifecycleState
from hunter_ai.schemas.result import HunterAIResult
from hunter_ai.agents.capabilities import AgentCapability
from hunter_ai.agents.registry import AgentRegistry, AgentDescriptor
from hunter_ai.providers.model_registry import ModelRegistry, ModelProfile
from hunter_ai.providers.fallback_engine import FallbackEngine, FailureReason, FallbackAction
from hunter_ai.context.manager import ContextManager
from hunter_ai.context.compressor import ContextCompressor
from hunter_ai.intelligence.critic import AICritic, CriticReviewResult
from hunter_ai.intelligence.validator import FindingValidator, ValidationScorecard
from hunter_ai.gateway.control_plane import HunterAIControlPlane
from hunter_ai.gateway.router import AIRouter

__all__ = [
    "HunterTask",
    "TaskLifecycleState",
    "HunterAIResult",
    "AgentCapability",
    "AgentRegistry",
    "AgentDescriptor",
    "ModelRegistry",
    "ModelProfile",
    "FallbackEngine",
    "FailureReason",
    "FallbackAction",
    "ContextManager",
    "ContextCompressor",
    "AICritic",
    "CriticReviewResult",
    "FindingValidator",
    "ValidationScorecard",
    "HunterAIControlPlane",
    "AIRouter",
]
