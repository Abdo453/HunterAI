"""
AI-Agent Bridge Package
Provides defensive prompt framing, refusal detection, structured parsing,
and hybrid local/online AI routing with automated fallbacks.
"""
from core.ai_bridge.defensive_prompt_framer import DefensivePromptFramer
from core.ai_bridge.refusal_detector import RefusalDetector, RefusalCheckResult
from core.ai_bridge.structured_output_parser import StructuredOutputParser
from core.ai_bridge.hybrid_ai_router import HybridAIRouter, AIBridgeResponse

__all__ = [
    "DefensivePromptFramer",
    "RefusalDetector",
    "RefusalCheckResult",
    "StructuredOutputParser",
    "HybridAIRouter",
    "AIBridgeResponse",
]
