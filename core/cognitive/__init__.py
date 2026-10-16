"""
HunterAI Cognitive Thinking Subsystem
=====================================
Exports the reasoning engines that let HunterAI think like the strongest
published reasoning models:

  * ClaudeThinkingEngine  — Claude extended/adaptive thinking (structured, interleaved)
  * DeepSeekThinkingEngine — DeepSeek-R1 reflective reasoning (self-consistency, backtracking)
  * HybridReasoningCore    — adaptive router that unifies both by task complexity

All pre-existing exports are preserved for backward compatibility.
"""
from core.cognitive.claude_thinking_protocol import (
    ClaudeThinkingEngine,
    ThinkingMode,
    ThinkingBudget,
    CognitiveHypothesis,
    ThinkingTrace,
)
from core.cognitive.deepseek_thinking_protocol import (
    DeepSeekThinkingEngine,
    DeepSeekTrace,
    DeepSeekVerdict,
    ReasoningPath,
    ReasonStep,
    ReasoningStepKind,
)
from core.cognitive.hybrid_reasoning_core import (
    HybridReasoningCore,
    HybridReasoningResult,
    ReasoningStrategy,
)

__all__ = [
    # Claude
    "ClaudeThinkingEngine",
    "ThinkingMode",
    "ThinkingBudget",
    "CognitiveHypothesis",
    "ThinkingTrace",
    # DeepSeek
    "DeepSeekThinkingEngine",
    "DeepSeekTrace",
    "DeepSeekVerdict",
    "ReasoningPath",
    "ReasonStep",
    "ReasoningStepKind",
    # Hybrid
    "HybridReasoningCore",
    "HybridReasoningResult",
    "ReasoningStrategy",
]
