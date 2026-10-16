"""
HunterAI Hybrid Reasoning Core
==============================
Unifies the two strongest published reasoning styles into one adaptive engine:

  * Claude "extended/adaptive thinking": structured 8-stage sequence, interleaved
    thinking between tool calls, effort/thinking-budget steering.
  * DeepSeek-R1: long reflective chain-of-thought, self-consistency, verification,
    "wait"-style backtracking, and rumination control.

The core auto-selects the strategy from task complexity — mirroring Claude's
adaptive thinking, which "evaluates the complexity of each request and determines
whether and how much to use extended thinking".

Design note (observability): the core exposes a *concise* decision rationale and
the structured, auditable reasoning trace. It does not surface private hidden
chain-of-thought in the user-facing answer.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from core.cognitive.claude_thinking_protocol import (
    ClaudeThinkingEngine,
    ThinkingMode,
)
from core.cognitive.deepseek_thinking_protocol import (
    DeepSeekThinkingEngine,
    DeepSeekTrace,
    DeepSeekVerdict,
)

logger = logging.getLogger("hunter_ai.hybrid_reasoning")


class ReasoningStrategy(str, Enum):
    CLAUDE_CONCISE = "claude_concise"       # fast, low-stakes
    DEEPSEEK_R1 = "deepseek_r1"             # reflective, multi-path
    HYBRID_DEEP = "hybrid_deep"             # structured + self-consistency


@dataclass
class HybridReasoningResult:
    strategy: ReasoningStrategy
    complexity: float
    chosen_answer: str
    confidence: float
    rationale: str
    claude_mode: Optional[str] = None
    deepseek_trace: Optional[DeepSeekTrace] = None
    steering_prompt: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "strategy": self.strategy.value,
            "complexity": round(self.complexity, 4),
            "chosen_answer": self.chosen_answer,
            "confidence": round(self.confidence, 4),
            "rationale": self.rationale,
            "claude_mode": self.claude_mode,
            "deepseek_trace": self.deepseek_trace.to_dict() if self.deepseek_trace else None,
            "metadata": self.metadata,
        }


class HybridReasoningCore:
    """
    Adaptive reasoning router over the Claude and DeepSeek engines.
    """

    # Complexity thresholds for adaptive strategy selection.
    CONCISE_THRESHOLD = 0.35
    HYBRID_THRESHOLD = 0.70

    def __init__(
        self,
        claude_engine: Optional[ClaudeThinkingEngine] = None,
        deepseek_engine: Optional[DeepSeekThinkingEngine] = None,
        default_role: str = "security researcher",
    ):
        self.claude = claude_engine or ClaudeThinkingEngine(mode=ThinkingMode.ADAPTIVE)
        self.deepseek = deepseek_engine or DeepSeekThinkingEngine()
        self.role = default_role

    # ── Adaptive complexity assessment ───────────────────────────────────────
    def assess_complexity(
        self,
        problem: str,
        observations: Optional[List[str]] = None,
        stakes: str = "medium",
    ) -> float:
        """
        Estimate task complexity in [0, 1] from observable signals (no LLM call).
        Longer problems, more observations, ambiguity and higher stakes raise it.
        """
        observations = observations or []
        score = 0.0

        # Length / breadth signals
        words = len(problem.split())
        score += min(0.30, words / 120.0)
        score += min(0.20, len(observations) * 0.04)

        # Ambiguity / reasoning-trigger keywords
        lowered = problem.lower()
        hard_markers = ["why", "how", "explain", "trade-off", "architecture",
                        "multi", "hypothesis", "contradiction", "root cause",
                        "chain", "exploit", "bypass", "reason"]
        score += min(0.25, sum(1 for m in hard_markers if m in lowered) * 0.05)

        # Task-type signal: a request that asks the agent to analyse / decide /
        # determine is inherently more complex than a mechanical listing, even
        # when it is short.
        analytic_markers = ["analy", "identif", "determin", "evaluat", "assess",
                            "investigat", "diagnos", "whether", "compare",
                            "validat", "explain", "justify"]
        score += min(0.20, sum(1 for m in analytic_markers if m in lowered) * 0.06)

        # Stakes
        stake_weight = {"low": 0.0, "medium": 0.05, "high": 0.15, "critical": 0.25}
        score += stake_weight.get(stakes.lower(), 0.05)

        return max(0.0, min(1.0, score))

    def select_strategy(self, complexity: float) -> ReasoningStrategy:
        if complexity < self.CONCISE_THRESHOLD:
            return ReasoningStrategy.CLAUDE_CONCISE
        if complexity < self.HYBRID_THRESHOLD:
            return ReasoningStrategy.DEEPSEEK_R1
        return ReasoningStrategy.HYBRID_DEEP

    # ── Unified think() ──────────────────────────────────────────────────────
    def think(
        self,
        problem: str,
        observations: Optional[List[str]] = None,
        constraints: Optional[List[str]] = None,
        candidate_answers: Optional[List[str]] = None,
        stakes: str = "medium",
        force_strategy: Optional[ReasoningStrategy] = None,
    ) -> HybridReasoningResult:
        complexity = self.assess_complexity(problem, observations, stakes)
        strategy = force_strategy or self.select_strategy(complexity)

        if strategy == ReasoningStrategy.CLAUDE_CONCISE:
            self.claude.mode = ThinkingMode.CONCISE
            prompt = self.claude.generate_system_prompt_steering(self.role)
            return HybridReasoningResult(
                strategy=strategy,
                complexity=complexity,
                chosen_answer="",
                confidence=0.5,
                rationale=(
                    f"Low-complexity task (score={complexity:.2f}): using concise "
                    "structured reasoning; deep multi-path reflection withheld."
                ),
                claude_mode=ThinkingMode.CONCISE.value,
                steering_prompt=prompt,
                metadata={"observations": len(observations or [])},
            )

        # DeepSeek reflective path (also the reflective half of HYBRID_DEEP)
        trace = self.deepseek.think(
            problem=problem,
            observations=observations,
            constraints=constraints,
            candidate_answers=candidate_answers,
        )

        if strategy == ReasoningStrategy.DEEPSEEK_R1:
            return HybridReasoningResult(
                strategy=strategy,
                complexity=complexity,
                chosen_answer=trace.chosen_answer,
                confidence=trace.confidence,
                rationale=(
                    f"Reflective task (score={complexity:.2f}): DeepSeek-R1 style — "
                    f"{len(trace.paths)} paths explored, verdict={trace.verdict.value}, "
                    f"agreement={trace.agreement_ratio:.2f}."
                ),
                deepseek_trace=trace,
                steering_prompt=self.deepseek.system_prompt_steering(problem, self.role),
                metadata={"aha_count": trace.aha_count, "halt_reason": trace.halt_reason},
            )

        # HYBRID_DEEP: structured Claude audit + DeepSeek self-consistency
        self.claude.mode = ThinkingMode.DEEP_AUDIT
        claude_prompt = self.claude.generate_system_prompt_steering(self.role)
        deep_prompt = self.deepseek.system_prompt_steering(problem, self.role)
        verified = [p for p in trace.paths if p.verified]
        return HybridReasoningResult(
            strategy=strategy,
            complexity=complexity,
            chosen_answer=trace.chosen_answer,
            confidence=trace.confidence,
            rationale=(
                f"High-complexity task (score={complexity:.2f}): hybrid deep mode — "
                f"structured Claude audit + DeepSeek self-consistency "
                f"({len(verified)}/{len(trace.paths)} verified paths, "
                f"verdict={trace.verdict.value})."
            ),
            claude_mode=ThinkingMode.DEEP_AUDIT.value,
            deepseek_trace=trace,
            steering_prompt=f"{claude_prompt}\n\n{deep_prompt}",
            metadata={"verified_paths": len(verified), "aha_count": trace.aha_count},
        )

    # ── Interleaved thinking hooks (Claude style, between tool calls) ─────────
    def pre_tool(self, tool_name: str, target: str, planned_params: Dict[str, Any]) -> str:
        return self.claude.pre_tool_deliberation(tool_name, target, planned_params)

    def post_tool(self, tool_name: str, status_code: int, response_snippet: str):
        return self.claude.post_tool_deliberation(tool_name, status_code, response_snippet)

    # ── Concise, observability-safe decision summary (no raw CoT) ─────────────
    def decision_summary(self, result: HybridReasoningResult) -> Dict[str, Any]:
        summary: Dict[str, Any] = {
            "strategy": result.strategy.value,
            "complexity": round(result.complexity, 2),
            "chosen_answer": result.chosen_answer,
            "confidence": round(result.confidence, 2),
            "rationale": result.rationale,
        }
        if result.deepseek_trace is not None:
            summary["reasoning_stats"] = {
                "paths": len(result.deepseek_trace.paths),
                "aha_moments": result.deepseek_trace.aha_count,
                "halt_reason": result.deepseek_trace.halt_reason,
            }
        return summary
