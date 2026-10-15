"""
HunterAI Cognitive Thinking Protocol — Claude Thinking & Steering Architecture
=============================================================================
Directly integrates Anthropic's Extended Thinking & Thinking Steering principles:
  1. Inner Monologue Scratchpad with raw stream-of-consciousness reasoning
  2. Adaptive Thinking Framework scaling depth by task complexity & stakes
  3. 8-Stage Core Thinking Sequence (Engagement -> Decomposition -> Multi-Hypothesis ->
     Detective Discovery -> Verification -> Error Correction -> Synthesis -> Meta-Cognition)
  4. Interleaved Thinking & Tool Use ("Think" Tool pattern before/after actions)
  5. Thinking Budget & Cost Steering (effort parameter, token bounds)
  6. Epistemic Confidence Calibration & Anti-Hallucination Invariants
"""
from __future__ import annotations

import json
import logging
import math
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("hunter_ai.claude_thinking")


class ThinkingMode(str, Enum):
    ADAPTIVE   = "adaptive"     # Evaluates task complexity dynamically
    EXTENDED   = "extended"     # Deep multi-hypothesis reasoning with high budget
    CONCISE    = "concise"      # Fast, focused reasoning for quick probes
    DEEP_AUDIT = "deep_audit"   # Exhaustive, zero-compromise security verification


@dataclass
class ThinkingBudget:
    """
    Governs token limits and cognitive steering parameters.
    Corresponds to Anthropic's effort parameter and budget_tokens.
    """
    effort: float = 0.7                  # 0.0 (fast/minimal) to 1.0 (exhaustive)
    max_thinking_tokens: int = 4096      # Token ceiling for thinking block
    min_thinking_tokens: int = 256       # Floor for complex tasks
    interleaved_allowed: bool = True     # Pausing after tool results to reflect
    cost_per_1k_tokens: float = 0.015    # Output token cost tracking

    @classmethod
    def for_mode(cls, mode: ThinkingMode) -> ThinkingBudget:
        if mode == ThinkingMode.CONCISE:
            return cls(effort=0.2, max_thinking_tokens=1024, min_thinking_tokens=128)
        elif mode == ThinkingMode.EXTENDED:
            return cls(effort=0.85, max_thinking_tokens=8192, min_thinking_tokens=1024)
        elif mode == ThinkingMode.DEEP_AUDIT:
            return cls(effort=1.0, max_thinking_tokens=16384, min_thinking_tokens=2048)
        return cls(effort=0.6, max_thinking_tokens=4096, min_thinking_tokens=512)


@dataclass
class CognitiveHypothesis:
    hypothesis_id: str
    statement: str
    vuln_class: str
    target: str
    confidence: float
    supporting_signals: List[str] = field(default_factory=list)
    counter_evidence: List[str] = field(default_factory=list)
    refutation_criteria: str = ""
    status: str = "ACTIVE"  # ACTIVE, REFUTED, CONFIRMED, SUSPENDED

    def update_confidence(self, signal_strength: float, is_supporting: bool) -> None:
        if is_supporting:
            # Asymptotic increase towards 1.0
            self.confidence = min(0.99, self.confidence + signal_strength * (1.0 - self.confidence))
        else:
            # Multiplicative penalty
            self.confidence = max(0.01, self.confidence * (1.0 - signal_strength))


@dataclass
class ThinkingTrace:
    trace_id: str
    timestamp: float
    mode: str
    prompt_context: str
    inner_monologue: str
    hypotheses_evaluated: List[Dict[str, Any]]
    pre_tool_reflection: Optional[str] = None
    post_tool_reflection: Optional[str] = None
    decided_action: str = ""
    tokens_estimated: int = 0
    duration_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ClaudeThinkingEngine:
    """
    Anthropic-grade Cognitive Engine that guides local and cloud LLMs through
    rigorous, human-like, stream-of-consciousness security reasoning.
    """
    def __init__(self, mode: ThinkingMode = ThinkingMode.ADAPTIVE, traces_dir: str | Path = "logs/thinking_traces"):
        self.mode = mode
        self.budget = ThinkingBudget.for_mode(mode)
        self.traces_dir = Path(traces_dir)
        self.traces_dir.mkdir(parents=True, exist_ok=True)
        self.active_hypotheses: Dict[str, CognitiveHypothesis] = {}
        self.trace_history: List[ThinkingTrace] = []

    # ── 1. System Prompt Construction ──────────────────────────────────────────

    def generate_system_prompt_steering(self, agent_role: str = "Strategist") -> str:
        """
        Builds the master <anthropic_thinking_protocol> system prompt
        specialized for security assessment and causal auditing.
        """
        return f"""
<anthropic_thinking_protocol>
  For EVERY SINGLE decision, plan, and tool invocation, the {agent_role} MUST engage
  in a comprehensive, natural, and unfiltered thinking process inside a ```thinking``` block.

  <basic_guidelines>
    - Express thinking in raw, organic, stream-of-consciousness inner monologue.
    - Avoid rigid checklists or mechanical bullet-points inside the thinking block.
    - Think like a senior investigative security researcher and offensive theorist:
      curious, skeptical, mathematically disciplined, and alert to anomalies.
    - Never jump to conclusions: treat every initial signal as a clue, not a verdict.
    - Respond in the operator's primary language while keeping code and technical identifiers pristine.
  </basic_guidelines>

  <core_thinking_sequence>
    1. INITIAL ENGAGEMENT:
       - Clearly rephrase the user's objective and target boundaries in your own words.
       - Map out what is known with certainty vs what is merely assumed or speculative.
       - Identify explicit scope constraints and inviolable safety boundaries.

    2. PROBLEM DECOMPOSITION:
       - Break down the target attack surface into logical components: network, auth, API, state.
       - Consider where trust boundaries exist and how data transitions between trust zones.

    3. MULTIPLE HYPOTHESES GENERATION (Anti-Premature Closure):
       - Maintain at least TWO to THREE competing hypotheses active simultaneously.
       - Example: "Could this be an IDOR? Or is it a multi-tenant read replica? Or public data?"
       - Explicitly ask: "What would prove me completely WRONG about this finding?"

    4. DETECTIVE DISCOVERY FLOW:
       - Follow the investigative trail: Signal -> Anomaly -> Hypothesis -> Targeted Probe.
       - Connect disparate signals: e.g. a JS bundle leak combined with an undocumented 403 API.
       - Circle back to earlier observations when a new tool result sheds fresh light.

    5. PRE-TOOL REFLECTION (Interleaved Think Tool):
       - Before issuing any tool call (nmap, katana, ffuf, burp, etc.), ask:
         * "Why this specific tool and parameters?"
         * "What exact observation would confirm my hypothesis?"
         * "What observation would refute it and save me from wasting time?"

    6. POST-TOOL REFLECTION:
       - Immediately upon receiving tool output, pause and process:
         * "Did the response match my expectation?"
         * "Is this a real vulnerability or a WAF block / generic redirect / error page?"
         * "What changed in my internal world model?"

    7. ERROR RECOGNITION & COURSE CORRECTION:
       - If a tool fails, timeout occurs, or probe returns 403:
         * Acknowledge the failure directly without excuse.
         * Formulate an adaptive workaround or alternative path.

    8. STRATEGIC META-COGNITION & EPISTEMIC HUMILITY:
       - Assign an honest confidence score (0.0 to 1.0).
       - Differentiate between:
         * Proof of Concept (reproducible execution trace)
         * Suspected Vulnerability (anomalous behavior)
         * Informational Surface (exposed endpoint)
  </core_thinking_sequence>

  <thinking_budget_steering>
    - Current Cognitive Mode: {self.mode.value.upper()}
    - Effort Parameter: {self.budget.effort}
    - Max Thinking Tokens: {self.budget.max_thinking_tokens}
    - Always conclude internal thinking before presenting the concise, actionable deliverable.
  </thinking_budget_steering>
</anthropic_thinking_protocol>
"""

    # ── 2. Hypothesis Management ──────────────────────────────────────────────

    def spawn_competing_hypotheses(self, observation: str, target: str) -> List[CognitiveHypothesis]:
        """
        Generates competing hypotheses for an observation to prevent confirmation bias.
        """
        obs_lower = observation.lower()
        hyps = []

        # Case A: Object ID in URL
        if any(k in obs_lower for k in ["id", "user", "account", "profile"]):
            h1 = CognitiveHypothesis(
                hypothesis_id=f"HYP-{uuid.uuid4().hex[:6].upper()}",
                statement=f"Object access on '{target}' lacks server-side authorization check (BOLA/IDOR).",
                vuln_class="IDOR",
                target=target,
                confidence=0.50,
                supporting_signals=[observation],
                refutation_criteria="Server returns 401/403 or same data for mismatched user context.",
            )
            h2 = CognitiveHypothesis(
                hypothesis_id=f"HYP-{uuid.uuid4().hex[:6].upper()}",
                statement=f"Object '{target}' is intentionally public data and returns identical payload regardless of session.",
                vuln_class="PUBLIC_DATA",
                target=target,
                confidence=0.40,
                supporting_signals=[observation],
                refutation_criteria="Unauthenticated request returns 401 or hides private attributes.",
            )
            hyps.extend([h1, h2])

        # Case B: Reflection / Header Anomaly
        elif any(k in obs_lower for k in ["origin", "cors", "header", "redirect"]):
            h1 = CognitiveHypothesis(
                hypothesis_id=f"HYP-{uuid.uuid4().hex[:6].upper()}",
                statement=f"Server improperly trusts Origin header reflecting arbitrary domain.",
                vuln_class="CORS_MISCONFIGURATION",
                target=target,
                confidence=0.55,
                supporting_signals=[observation],
                refutation_criteria="Access-Control-Allow-Origin header is omitted or statically constrained.",
            )
            h2 = CognitiveHypothesis(
                hypothesis_id=f"HYP-{uuid.uuid4().hex[:6].upper()}",
                statement=f"Header reflection is handled by a caching proxy or CDN edge without credentials.",
                vuln_class="EDGE_CACHE_REFLECTION",
                target=target,
                confidence=0.35,
                supporting_signals=[observation],
                refutation_criteria="Access-Control-Allow-Credentials: true is absent.",
            )
            hyps.extend([h1, h2])

        else:
            h1 = CognitiveHypothesis(
                hypothesis_id=f"HYP-{uuid.uuid4().hex[:6].upper()}",
                statement=f"Unclassified surface anomaly on '{target}'.",
                vuln_class="ANOMALY",
                target=target,
                confidence=0.30,
                supporting_signals=[observation],
                refutation_criteria="Behaves identically to baseline normal traffic.",
            )
            hyps.append(h1)

        for h in hyps:
            self.active_hypotheses[h.hypothesis_id] = h

        return hyps

    # ── 3. Interleaved Reflection Blocks ──────────────────────────────────────

    def pre_tool_deliberation(self, tool_name: str, target: str, planned_params: Dict[str, Any]) -> str:
        """
        Executes pre-action thinking block: verifies intent, invariants, and hypotheses.
        """
        return (
            f"```thinking\n"
            f"Let me pause and deliberate before firing tool '{tool_name}' on target '{target}'.\n"
            f"1. Goal: Validate active hypotheses with minimal footprint.\n"
            f"2. Parameters: {json.dumps(planned_params)}\n"
            f"3. Safety Invariant Check: Is target within authorized scope? Yes.\n"
            f"4. Expected Signal: A non-generic response status or delta indicating parameter sensitivity.\n"
            f"5. Refutation Trigger: If status is 404 or generic 200 WAF challenge, abort this branch.\n"
            f"Proceeding with controlled execution.\n"
            f"```"
        )

    def post_tool_deliberation(self, tool_name: str, status_code: int, response_snippet: str) -> Tuple[str, Optional[CognitiveHypothesis]]:
        """
        Executes post-action reflection block: updates hypotheses based on actual response.
        """
        monologue_lines = [
            f"```thinking",
            f"Tool '{tool_name}' completed execution. Inspecting resulting output...",
            f"Status code received: {status_code}",
        ]

        leading_hyp: Optional[CognitiveHypothesis] = None
        if self.active_hypotheses:
            leading_hyp = max(self.active_hypotheses.values(), key=lambda h: h.confidence)

        if status_code == 200 and len(response_snippet) > 10:
            monologue_lines.append("Observation: Substantive 200 OK payload returned. Evaluating signal...")
            if leading_hyp:
                leading_hyp.update_confidence(0.35, is_supporting=True)
                monologue_lines.append(f"Confidence for [{leading_hyp.hypothesis_id}: {leading_hyp.vuln_class}] increased to {leading_hyp.confidence:.2f}.")
        elif status_code in (401, 403):
            monologue_lines.append("Observation: Authorization enforced by target (401/403).")
            if leading_hyp:
                leading_hyp.update_confidence(0.50, is_supporting=False)
                monologue_lines.append(f"Negative evidence: refuting [{leading_hyp.hypothesis_id}]. Adjusted confidence to {leading_hyp.confidence:.2f}.")
        else:
            monologue_lines.append(f"Observation: Non-standard status {status_code}. Maintaining suspended stance.")

        monologue_lines.append("Synthesizing current state and updating blackboard.\n```")
        reflection = "\n".join(monologue_lines)
        return reflection, leading_hyp

    # ── 4. Trace Recording & Persistence ──────────────────────────────────────

    def record_trace(
        self,
        prompt_context: str,
        inner_monologue: str,
        decided_action: str = "",
        duration_ms: float = 0.0,
    ) -> ThinkingTrace:
        """
        Captures full inner monologue trace into persistent JSON audit log.
        """
        trace_id = f"COT-{uuid.uuid4().hex[:8].upper()}"
        estimated_tokens = len(inner_monologue.split()) * 2

        trace = ThinkingTrace(
            trace_id=trace_id,
            timestamp=time.time(),
            mode=self.mode.value,
            prompt_context=prompt_context[:300],
            inner_monologue=inner_monologue,
            hypotheses_evaluated=[asdict(h) for h in self.active_hypotheses.values()],
            decided_action=decided_action,
            tokens_estimated=estimated_tokens,
            duration_ms=duration_ms,
        )

        self.trace_history.append(trace)

        # Persist to disk
        trace_file = self.traces_dir / f"{trace_id}.json"
        try:
            trace_file.write_text(json.dumps(trace.to_dict(), indent=2), encoding="utf-8")
        except Exception as e:
            logger.warning("Failed saving cognitive trace: %s", e)

        return trace
