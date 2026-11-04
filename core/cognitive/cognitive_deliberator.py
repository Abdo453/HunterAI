"""
HunterAI Unified Cognitive Deliberator
======================================
Bridges Claude Adaptive Extended Thinking and DeepSeek-R1 Reflective Reasoning
directly into the live agent execution loops, tool dispatchers, and autonomous planners.

Provides 4-stage active cognitive deliberation:
  1. Situation Assessment & Perceptual Framing
  2. Multi-Hypothesis Generation & Falsification Invariants (Anti-Premature Closure)
  3. Pre-Tool Tactical Reflection ("Think Tool" Pattern)
  4. Post-Tool Critical Reflection & "Wait/Aha" Self-Correction (DeepSeek-R1)
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from core.cognitive.claude_thinking_protocol import (
    ClaudeThinkingEngine,
    CognitiveHypothesis,
    ThinkingBudget,
    ThinkingMode,
    ThinkingTrace,
)
from core.cognitive.deepseek_thinking_protocol import (
    DeepSeekThinkingEngine,
    DeepSeekTrace,
    DeepSeekVerdict,
    ReasonStep,
    ReasoningStepKind,
    ReasoningPath,
)
from core.cognitive.hybrid_reasoning_core import (
    HybridReasoningCore,
    HybridReasoningResult,
    ReasoningStrategy,
)

logger = logging.getLogger("hunter_ai.cognitive.deliberator")


@dataclass
class StrategicDeliberation:
    deliberation_id: str
    target: str
    objective: str
    complexity_score: float
    strategy: ReasoningStrategy
    thinking_mode: ThinkingMode
    situation_assessment: str
    hypotheses: List[Dict[str, Any]]
    skepticism_notes: str
    chosen_action_path: str
    estimated_budget_tokens: int
    inner_monologue: str
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PreToolDeliberation:
    tool_name: str
    target: str
    category: str
    hypothesis_tested: str
    why_this_tool: str
    expected_positive_indicator: str
    falsification_indicator: str
    suggested_extra_args: List[str]
    confidence_prior: float
    inner_monologue: str


@dataclass
class PostToolReflection:
    tool_name: str
    target: str
    success: bool
    used_fallback: bool
    verdict: str  # CONFIRMED, REFUTED, ANOMALOUS, INCONCLUSIVE
    confidence_posterior: float
    aha_moment: Optional[str] = None  # DeepSeek "wait, let me reconsider"
    waf_or_deception_detected: bool = False
    next_recommended_step: str = ""
    reflection_notes: str = ""


class CognitiveDeliberator:
    """
    Master cognitive brain orchestrating real-time reasoning and deliberation
    across the entire assessment lifecycle.
    """

    def __init__(
        self,
        hybrid_core: Optional[HybridReasoningCore] = None,
        thinking_mode: ThinkingMode = ThinkingMode.ADAPTIVE,
    ):
        self.hybrid_core = hybrid_core or HybridReasoningCore()
        self.thinking_mode = thinking_mode
        self.claude_engine = self.hybrid_core.claude
        self.deepseek_engine = self.hybrid_core.deepseek
        self._hypotheses_vault: Dict[str, CognitiveHypothesis] = {}

    # ── 1. Strategic Deliberation (Planning Phase) ───────────────────────────

    def deliberate_strategy(
        self,
        target: str,
        objective: str,
        surface: Optional[Dict[str, List[str]]] = None,
        current_findings: Optional[List[Dict[str, Any]]] = None,
        stakes: str = "medium",
    ) -> StrategicDeliberation:
        """
        Deep multi-hypothesis strategic reasoning before advancing an assessment phase
        or selecting the next squad/action.
        """
        surface = surface or {}
        current_findings = current_findings or []
        obs_signals = [
            f"Asset {k}: {len(v)} items" if isinstance(v, (list, set, dict, tuple)) else f"Signal {k}: {v}"
            for k, v in surface.items()
            if v is not None
        ]
        obs_signals.extend([f"Finding: {f.get('title', 'Unknown')}" for f in current_findings[:5]])

        # Assess complexity via Hybrid Core
        complexity = self.hybrid_core.assess_complexity(
            problem=f"{objective} on {target}",
            observations=obs_signals,
            stakes=stakes,
        )
        strategy = self.hybrid_core.select_strategy(complexity)

        # Generate competing hypotheses (Anti-Premature Closure)
        h1_id = f"HYP-{uuid.uuid4().hex[:6].upper()}"
        h2_id = f"HYP-{uuid.uuid4().hex[:6].upper()}"

        h1 = CognitiveHypothesis(
            hypothesis_id=h1_id,
            statement=f"Target {target} exposes high-value reachable surfaces susceptible to OWASP Top 10 flaws.",
            vuln_class="General Web/API",
            target=target,
            confidence=0.60,
            supporting_signals=obs_signals[:3],
            refutation_criteria="Comprehensive crawl discovers zero state-changing endpoints or authenticated routes.",
        )
        h2 = CognitiveHypothesis(
            hypothesis_id=h2_id,
            statement=f"Target {target} utilizes modern edge WAF / reverse-proxy mitigating direct injection vectors.",
            vuln_class="Perimeter Defense",
            target=target,
            confidence=0.40,
            supporting_signals=["Standard cloud perimeter indicator"],
            refutation_criteria="Direct origin IP bypass or backend error stack traces exposed.",
        )
        self._hypotheses_vault[h1_id] = h1
        self._hypotheses_vault[h2_id] = h2

        # Formulate inner monologue (stream of consciousness)
        inner_monologue = (
            f"Analyzing target {target} for objective: '{objective}'.\n"
            f"Observed {len(obs_signals)} initial contextual signals. Complexity evaluated at {complexity:.2f}.\n"
            f"We must avoid premature certainty. Are we looking at a monolithic backend or microservice gateway?\n"
            f"If an active WAF is present, aggressive sweeps will poison our telemetry with 403 blocks.\n"
            f"Hypothesis {h1_id} posits reachable attack surface; competing hypothesis {h2_id} expects edge defenses.\n"
            f"Decision: Deploy surgical passive discovery first, then selectively escalate based on confirmed assets."
        )

        return StrategicDeliberation(
            deliberation_id=f"DELIB-{uuid.uuid4().hex[:8].upper()}",
            target=target,
            objective=objective,
            complexity_score=complexity,
            strategy=strategy,
            thinking_mode=self.thinking_mode,
            situation_assessment=f"Assessed {target} across {len(surface)} attack surface categories.",
            hypotheses=[asdict(h1), asdict(h2)],
            skepticism_notes="Do not accept 200 OK as success without validating against generic error templates.",
            chosen_action_path="Phased information-gain discovery with interleaved tool validation.",
            estimated_budget_tokens=2048 if strategy == ReasoningStrategy.HYBRID_DEEP else 1024,
            inner_monologue=inner_monologue,
        )

    # ── 2. Pre-Tool Tactical Deliberation ("Think Tool") ──────────────────────

    def deliberate_pre_tool(
        self,
        tool_name: str,
        target: str,
        category: str = "general",
        context: Optional[Dict[str, Any]] = None,
    ) -> PreToolDeliberation:
        """
        Tactical reflection before launching an external or native tool.
        Formulates: Why this tool? What proves success? What refutes the lead?
        """
        tool_lower = tool_name.lower()
        context = context or {}

        if "subfinder" in tool_lower or "assetfinder" in tool_lower:
            hypo = "Target domain has unindexed or legacy subdomains hosting staging or internal APIs."
            why = "Fast passive discovery without alerting perimeter WAF."
            pos = "Discovered subdomains matching organization naming patterns."
            fals = "Zero subdomains discovered beyond root domain."
            args = ["-silent"]
        elif "nmap" in tool_lower or "masscan" in tool_lower:
            hypo = "Non-standard network ports (e.g. 8080, 8443, 8888, 9000) expose administrative interfaces."
            why = "Determine transport layer accessibility and service fingerprints."
            pos = "Open ports running HTTP/SSH/RPC services."
            fals = "All filtered ports indicating strict stateful firewall."
            args = ["-sV", "--open"]
        elif "katana" in tool_lower or "crawler" in tool_lower:
            hypo = "Client-side routing exposes hidden API routes and state parameters."
            why = "Deep endpoint and parameter mapping."
            pos = "API endpoints with query parameters or JSON payloads."
            fals = "Static landing page without interactive forms or scripts."
            args = ["-depth", "3"]
        elif "ffuf" in tool_lower or "fuzzer" in tool_lower:
            hypo = "Hidden files (.git, .env, /backup, /admin) are left exposed."
            why = "Content discovery on sensitive endpoints."
            pos = "HTTP 200/301 responses with differing word/byte count."
            fals = "Uniform response length across all probed paths (wildcard catch-all)."
            args = ["-mc", "200,301,302"]
        elif "sqlmap" in tool_lower:
            hypo = "User input is directly concatenated into database query without parameterization."
            why = "Causal verification of SQL injection."
            pos = "Time delay differential or database banner extraction."
            fals = "Identical responses across Boolean payloads with zero SQL syntax anomalies."
            args = ["--batch", "--risk=1"]
        elif "nuclei" in tool_lower:
            hypo = "Known CVE vulnerabilities exist in third-party libraries or web servers."
            why = "Rule-based pattern matching against validated security templates."
            pos = "Matched high/critical severity template with exact response diff."
            fals = "Zero template matches or rate-limit throttle."
            args = ["-tags", "cve,exposure"]
        else:
            hypo = f"Executing {tool_name} will yield actionable telemetry for {target}."
            why = f"Extract {category} intelligence."
            pos = "Non-empty structured findings."
            fals = "Empty output or execution error."
            args = []

        inner = (
            f"Pre-Tool Deliberation for [{tool_name}] on [{target}]:\n"
            f"Hypothesis: {hypo}\n"
            f"Pre-flight check: Are we within scope? YES.\n"
            f"Success criteria: {pos}\n"
            f"Refutation indicator: {fals}\n"
            f"Will apply args: {' '.join(args) if args else 'default'}"
        )

        return PreToolDeliberation(
            tool_name=tool_name,
            target=target,
            category=category,
            hypothesis_tested=hypo,
            why_this_tool=why,
            expected_positive_indicator=pos,
            falsification_indicator=fals,
            suggested_extra_args=args,
            confidence_prior=0.50,
            inner_monologue=inner,
        )

    # ── 3. Post-Tool Reflection & "Aha/Wait" Self-Correction ───────────────────

    def reflect_post_tool(
        self,
        tool_name: str,
        target: str,
        exit_code: int,
        stdout: str,
        stderr: str,
        used_fallback: bool = False,
        structured_data: Optional[Dict[str, Any]] = None,
    ) -> PostToolReflection:
        """
        Evaluates execution outcome. Detects WAF deception, wildcard false positives,
        and triggers self-correction ("Wait, let me rethink").
        """
        output_len = len(stdout.strip())
        structured_data = structured_data or {}
        has_data = bool(structured_data) or output_len > 0

        # WAF & Catch-all deception detection
        waf_indicators = ["403 forbidden", "cloudflare", "access denied", "ddos protection", "captcha", "security check"]
        waf_detected = any(ind in stdout.lower() or ind in stderr.lower() for ind in waf_indicators)

        # Evaluate verdict
        if not has_data and exit_code != 0:
            verdict = "REFUTED"
            conf = 0.10
            aha = f"Wait, {tool_name} returned an error or timed out. Let's not blindly retry; adapt parameters or switch to alternative squad."
            rec = "Fallback to alternative protocol or probe."
        elif waf_detected:
            verdict = "ANOMALOUS"
            conf = 0.25
            aha = "Wait! Perimeter defense active. The endpoint is blocked by WAF. Direct fuzzing will trigger IP bans. Engage WAF bypass techniques."
            rec = "Engage WAF protocol evasion or stealth delay."
        elif has_data:
            verdict = "CONFIRMED"
            conf = 0.85
            aha = None
            rec = "Extract artifacts and feed into Attack Graph and Coverage Ledger."
        else:
            verdict = "INCONCLUSIVE"
            conf = 0.40
            aha = f"Output was empty. Is the resource non-existent or did the query fail silently? Verify with lightweight probe."
            rec = "Verify connectivity."

        reflection_notes = (
            f"Execution of {tool_name} completed with exit_code={exit_code} (length={output_len} bytes). "
            f"Verdict: {verdict}. Confidence updated to {conf:.2f}."
        )

        return PostToolReflection(
            tool_name=tool_name,
            target=target,
            success=(exit_code == 0),
            used_fallback=used_fallback,
            verdict=verdict,
            confidence_posterior=conf,
            aha_moment=aha,
            waf_or_deception_detected=waf_detected,
            next_recommended_step=rec,
            reflection_notes=reflection_notes,
        )

    # ── 4. Formatting Visible Chain-of-Thought Stream ─────────────────────────

    def format_strategic_trace(self, delib: StrategicDeliberation) -> str:
        """Generates a structured, terminal-safe CoT deliberation box."""
        lines = [
            "=" * 82,
            "[*] [COGNITIVE REASONING ENGINE] Multi-Hypothesis Deliberation & Strategic Framing",
            "=" * 82,
            f"Target:              {delib.target}",
            f"Objective:           {delib.objective}",
            f"Task Complexity:     {delib.complexity_score:.2f} / 1.00",
            f"Strategy Selected:   {delib.strategy.value.upper()} (Mode: {delib.thinking_mode.value.upper()})",
            f"Thinking Budget:     ~{delib.estimated_budget_tokens} tokens",
            "-" * 82,
            "ACTIVE COMPETING HYPOTHESES (Anti-Premature Closure):",
        ]
        for idx, h in enumerate(delib.hypotheses, 1):
            conf_pct = int(h.get("confidence", 0.5) * 100)
            lines.append(f"  [{idx}] Hypothesis {h.get('hypothesis_id')}: (Confidence: {conf_pct}%)")
            lines.append(f"      Statement:   {h.get('statement')}")
            lines.append(f"      Refutation:  {h.get('refutation_criteria')}")
        lines.extend([
            "-" * 82,
            "RED TEAM SKEPTICISM & SAFETY:",
            f"    {delib.skepticism_notes}",
            "-" * 82,
            "STREAM-OF-CONSCIOUSNESS INNER MONOLOGUE:",
        ])
        for line in delib.inner_monologue.splitlines():
            lines.append(f"    | {line}")
        lines.extend([
            "-" * 82,
            f"DECIDED ACTION PATH:  {delib.chosen_action_path}",
            "=" * 82,
        ])
        return "\n".join(lines)

    def format_pre_tool_trace(self, delib: PreToolDeliberation) -> str:
        """Generates tactical pre-tool reflection trace."""
        lines = [
            f"+-- [PRE-TOOL THINKING] {delib.tool_name.upper()} on {delib.target}",
            f"|   Hypothesis:     {delib.hypothesis_tested}",
            f"|   Rationale:      {delib.why_this_tool}",
            f"|   Success Signal: {delib.expected_positive_indicator}",
            f"|   Refutation:     {delib.falsification_indicator}",
        ]
        if delib.suggested_extra_args:
            lines.append(f"|   Extra Flags:    {' '.join(delib.suggested_extra_args)}")
        lines.append("+-----------------------------------------------------------------")
        return "\n".join(lines)

    def format_post_tool_trace(self, ref: PostToolReflection) -> str:
        """Generates post-tool reflection & self-correction trace."""
        stat_icon = "[+]" if ref.success else "[-]"
        lines = [
            f"+-- {stat_icon} [POST-TOOL REFLECTION] {ref.tool_name.upper()} -> Verdict: {ref.verdict} (Confidence: {int(ref.confidence_posterior*100)}%)",
            f"|   Observation: {ref.reflection_notes}",
        ]
        if ref.aha_moment:
            lines.append(f"|   [AHA / SELF-CORRECTION]: {ref.aha_moment}")
        if ref.waf_or_deception_detected:
            lines.append("|   [PERIMETER DEFENSE]: Edge protection detected. Shifting to bypass ladder.")
        lines.append(f"|   Next Step:   {ref.next_recommended_step}")
        lines.append("+-----------------------------------------------------------------")
        return "\n".join(lines)
