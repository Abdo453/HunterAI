"""
Multi-Agent Collaboration & Adversarial Debate Engine
Implements Supervisor orchestration and the Analyst <-> Critic <-> Verifier debate loop.
Prevents single-LLM cognitive bias by enforcing self-criticism and empirical verification.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class DebateContribution:
    agent_role: str  # "analyst", "critic", "verifier", "supervisor"
    statement: str
    evidence_items: List[str] = field(default_factory=list)
    confidence: float = 0.50
    timestamp: float = field(default_factory=time.time)


@dataclass
class DebateOutcome:
    finding_id: str
    title: str
    analyst_hypothesis: str
    critic_challenges: List[str]
    verifier_evidence: List[str]
    final_verdict: str  # "CONFIRMED", "REJECTED_FALSE_POSITIVE", "INCONCLUSIVE_NEEDS_MORE_DATA"
    final_confidence: float
    consensus_rationale: str
    debate_transcript: List[DebateContribution] = field(default_factory=list)


class MultiAgentDebateEngine:
    """
    محرك النقاش المعرفي متعدد الوكلاء (Analyst vs Critic vs Verifier)
    - Analyst: يكتشف الأنماط ويقترح فرضيات الثغرات.
    - Critic: يطرح الأسئلة المضادة (هل الـ Endpoint عام عن عمد؟ هل الـ 500 مجرد خطأ معالجة؟).
    - Verifier: يصمم وينفذ تجربة إثبات آمنة ومفرقة (Differential Test).
    - Supervisor: يحسم القرار النهائي بناءً على تكامل الأدلة.
    """

    def __init__(self):
        self.debate_history: List[DebateOutcome] = []

    def conduct_debate(
        self,
        finding_id: str,
        title: str,
        observation: str,
        proposed_vulnerability_type: str,
        raw_evidence: Dict[str, Any]
    ) -> DebateOutcome:
        transcript: List[DebateContribution] = []

        # ── 1. Analyst Phase: Hypothesis Formulation ─────────────────
        analyst_statement = (
            f"Observed pattern in '{observation}'. Hypothesizing {proposed_vulnerability_type} "
            f"based on initial response anomalies."
        )
        initial_conf = 0.65
        transcript.append(DebateContribution(
            agent_role="analyst",
            statement=analyst_statement,
            evidence_items=[str(raw_evidence.get("snippet", ""))],
            confidence=initial_conf
        ))

        # ── 2. Critic Phase: Self-Criticism & Alternative Explanations ───
        challenges = []
        if "500" in str(raw_evidence.get("status_code", "")) or "error" in str(raw_evidence.get("snippet", "")).lower():
            challenges.append("Could this 500 response simply be an unhandled type exception rather than SQL execution?")
            challenges.append("Is there proof of syntax breakout or execution of injected logic?")

        if "public" in title.lower() or "idor" in proposed_vulnerability_type.lower():
            challenges.append("Could this object be intentionally exposed as public metadata?")
            challenges.append("Did we verify access with a second unauthenticated / unprivileged session?")

        if not challenges:
            challenges.append("Is the evidence reproducible across multiple identical requests?")

        critic_statement = "Raised critical counter-arguments: " + "; ".join(challenges)
        transcript.append(DebateContribution(
            agent_role="critic",
            statement=critic_statement,
            evidence_items=challenges,
            confidence=0.45
        ))

        # ── 3. Verifier Phase: Empirical Controlled Testing ─────────
        verifier_evidence = []
        is_verified = False
        final_conf = initial_conf

        differential_passed = raw_evidence.get("differential_passed", False)
        dual_account_passed = raw_evidence.get("dual_account_passed", False)
        benign_math_passed = raw_evidence.get("benign_math_passed", False)

        if differential_passed or dual_account_passed or benign_math_passed:
            is_verified = True
            final_conf = 0.95
            if dual_account_passed:
                verifier_evidence.append("Dual-account differential confirmed: Account B object inaccessible to Account A unless authorization is broken.")
            if benign_math_passed or differential_passed:
                verifier_evidence.append("Benign mathematical / Boolean differential confirmed: Payload evaluated by backend interpreter.")
            ver_statement = "Controlled verification succeeded. Counter-arguments refuted by empirical proof."
        else:
            final_conf = 0.35
            verifier_evidence.append("Differential test failed or inconclusive. No conclusive backend execution proof.")
            ver_statement = "Controlled verification failed. Maintaining finding as unverified hypothesis."

        transcript.append(DebateContribution(
            agent_role="verifier",
            statement=ver_statement,
            evidence_items=verifier_evidence,
            confidence=final_conf
        ))

        # ── 4. Supervisor Phase: Consensus Decision ─────────────────
        if is_verified and final_conf >= 0.85:
            verdict = "CONFIRMED"
            rationale = "Analyst hypothesis validated by empirical verifier tests; all Critic objections successfully addressed."
        elif final_conf <= 0.40:
            verdict = "REJECTED_FALSE_POSITIVE"
            rationale = "Objections raised by Critic were substantiated; Verifier failed to produce empirical differential proof."
        else:
            verdict = "INCONCLUSIVE_NEEDS_MORE_DATA"
            rationale = "Evidence is suggestive but insufficient to meet strict Bug Bounty triage standards."

        transcript.append(DebateContribution(
            agent_role="supervisor",
            statement=f"Final Verdict: {verdict}. {rationale}",
            evidence_items=[f"Confidence: {final_conf:.0%}"],
            confidence=final_conf
        ))

        outcome = DebateOutcome(
            finding_id=finding_id,
            title=title,
            analyst_hypothesis=analyst_statement,
            critic_challenges=challenges,
            verifier_evidence=verifier_evidence,
            final_verdict=verdict,
            final_confidence=final_conf,
            consensus_rationale=rationale,
            debate_transcript=transcript
        )
        self.debate_history.append(outcome)
        return outcome
