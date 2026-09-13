"""
HunterAI Uncertainty Engine (Explaining "Why")
==============================================
Replaces opaque binary outputs with transparent diagnostic reasoning:
Verdicts: CONFIRMED | PROBABLE | UNCERTAIN | INSUFFICIENT_EVIDENCE | REJECTED
Explains exact causes of uncertainty:
- WAF_INTERFERENCE
- SESSION_EXPIRED
- UNSTABLE_RESPONSE
- MISSING_BASELINE
- EVIDENCE_NOT_REPRODUCIBLE
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional


class UncertaintyReason(str, Enum):
    WAF_INTERFERENCE = "WAF_INTERFERENCE"
    SESSION_EXPIRED = "SESSION_EXPIRED"
    UNSTABLE_RESPONSE = "UNSTABLE_RESPONSE"
    MISSING_BASELINE = "MISSING_BASELINE"
    EVIDENCE_NOT_REPRODUCIBLE = "EVIDENCE_NOT_REPRODUCIBLE"
    NONE = "NONE"


@dataclass
class UncertaintyVerdict:
    verdict: str  # CONFIRMED, PROBABLE, UNCERTAIN, INSUFFICIENT_EVIDENCE, REJECTED
    reason: UncertaintyReason = UncertaintyReason.NONE
    explanation: str = ""
    is_actionable: bool = True


class UncertaintyEngine:
    """Evaluates evidence stability and diagnoses root cause of uncertainty"""

    @classmethod
    def diagnose(
        cls,
        waf_blocked: bool,
        session_active: bool,
        response_reproduced: bool,
        baseline_available: bool,
        has_execution_proof: bool
    ) -> UncertaintyVerdict:
        if waf_blocked:
            return UncertaintyVerdict(
                verdict="UNCERTAIN",
                reason=UncertaintyReason.WAF_INTERFERENCE,
                explanation="Response was filtered or blocked by Cloudflare / WAF; origin application state undetermined.",
                is_actionable=False
            )

        if not session_active:
            return UncertaintyVerdict(
                verdict="UNCERTAIN",
                reason=UncertaintyReason.SESSION_EXPIRED,
                explanation="User authentication dropped mid-probe; cannot ascertain access control validity.",
                is_actionable=False
            )

        if not baseline_available:
            return UncertaintyVerdict(
                verdict="INSUFFICIENT_EVIDENCE",
                reason=UncertaintyReason.MISSING_BASELINE,
                explanation="Neutral baseline response could not be established for differential comparison.",
                is_actionable=False
            )

        if not response_reproduced:
            return UncertaintyVerdict(
                verdict="UNCERTAIN",
                reason=UncertaintyReason.EVIDENCE_NOT_REPRODUCIBLE,
                explanation="Probe response did not reproduce across consecutive trials; server response is non-deterministic.",
                is_actionable=False
            )

        if has_execution_proof:
            return UncertaintyVerdict(
                verdict="CONFIRMED",
                reason=UncertaintyReason.NONE,
                explanation="Deterministic proof of execution successfully verified.",
                is_actionable=True
            )

        return UncertaintyVerdict(
            verdict="PROBABLE",
            reason=UncertaintyReason.NONE,
            explanation="Strong differential observed, but full PoE token was unverified.",
            is_actionable=True
        )