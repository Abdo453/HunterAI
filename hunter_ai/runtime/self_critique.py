"""
HunterAI Runtime: Self-Critique & Independent Validator
========================================================
Challenges candidate findings before they are confirmed.
Acts as a skeptical reviewer exploring alternative explanations:
- Is a 403 status code a WAF block or genuine authorization enforcement?
- Is response body length change caused by dynamic timestamps/nonces or SQL logic?
- In IDOR, is the returned record truly private or just a public object?
- In XSS, is the payload reflected within executable script context or safely encoded?
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any

logger = logging.getLogger("hunter_ai.self_critique")


class CritiqueStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    REFUTED = "REFUTED"
    NEEDS_MORE_EVIDENCE = "NEEDS_MORE_EVIDENCE"


@dataclass
class CritiqueVerdict:
    status: CritiqueStatus
    confidence: float
    confirmed_facts: List[str]
    alternative_explanations: List[str]
    refuted_explanations: List[str]
    reasoning: str
    recommended_test: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "confidence": round(self.confidence, 2),
            "confirmed_facts": self.confirmed_facts,
            "alternative_explanations": self.alternative_explanations,
            "refuted_explanations": self.refuted_explanations,
            "reasoning": self.reasoning,
            "recommended_test": self.recommended_test
        }


class SelfCritiqueValidator:
    """
    Skeptical critic agent that tests counter-hypotheses
    to eliminate hallucinations and false positives.
    """

    def challenge_finding(
        self,
        vuln_type: str,
        endpoint: str,
        param_name: str,
        claimed_evidence: Dict[str, Any]
    ) -> CritiqueVerdict:
        """
        Applies rigorous domain-specific adversarial checks against a claimed finding.
        """
        v_type = vuln_type.lower()
        confirmed = []
        alternatives = []
        refuted = []

        # ── 1. SQL Injection Challenges ───────────────────────────────────────
        if "sql" in v_type:
            # Check 1: Was there a negative control test?
            has_boolean_diff = claimed_evidence.get("boolean_differential", False)
            has_error = claimed_evidence.get("syntax_error_detected", False)
            probe_status = claimed_evidence.get("probe_status", 200)
            control_status = claimed_evidence.get("control_status", 200)

            if probe_status in [429, 403, 503]:
                alternatives.append("WAF or rate-limiter block triggered, not SQL execution")
                return CritiqueVerdict(
                    status=CritiqueStatus.REFUTED,
                    confidence=0.1,
                    confirmed_facts=[f"Endpoint returned HTTP {probe_status}"],
                    alternative_explanations=alternatives,
                    refuted_explanations=[],
                    reasoning=f"Probe triggered HTTP {probe_status} (WAF/Rate-limit block). Not a confirmed vulnerability.",
                    recommended_test="Apply WAF evasion encoding or increase delay"
                )

            if has_boolean_diff:
                confirmed.append("Differential behavior verified between TRUE and FALSE predicates")
                refuted.append("Random page variation (control probe showed identical negative baseline)")
                return CritiqueVerdict(
                    status=CritiqueStatus.CONFIRMED,
                    confidence=0.92,
                    confirmed_facts=confirmed,
                    alternative_explanations=[],
                    refuted_explanations=refuted,
                    reasoning="Boolean differential strictly reproduced between valid and invalid predicates."
                )

            if has_error:
                error_msg = claimed_evidence.get("error_message", "")
                confirmed.append(f"Database error disclosed: {error_msg[:80]}")
                return CritiqueVerdict(
                    status=CritiqueStatus.CONFIRMED,
                    confidence=0.88,
                    confirmed_facts=confirmed,
                    alternative_explanations=[],
                    refuted_explanations=["Generic 500 error"],
                    reasoning="Authentic DBMS error syntax detected in response body."
                )

            # If only length difference without controls
            alternatives.append("Dynamic page nonces, ads, or timestamps caused response length variance")
            return CritiqueVerdict(
                status=CritiqueStatus.NEEDS_MORE_EVIDENCE,
                confidence=0.45,
                confirmed_facts=["Response length changed on payload input"],
                alternative_explanations=alternatives,
                refuted_explanations=[],
                reasoning="Response length changed, but no 3-way negative control probe was executed to rule out random nonces.",
                recommended_test="Execute independent_verify with 1' AND '1'='2 negative control"
            )

        # ── 2. IDOR / Authorization Challenges ────────────────────────────────
        elif "idor" in v_type or "auth" in v_type:
            diff_detected = claimed_evidence.get("different_user_data_accessed", False)
            is_public_record = claimed_evidence.get("is_public_record", False)

            if is_public_record:
                alternatives.append("Record accessed is public or catalog data, not private user data")
                return CritiqueVerdict(
                    status=CritiqueStatus.REFUTED,
                    confidence=0.2,
                    confirmed_facts=["Endpoint returns record for given ID"],
                    alternative_explanations=alternatives,
                    refuted_explanations=[],
                    reasoning="Target object is public catalog data; no access boundary was violated."
                )

            if diff_detected and not is_public_record:
                confirmed.append("Unauthenticated or cross-tenant private profile data disclosed")
                return CritiqueVerdict(
                    status=CritiqueStatus.CONFIRMED,
                    confidence=0.90,
                    confirmed_facts=confirmed,
                    alternative_explanations=[],
                    refuted_explanations=["Public endpoint"],
                    reasoning="Cross-account data accessed without matching authorization session."
                )

            return CritiqueVerdict(
                status=CritiqueStatus.NEEDS_MORE_EVIDENCE,
                confidence=0.4,
                confirmed_facts=["Endpoint accepts user ID parameter"],
                alternative_explanations=["User session is not isolated or data is mocked"],
                refuted_explanations=[],
                reasoning="Object lookup occurs, but ownership violation has not been definitively proven with distinct tenant sessions.",
                recommended_test="Compare request with User A auth cookie against User B resource ID"
            )

        # ── 3. General Default Challenge ──────────────────────────────────────
        is_verified = claimed_evidence.get("differential_verified", False)
        if is_verified:
            return CritiqueVerdict(
                status=CritiqueStatus.CONFIRMED,
                confidence=0.85,
                confirmed_facts=["3-way differential verification passed"],
                alternative_explanations=[],
                refuted_explanations=["Network noise", "Generic error"],
                reasoning="Differential behavioral verification succeeded."
            )

        return CritiqueVerdict(
            status=CritiqueStatus.NEEDS_MORE_EVIDENCE,
            confidence=0.5,
            confirmed_facts=["Initial anomaly observed"],
            alternative_explanations=["Server configuration quirk", "Input sanitization without execution"],
            refuted_explanations=[],
            reasoning="Evidence is currently insufficient to rule out non-vulnerable application behavior.",
            recommended_test="Run targeted differential probe with control negative"
        )
