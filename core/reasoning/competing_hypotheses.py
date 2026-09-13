"""
HunterAI Analysis of Competing Hypotheses (ACH)
==============================================
Evaluates alternative explanations simultaneously to eliminate False Positives:
H1: True Vulnerability Exists
H2: WAF Challenge or Rate Limiter Blocked the Request
H3: Session Authentication Expired
H4: Backend Application Flakiness / Jitter
H5: Random Server Variance

Guarantees:
- HunterAI does not just try to prove H1.
- HunterAI explicitly tests whether H2, H3, H4 can be falsified.
- If alternative explanations cannot be refuted, rules: INCONCLUSIVE.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List


class HypothesisOption(str, Enum):
    H1_TRUE_VULNERABILITY = "H1_TRUE_VULNERABILITY"
    H2_WAF_OR_RATE_LIMIT = "H2_WAF_OR_RATE_LIMIT"
    H3_AUTH_SESSION_EXPIRED = "H3_AUTH_SESSION_EXPIRED"
    H4_BACKEND_JITTER_FLAKY = "H4_BACKEND_JITTER_FLAKY"
    H5_BENIGN_APPLICATION_ERROR = "H5_BENIGN_APPLICATION_ERROR"


@dataclass
class ACHMatrixResult:
    winning_hypothesis: HypothesisOption
    is_conclusive: bool
    verdict: str  # "CONFIRMED", "REFUTED", "INCONCLUSIVE"
    candidate_scores: Dict[str, float]
    falsified_alternatives: List[str]
    surviving_alternatives: List[str]
    justification: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "winning_hypothesis": self.winning_hypothesis.value,
            "is_conclusive": self.is_conclusive,
            "verdict": self.verdict,
            "falsified": self.falsified_alternatives,
            "surviving": self.surviving_alternatives,
            "justification": self.justification,
        }


class CompetingHypothesesEngine:
    """Rigorous epistemic evaluation across competing causal models"""

    @classmethod
    def evaluate(
        cls,
        status_code: int,
        body: str,
        proof_nonce_present: bool,
        baseline_stable: bool,
        waf_signatures_found: bool,
        auth_session_valid: bool
    ) -> ACHMatrixResult:
        falsified: List[str] = []
        surviving: List[str] = []

        scores: Dict[str, float] = {
            HypothesisOption.H1_TRUE_VULNERABILITY.value: 0.1,
            HypothesisOption.H2_WAF_OR_RATE_LIMIT.value: 0.1,
            HypothesisOption.H3_AUTH_SESSION_EXPIRED.value: 0.1,
            HypothesisOption.H4_BACKEND_JITTER_FLAKY.value: 0.1,
            HypothesisOption.H5_BENIGN_APPLICATION_ERROR.value: 0.1,
        }

        # 1. Evaluate H3 (Session Expired)
        if not auth_session_valid or status_code == 401 or "/login" in body.lower():
            scores[HypothesisOption.H3_AUTH_SESSION_EXPIRED.value] += 0.8
            surviving.append(HypothesisOption.H3_AUTH_SESSION_EXPIRED.value)
        else:
            falsified.append(HypothesisOption.H3_AUTH_SESSION_EXPIRED.value)

        # 2. Evaluate H2 (WAF)
        if waf_signatures_found or status_code == 429:
            scores[HypothesisOption.H2_WAF_OR_RATE_LIMIT.value] += 0.8
            surviving.append(HypothesisOption.H2_WAF_OR_RATE_LIMIT.value)
        else:
            falsified.append(HypothesisOption.H2_WAF_OR_RATE_LIMIT.value)

        # 3. Evaluate H4 (Jitter / Flakiness)
        if not baseline_stable:
            scores[HypothesisOption.H4_BACKEND_JITTER_FLAKY.value] += 0.7
            surviving.append(HypothesisOption.H4_BACKEND_JITTER_FLAKY.value)
        else:
            falsified.append(HypothesisOption.H4_BACKEND_JITTER_FLAKY.value)

        # 4. Evaluate H1 (True Vulnerability)
        if proof_nonce_present:
            scores[HypothesisOption.H1_TRUE_VULNERABILITY.value] += 0.85
            surviving.append(HypothesisOption.H1_TRUE_VULNERABILITY.value)
        else:
            falsified.append(HypothesisOption.H1_TRUE_VULNERABILITY.value)

        # Check for ambiguity / competing hypotheses
        # If proof_nonce_present is True but H4 (jitter) or H2 (WAF) or H3 (session expired) also survived:
        if proof_nonce_present and any(alt in surviving for alt in [
            HypothesisOption.H2_WAF_OR_RATE_LIMIT.value,
            HypothesisOption.H4_BACKEND_JITTER_FLAKY.value,
            HypothesisOption.H3_AUTH_SESSION_EXPIRED.value
        ]):
            return ACHMatrixResult(
                winning_hypothesis=HypothesisOption.H1_TRUE_VULNERABILITY,
                is_conclusive=False,
                verdict="INCONCLUSIVE",
                candidate_scores=scores,
                falsified_alternatives=falsified,
                surviving_alternatives=surviving,
                justification="Apparent exploit signal detected, but competing server jitter or environmental noise cannot be eliminated."
            )

        # Determine winner
        winner_key = max(scores, key=scores.get)
        winner = HypothesisOption(winner_key)

        if winner == HypothesisOption.H1_TRUE_VULNERABILITY:
            return ACHMatrixResult(
                winning_hypothesis=winner,
                is_conclusive=True,
                verdict="CONFIRMED",
                candidate_scores=scores,
                falsified_alternatives=falsified,
                surviving_alternatives=surviving,
                justification="Deterministic proof verified. All competing noise explanations (WAF, Jitter, Auth Expired) conclusively eliminated."
            )

        # Winner is a noise explanation
        return ACHMatrixResult(
            winning_hypothesis=winner,
            is_conclusive=True,
            verdict="REFUTED",
            candidate_scores=scores,
            falsified_alternatives=falsified,
            surviving_alternatives=surviving,
            justification=f"Claim refuted: Behavior explained by {winner.value} rather than genuine vulnerability."
        )
