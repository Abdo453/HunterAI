"""
HunterAI Evidence Court 2.0 (Adversarial Epistemic Tribunal)
============================================================
Replaces single-evaluator judgment with a multi-role adversarial tribunal:
1. Finder Agent: Presents candidate observation & initial anomaly.
2. Verifier Agent: Checks deterministic contract proof & nonces.
3. Skeptic Agent (Devil's Advocate): Actively seeks alternative noise explanations (Jitter, WAF, Flakiness).
4. Causal Analyzer: Verifies unbroken cause-effect chain from input to observable sink.
5. Chief Justice: Issues final binding verdict.

Invariants:
- Finding CANNOT be confirmed if Skeptic proves an alternative explanation survives.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class CourtParticipantRole(str, Enum):
    FINDER = "FINDER"
    VERIFIER = "VERIFIER"
    SKEPTIC = "SKEPTIC"
    CAUSAL_ANALYZER = "CAUSAL_ANALYZER"
    CHIEF_JUSTICE = "CHIEF_JUSTICE"


@dataclass
class CourtRoleVerdict:
    role: CourtParticipantRole
    disposition: str  # "VOTE_CONFIRM", "VOTE_REJECT", "VOTE_INCONCLUSIVE"
    argument: str
    confidence: float


@dataclass
class TribunalRuling:
    case_id: str
    target_endpoint: str
    final_verdict: str  # "CONFIRMED", "REFUTED", "INCONCLUSIVE"
    unanimous: bool
    opinions: List[CourtRoleVerdict]
    chief_justification: str
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "endpoint": self.target_endpoint,
            "verdict": self.final_verdict,
            "unanimous": self.unanimous,
            "opinions": [
                {"role": o.role.value, "vote": o.disposition, "arg": o.argument}
                for o in self.opinions
            ],
            "justification": self.chief_justification,
        }


class EvidenceCourtV2:
    """Simulates adversarial tribunal adjudication over submitted security findings"""

    @classmethod
    def adjudicate_case(
        cls,
        case_id: str,
        endpoint: str,
        proof_nonce_proven: bool,
        reproductions_count: int,
        causal_chain_verified: bool,
        baseline_stable: bool,
        waf_clean: bool
    ) -> TribunalRuling:
        opinions: List[CourtRoleVerdict] = []

        # 1. Finder: Discovers anomaly and advocates confirmation
        opinions.append(CourtRoleVerdict(
            role=CourtParticipantRole.FINDER,
            disposition="VOTE_CONFIRM",
            argument=f"Observable anomaly detected on {endpoint} during active testing.",
            confidence=0.85
        ))

        # 2. Verifier: Requires proof nonce & minimum 2 reproductions
        if proof_nonce_proven and reproductions_count >= 2:
            opinions.append(CourtRoleVerdict(
                role=CourtParticipantRole.VERIFIER,
                disposition="VOTE_CONFIRM",
                argument=f"Deterministic nonce proven across {reproductions_count} independent reproduction runs.",
                confidence=0.95
            ))
        else:
            opinions.append(CourtRoleVerdict(
                role=CourtParticipantRole.VERIFIER,
                disposition="VOTE_REJECT",
                argument=f"Verification failed: Nonce missing or insufficient reproductions ({reproductions_count}/2).",
                confidence=0.90
            ))

        # 3. Skeptic: Challenges baseline stability & WAF noise
        if not baseline_stable:
            opinions.append(CourtRoleVerdict(
                role=CourtParticipantRole.SKEPTIC,
                disposition="VOTE_INCONCLUSIVE",
                argument="Skeptic Challenge: Baseline is unstable. Flaky server responses mimic vulnerability symptoms.",
                confidence=0.88
            ))
        elif not waf_clean:
            opinions.append(CourtRoleVerdict(
                role=CourtParticipantRole.SKEPTIC,
                disposition="VOTE_REJECT",
                argument="Skeptic Challenge: WAF challenge signature detected. Behavior caused by perimeter defense.",
                confidence=0.92
            ))
        else:
            opinions.append(CourtRoleVerdict(
                role=CourtParticipantRole.SKEPTIC,
                disposition="VOTE_CONFIRM",
                argument="Skeptic Concession: All alternative noise explanations (Jitter, WAF, Auth Expired) eliminated.",
                confidence=0.92
            ))

        # 4. Causal Analyzer: Verifies unbroken cause-and-effect path
        if causal_chain_verified:
            opinions.append(CourtRoleVerdict(
                role=CourtParticipantRole.CAUSAL_ANALYZER,
                disposition="VOTE_CONFIRM",
                argument="Unbroken directed causal path from input parameter to observable execution sink confirmed.",
                confidence=0.95
            ))
        else:
            opinions.append(CourtRoleVerdict(
                role=CourtParticipantRole.CAUSAL_ANALYZER,
                disposition="VOTE_REJECT",
                argument="Causal link broken: No direct data flow proven from payload to sink.",
                confidence=0.85
            ))

        # 5. Chief Justice weighs votes
        votes = [o.disposition for o in opinions]
        is_unanimous = len(set(votes)) == 1 and votes[0] == "VOTE_CONFIRM"

        if is_unanimous:
            final_verdict = "CONFIRMED"
            justification = "Unanimous tribunal decision: Deterministic proof, causal chain, and absence of noise all proven."
        elif "VOTE_INCONCLUSIVE" in votes:
            final_verdict = "INCONCLUSIVE"
            justification = "Tribunal impasse: Skeptic raised valid doubts regarding server jitter or environmental instability."
        elif votes.count("VOTE_REJECT") >= 1:
            final_verdict = "REFUTED"
            justification = "Claim dismissed: Evidence contract or causal integrity rejected by tribunal officers."
        else:
            final_verdict = "INCONCLUSIVE"
            justification = "Split opinion among tribunal members."

        return TribunalRuling(
            case_id=case_id,
            target_endpoint=endpoint,
            final_verdict=final_verdict,
            unanimous=is_unanimous,
            opinions=opinions,
            chief_justification=justification
        )
