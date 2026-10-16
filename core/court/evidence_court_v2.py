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
    # These mirror the authoritative Evidence Court (v1) judgment so the tribunal
    # never hides HOW a proof was established (DERIVED vs DECLARED vs NONE).
    proof_strength: str = "NONE"
    epistemic_state: str = "UNKNOWN"
    court_judgment_id: str = ""
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
            "proof_strength": self.proof_strength,
            "epistemic_state": self.epistemic_state,
            "court_judgment_id": self.court_judgment_id,
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
        waf_clean: bool,
        proof_payload: Optional[Any] = None,
        verifier_result: Optional[Dict[str, Any]] = None,
        allow_declared_proof: bool = False,
    ) -> TribunalRuling:
        """Adversarial tribunal that DELEGATES the proof decision to the single
        authoritative Evidence Court (v1).

        Historically this tribunal accepted the caller's booleans as if they were
        deterministic proof, so it could confirm what the v1 court refuted. It now
        feeds the same evidence to ``EvidenceCourt.adjudicate`` and derives its
        ruling from that judgment: a caller assertion (``proof_nonce_proven``) is
        recorded as DECLARED proof and never confirms on its own. Only a
        re-evaluable ``proof_payload`` (or a typed causal invariant) can yield
        CONFIRMED — identically to v1.
        """
        from core.evidence_court import CourtVerdict, EvidenceCourt

        vr: Dict[str, Any] = dict(verifier_result or {})
        vr.setdefault("reproduced", reproductions_count >= 1)
        if proof_nonce_proven:
            # A bare caller assertion is DECLARED, not DERIVED. The engine must
            # still be able to re-evaluate it through proof_payload.
            vr.setdefault("deterministic_proof", True)
        if not waf_clean:
            vr.setdefault("waf_blocked", True)

        judgment = EvidenceCourt.adjudicate(
            target_url=endpoint,
            parameter=str(vr.get("parameter", "")),
            vuln_class=str(vr.get("vuln_class", "")),
            finder_claim={"claim": f"Tribunal case {case_id}"},
            verifier_result=vr,
            proof_payload=proof_payload,
            is_in_scope=True,
            allow_declared_proof=allow_declared_proof,
        )

        opinions: List[CourtRoleVerdict] = []

        # 1. Finder: Discovers anomaly and advocates confirmation
        opinions.append(CourtRoleVerdict(
            role=CourtParticipantRole.FINDER,
            disposition="VOTE_CONFIRM",
            argument=f"Observable anomaly detected on {endpoint} during active testing.",
            confidence=0.85
        ))

        # 2. Verifier: confirms only when the v1 court actually derived the proof
        #    AND the minimum reproduction threshold is met.
        if judgment.verdict == CourtVerdict.CONFIRMED and reproductions_count >= 2:
            opinions.append(CourtRoleVerdict(
                role=CourtParticipantRole.VERIFIER,
                disposition="VOTE_CONFIRM",
                argument=(
                    f"Evidence Court confirmed by {judgment.proof_strength} proof "
                    f"across {reproductions_count} reproduction runs."
                ),
                confidence=0.95
            ))
        else:
            reason = judgment.proof_detail or judgment.adjudication_rationale
            opinions.append(CourtRoleVerdict(
                role=CourtParticipantRole.VERIFIER,
                disposition="VOTE_REJECT",
                argument=(
                    f"Verification failed: {reason} "
                    f"(reproductions {reproductions_count}/2)."
                ),
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

        # 5. Chief Justice weighs the tribunal AND the authoritative v1 judgment.
        #    The skeptic can always downgrade; the v1 verdict decides whether the
        #    deterministic proof gate was actually passed.
        votes = [o.disposition for o in opinions]
        is_unanimous = len(set(votes)) == 1 and votes[0] == "VOTE_CONFIRM"

        if is_unanimous and judgment.verdict == CourtVerdict.CONFIRMED:
            final_verdict = "CONFIRMED"
            justification = (
                "Unanimous tribunal decision: deterministic proof, causal chain, "
                "and absence of noise all proven."
            )
        elif "VOTE_INCONCLUSIVE" in votes:
            final_verdict = "INCONCLUSIVE"
            justification = (
                "Tribunal impasse: Skeptic raised valid doubts regarding server "
                "jitter or environmental instability."
            )
        elif votes.count("VOTE_REJECT") >= 1:
            final_verdict = "REFUTED"
            justification = (
                f"Claim dismissed by tribunal officers: {judgment.adjudication_rationale}"
            )
        else:
            final_verdict = "INCONCLUSIVE"
            justification = "Split opinion among tribunal members."

        return TribunalRuling(
            case_id=case_id,
            target_endpoint=endpoint,
            final_verdict=final_verdict,
            unanimous=is_unanimous,
            opinions=opinions,
            chief_justification=justification,
            proof_strength=judgment.proof_strength,
            epistemic_state=judgment.epistemic_state,
            court_judgment_id=judgment.judgment_id,
        )
