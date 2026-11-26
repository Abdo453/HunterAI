"""
HunterAI Evidence Court 2.0 (Adversarial Epistemic Tribunal)
============================================================
Replaces single-evaluator judgment with a multi-role adversarial tribunal:
1. Finder Agent: Presents candidate observation & initial anomaly.
2. Verifier Agent: Delegates deterministic proof validation to canonical EvidenceCourt.
3. Skeptic Agent: Challenges baseline stability and WAF noise.
4. Adversarial Prosecutor: Cross-examines counter-theories via AdversarialEvidenceProsecutor.
5. Causal Analyzer: Verifies unbroken cause-effect chain from input to observable sink.
6. Chief Justice: Issues final binding verdict mapped cleanly to the canonical 7 states.

Invariants:
- Finding CANNOT be confirmed if canonical EvidenceCourt does not DERIVE proof.
- Finding CANNOT be confirmed if Skeptic or Adversarial Prosecutor sustains an objection.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from core.court.adversarial_prosecutor import (
    AdversarialEvidenceProsecutor,
    CounterTheoryType,
)


class CourtParticipantRole(str, Enum):
    FINDER = "FINDER"
    VERIFIER = "VERIFIER"
    SKEPTIC = "SKEPTIC"
    PROSECUTOR = "PROSECUTOR"
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
    final_verdict: str  # "CONFIRMED", "REFUTED", "INCONCLUSIVE", "UNAVAILABLE", "ERROR"
    unanimous: bool
    opinions: List[CourtRoleVerdict]
    chief_justification: str
    proof_strength: str = "NONE"
    epistemic_state: str = "UNKNOWN"
    court_judgment_id: str = ""
    canonical_verdict: str = "UNVERIFIED"
    prosecutor_ruling: Optional[Dict[str, Any]] = None
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "endpoint": self.target_endpoint,
            "verdict": self.final_verdict,
            "canonical_verdict": self.canonical_verdict,
            "unanimous": self.unanimous,
            "opinions": [
                {"role": o.role.value, "vote": o.disposition, "arg": o.argument}
                for o in self.opinions
            ],
            "justification": self.chief_justification,
            "proof_strength": self.proof_strength,
            "epistemic_state": self.epistemic_state,
            "court_judgment_id": self.court_judgment_id,
            "prosecutor_ruling": self.prosecutor_ruling,
        }


class EvidenceCourtV2:
    """Adversarial tribunal delegating proof adjudication to canonical EvidenceCourt + Prosecutor."""

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
        vuln_family: Optional[str] = None,
    ) -> TribunalRuling:
        """Adversarial tribunal delegating deterministic proof evaluation to
        canonical ``EvidenceCourt.adjudicate`` and cross-examination to
        ``AdversarialEvidenceProsecutor.cross_examine_finding``.
        """
        from core.evidence_court import CourtVerdict, EvidenceCourt, ProofStrength

        vr: Dict[str, Any] = dict(verifier_result or {})
        vr.setdefault("reproduced", reproductions_count >= 1)
        if proof_nonce_proven:
            vr.setdefault("deterministic_proof", True)
        if not waf_clean:
            vr.setdefault("waf_blocked", True)

        resolved_family = str(vuln_family or vr.get("vuln_class") or vr.get("vuln_family") or "")

        judgment = EvidenceCourt.adjudicate(
            target_url=endpoint,
            parameter=str(vr.get("parameter", "")),
            vuln_class=resolved_family,
            finder_claim={"claim": f"Tribunal case {case_id}"},
            verifier_result=vr,
            proof_payload=proof_payload,
            is_in_scope=bool(vr.get("is_in_scope", True)),
            allow_declared_proof=allow_declared_proof,
        )

        # Short-circuit honest UNAVAILABLE / ERROR propagation from canonical court
        if judgment.verdict in (CourtVerdict.UNAVAILABLE, CourtVerdict.ERROR):
            canon = judgment.canonical_verdict.value
            return TribunalRuling(
                case_id=case_id,
                target_endpoint=endpoint,
                final_verdict=canon,
                canonical_verdict=canon,
                unanimous=False,
                opinions=[
                    CourtRoleVerdict(
                        role=CourtParticipantRole.VERIFIER,
                        disposition="VOTE_INCONCLUSIVE",
                        argument=judgment.adjudication_rationale,
                        confidence=0.0,
                    )
                ],
                chief_justification=judgment.adjudication_rationale,
                proof_strength=judgment.proof_strength,
                epistemic_state=judgment.epistemic_state,
                court_judgment_id=judgment.judgment_id,
            )

        # Build prosecutor cross-examination payload (never auto-rebut explicit False values)
        derived_ok = (
            judgment.verdict == CourtVerdict.CONFIRMED
            and (judgment.proof_strength == ProofStrength.DERIVED.value or allow_declared_proof)
        )
        prosecutor_payload: Dict[str, Any] = dict(vr)
        prosecutor_payload["waf_clean"] = waf_clean
        prosecutor_payload["waf_block_detected"] = (not waf_clean) or (judgment.verdict == CourtVerdict.BLOCKED)
        prosecutor_payload["baseline_stable"] = baseline_stable
        prosecutor_payload.setdefault("timing_reproduced_n_times", reproductions_count if derived_ok else 0)
        if derived_ok:
            prosecutor_payload.setdefault("sensitive_data_leaked", True)
            prosecutor_payload.setdefault("dynamic_nonce_verified", True)

        prosecutor_ruling = AdversarialEvidenceProsecutor.cross_examine_finding(
            vuln_family=resolved_family,
            endpoint=endpoint,
            evidence_payload=prosecutor_payload,
        )

        opinions: List[CourtRoleVerdict] = []

        # 1. Finder
        opinions.append(CourtRoleVerdict(
            role=CourtParticipantRole.FINDER,
            disposition="VOTE_CONFIRM",
            argument=f"Observable anomaly detected on {endpoint} during active testing.",
            confidence=0.85,
        ))

        # 2. Verifier: confirms only when canonical court derived proof AND N >= 2 reproductions
        if derived_ok and reproductions_count >= 2:
            opinions.append(CourtRoleVerdict(
                role=CourtParticipantRole.VERIFIER,
                disposition="VOTE_CONFIRM",
                argument=(
                    f"Evidence Court confirmed by {judgment.proof_strength} proof "
                    f"across {reproductions_count} reproduction runs."
                ),
                confidence=0.95,
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
                confidence=0.90,
            ))

        # 3. Skeptic: Challenges baseline stability & WAF noise
        if not baseline_stable:
            opinions.append(CourtRoleVerdict(
                role=CourtParticipantRole.SKEPTIC,
                disposition="VOTE_INCONCLUSIVE",
                argument="Skeptic Challenge: Baseline is unstable. Flaky server responses mimic vulnerability symptoms.",
                confidence=0.88,
            ))
        elif not waf_clean:
            opinions.append(CourtRoleVerdict(
                role=CourtParticipantRole.SKEPTIC,
                disposition="VOTE_REJECT",
                argument="Skeptic Challenge: WAF challenge signature detected. Behavior caused by perimeter defense.",
                confidence=0.92,
            ))
        else:
            opinions.append(CourtRoleVerdict(
                role=CourtParticipantRole.SKEPTIC,
                disposition="VOTE_CONFIRM",
                argument="Skeptic Concession: All alternative noise explanations (Jitter, WAF, Auth Expired) eliminated.",
                confidence=0.92,
            ))

        # 4. Adversarial Prosecutor: Cross-examines counter-theories
        if prosecutor_ruling.all_rebutted:
            opinions.append(CourtRoleVerdict(
                role=CourtParticipantRole.PROSECUTOR,
                disposition="VOTE_CONFIRM",
                argument=prosecutor_ruling.justification,
                confidence=0.93,
            ))
        else:
            unmet_types = [c.theory_type for c in prosecutor_ruling.challenges_raised if not c.is_rebutted]
            only_jitter = bool(unmet_types) and all(
                t in (CounterTheoryType.BASELINE_INSTABILITY, CounterTheoryType.SERVER_TIMING_JITTER)
                for t in unmet_types
            )
            opinions.append(CourtRoleVerdict(
                role=CourtParticipantRole.PROSECUTOR,
                disposition="VOTE_INCONCLUSIVE" if only_jitter else "VOTE_REJECT",
                argument=prosecutor_ruling.justification,
                confidence=0.90,
            ))

        # 5. Causal Analyzer: Verifies unbroken cause-and-effect path
        if causal_chain_verified:
            opinions.append(CourtRoleVerdict(
                role=CourtParticipantRole.CAUSAL_ANALYZER,
                disposition="VOTE_CONFIRM",
                argument="Unbroken directed causal path from input parameter to observable execution sink confirmed.",
                confidence=0.95,
            ))
        else:
            opinions.append(CourtRoleVerdict(
                role=CourtParticipantRole.CAUSAL_ANALYZER,
                disposition="VOTE_REJECT",
                argument="Causal link broken: No direct data flow proven from payload to sink.",
                confidence=0.85,
            ))

        # 6. Chief Justice synthesizes votes + canonical 7-state verdict
        votes = [o.disposition for o in opinions]
        is_unanimous = len(set(votes)) == 1 and votes[0] == "VOTE_CONFIRM"

        if is_unanimous and derived_ok:
            final_verdict = "CONFIRMED"
            canon_verdict = CourtVerdict.CONFIRMED.value
            justification = (
                "Unanimous tribunal decision: deterministic proof, prosecutor cross-examination, "
                "causal chain, and absence of noise all proven."
            )
        elif "VOTE_INCONCLUSIVE" in votes and "VOTE_REJECT" not in votes:
            final_verdict = "INCONCLUSIVE"
            canon_verdict = CourtVerdict.INCONCLUSIVE.value
            justification = (
                "Tribunal impasse: Skeptic/Prosecutor raised unresolved environmental or timing doubts."
            )
        elif "VOTE_INCONCLUSIVE" in votes and not baseline_stable:
            final_verdict = "INCONCLUSIVE"
            canon_verdict = CourtVerdict.INCONCLUSIVE.value
            justification = (
                "Tribunal impasse: Skeptic raised valid doubts regarding server "
                "jitter or environmental instability."
            )
        elif votes.count("VOTE_REJECT") >= 1:
            final_verdict = "REFUTED"
            canon_verdict = (
                judgment.canonical_verdict.value
                if judgment.canonical_verdict in (CourtVerdict.UNVERIFIED, CourtVerdict.CANDIDATE, CourtVerdict.REJECTED)
                else CourtVerdict.REJECTED.value
            )
            if not prosecutor_ruling.all_rebutted or not waf_clean or not causal_chain_verified:
                canon_verdict = CourtVerdict.REJECTED.value
            justification = (
                f"Claim dismissed by tribunal officers: {judgment.adjudication_rationale}"
                + (f" | {prosecutor_ruling.justification}" if not prosecutor_ruling.all_rebutted else "")
            )
        else:
            final_verdict = "INCONCLUSIVE"
            canon_verdict = CourtVerdict.INCONCLUSIVE.value
            justification = "Split opinion among tribunal members."

        return TribunalRuling(
            case_id=case_id,
            target_endpoint=endpoint,
            final_verdict=final_verdict,
            canonical_verdict=canon_verdict,
            unanimous=is_unanimous,
            opinions=opinions,
            chief_justification=justification,
            proof_strength=judgment.proof_strength,
            epistemic_state=judgment.epistemic_state,
            court_judgment_id=judgment.judgment_id,
            prosecutor_ruling=prosecutor_ruling.to_dict(),
        )
