"""
HunterAI Adversarial Evidence Court Compatibility Shim
======================================================
Legacy compatibility adapter preserving ``Verdict``, ``CourtEvidence``,
``CourtArgument``, ``CourtCase``, and ``EvidenceCourt.try_case()`` while
delegating ALL proof adjudication to the single authoritative
``core.evidence_court.EvidenceCourt.adjudicate()``.

No confidence-score arithmetic (``>= 0.75``) can ever confirm a finding.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from core.evidence_court import (
    CausalEvidence,
    CourtJudgment,
    CourtVerdict as CanonicalCourtVerdict,
    EvidenceCourt as AuthoritativeEvidenceCourt,
    ProofPayload,
    ProofStrength,
)

log = logging.getLogger("hunter_ai.evidence_court")


class Verdict(str, Enum):
    CONFIRMED = "confirmed"        # Canonical CONFIRMED with DERIVED proof
    REJECTED = "rejected"          # Canonical REJECTED / FALSE_POSITIVE / DISPROVED / BLOCKED / OUT_OF_SCOPE
    INCONCLUSIVE = "inconclusive"  # Canonical UNVERIFIED / CANDIDATE / INCONCLUSIVE / UNAVAILABLE / ERROR
    ESCALATED = "escalated"        # Escalated for human review


@dataclass
class CourtEvidence:
    """Single piece of evidence submitted to the compatibility tribunal."""
    evidence_id: str
    source: str
    type: str
    description: str
    confidence: float
    raw_data: Dict[str, Any] = field(default_factory=dict)
    captured_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "evidence_id": self.evidence_id,
            "source": self.source,
            "type": self.type,
            "description": self.description,
            "confidence": self.confidence,
            "raw_data": self.raw_data,
            "captured_at": self.captured_at,
        }


@dataclass
class CourtArgument:
    """Argument recorded during compatibility tribunal adjudication."""
    role: str
    argument: str
    supporting_evidence: List[str] = field(default_factory=list)
    confidence_delta: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "role": self.role,
            "argument": self.argument,
            "supporting_evidence": self.supporting_evidence,
            "confidence_delta": self.confidence_delta,
            "timestamp": self.timestamp,
        }


@dataclass
class CourtCase:
    """Case record tracking canonical judgment and mapped legacy Verdict."""
    case_id: str
    finding_type: str
    target: str
    evidence: List[CourtEvidence] = field(default_factory=list)
    arguments: List[CourtArgument] = field(default_factory=list)
    verdict: Verdict = Verdict.INCONCLUSIVE
    final_confidence: float = 0.0
    reasoning_summary: str = ""
    requires_manual_review: bool = False
    canonical_verdict: str = CanonicalCourtVerdict.UNVERIFIED.value
    proof_strength: str = ProofStrength.NONE.value
    court_judgment_id: str = ""
    created_at: float = field(default_factory=time.time)
    concluded_at: Optional[float] = None

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "finding_type": self.finding_type,
            "target": self.target,
            "evidence": [e.to_dict() for e in self.evidence],
            "arguments": [a.to_dict() for a in self.arguments],
            "verdict": self.verdict.value if isinstance(self.verdict, Enum) else str(self.verdict),
            "canonical_verdict": self.canonical_verdict,
            "proof_strength": self.proof_strength,
            "court_judgment_id": self.court_judgment_id,
            "final_confidence": round(self.final_confidence, 3),
            "reasoning_summary": self.reasoning_summary,
            "requires_manual_review": self.requires_manual_review,
            "created_at": self.created_at,
            "concluded_at": self.concluded_at,
        }


class EvidenceCourt:
    """Compatibility tribunal delegating every verdict to canonical core.evidence_court.EvidenceCourt."""

    def __init__(self) -> None:
        self.cases: Dict[str, CourtCase] = {}
        self.verdict_history: List[CourtCase] = []

    @staticmethod
    def _extract_adjudication_inputs(
        finding_type: str,
        evidence: List[CourtEvidence],
    ) -> Tuple[Dict[str, Any], Optional[ProofPayload], Optional[CausalEvidence], bool, bool]:
        """Extract raw checkable artifacts from legacy CourtEvidence items."""
        verifier_result: Dict[str, Any] = {}
        proof_payload: Optional[ProofPayload] = None
        causal_evidence: Optional[CausalEvidence] = None
        is_in_scope = True
        is_blocked_by_waf = False

        for item in evidence:
            raw = item.raw_data if isinstance(item.raw_data, dict) else {}
            if raw.get("is_in_scope") is False:
                is_in_scope = False
            if raw.get("waf_blocked"):
                is_blocked_by_waf = True
            if raw.get("is_reflection"):
                verifier_result["is_reflection"] = True
            if raw.get("length_delta_only"):
                verifier_result["length_delta_only"] = True
            if raw.get("status_change_only"):
                verifier_result["status_change_only"] = True
            if raw.get("error") or raw.get("exception"):
                verifier_result["error"] = raw.get("error") or raw.get("exception")
            if raw.get("timeout") or raw.get("timed_out") or raw.get("unavailable") or raw.get("missing_binary"):
                verifier_result["unavailable"] = True
                verifier_result["reason"] = str(raw.get("reason") or "verifier_unavailable")
            if raw.get("reproduced"):
                verifier_result["reproduced"] = True
            if "status_code" in raw:
                verifier_result["status_code"] = raw["status_code"]

            # Structured CausalEvidence object if present
            ce = raw.get("causal_evidence")
            if isinstance(ce, CausalEvidence):
                causal_evidence = ce
                verifier_result["reproduced"] = True

            # Explicit ProofPayload
            if proof_payload is None and raw.get("proof_payload"):
                proof_payload = ProofPayload.from_mapping(raw.get("proof_payload"))
                if proof_payload is not None:
                    verifier_result["reproduced"] = True

            # Raw HTTP response / baseline / token fields inside raw_data
            if proof_payload is None and any(
                k in raw for k in ("response_text", "response_body", "expected_token", "expected_result")
            ):
                proof_payload = ProofPayload(
                    response_text=str(raw.get("response_text") or raw.get("response_body") or ""),
                    baseline_text=str(raw.get("baseline_text") or raw.get("baseline_body") or ""),
                    artifact_type=str(raw.get("artifact_type") or finding_type),
                    probed_expression=str(raw.get("probed_expression") or "53+19"),
                    expected_result=str(raw.get("expected_result") or "72"),
                    expected_token=str(raw.get("expected_token") or ""),
                    metadata=dict(raw.get("metadata") or raw),
                )
                verifier_result["reproduced"] = True

        # If evidence exists without explicit failure/reflection flags, mark signal observed (NOT proven)
        if evidence and not verifier_result:
            verifier_result = {"reproduced": False, "status": "CANDIDATE"}

        return verifier_result, proof_payload, causal_evidence, is_in_scope, is_blocked_by_waf

    @staticmethod
    def _map_canonical_to_legacy(judgment: CourtJudgment) -> Tuple[Verdict, bool]:
        canon = judgment.canonical_verdict
        if canon == CanonicalCourtVerdict.CONFIRMED and judgment.proof_strength == ProofStrength.DERIVED.value:
            return Verdict.CONFIRMED, False
        if canon == CanonicalCourtVerdict.REJECTED:
            return Verdict.REJECTED, False
        return Verdict.INCONCLUSIVE, True

    async def try_case(
        self,
        case_id: str,
        finding_type: str,
        target: str,
        evidence: List[CourtEvidence],
        initial_confidence: float = 0.5,
    ) -> CourtCase:
        """Adjudicate a case by delegating directly to canonical core.evidence_court.EvidenceCourt."""
        verifier_result, proof_payload, causal_evidence, is_in_scope, is_blocked_by_waf = (
            self._extract_adjudication_inputs(finding_type, evidence)
        )

        judgment = AuthoritativeEvidenceCourt.adjudicate(
            target_url=target,
            parameter="",
            vuln_class=finding_type,
            finder_claim={
                "case_id": case_id,
                "evidence_count": len(evidence),
                "sources": sorted({e.source for e in evidence}),
            },
            verifier_result=verifier_result or None,
            is_in_scope=is_in_scope,
            is_blocked_by_waf=is_blocked_by_waf,
            causal_evidence=causal_evidence,
            proof_payload=proof_payload,
            allow_declared_proof=False,
        )

        legacy_verdict, requires_manual = self._map_canonical_to_legacy(judgment)

        case = CourtCase(
            case_id=case_id,
            finding_type=finding_type,
            target=target,
            evidence=evidence,
            verdict=legacy_verdict,
            final_confidence=judgment.confidence_score,
            reasoning_summary=judgment.adjudication_rationale,
            requires_manual_review=requires_manual,
            canonical_verdict=judgment.canonical_verdict.value,
            proof_strength=judgment.proof_strength,
            court_judgment_id=judgment.judgment_id,
            concluded_at=time.time(),
        )

        case.arguments.extend([
            CourtArgument(
                role="finder",
                argument=f"Submitted {len(evidence)} evidence item(s) for {finding_type} on {target}.",
                supporting_evidence=[e.evidence_id for e in evidence],
            ),
            CourtArgument(
                role="verifier",
                argument=f"Canonical EvidenceCourt proof evaluation: strength={judgment.proof_strength}, kind={judgment.proof_kind or 'none'}.",
                supporting_evidence=[e.evidence_id for e in evidence],
            ),
            CourtArgument(
                role="justice",
                argument=f"Canonical verdict={judgment.canonical_verdict.value} -> legacy={legacy_verdict.value}. {judgment.adjudication_rationale}",
            ),
        ])

        self.cases[case_id] = case
        self.verdict_history.append(case)
        log.info(
            "[EvidenceCourt-Shim] Case %s: legacy=%s canonical=%s proof_strength=%s",
            case_id,
            legacy_verdict.value,
            judgment.canonical_verdict.value,
            judgment.proof_strength,
        )
        return case

    def get_confirmed_cases(self) -> List[CourtCase]:
        return [c for c in self.cases.values() if c.verdict == Verdict.CONFIRMED]

    def get_manual_review_queue(self) -> List[CourtCase]:
        return [c for c in self.cases.values() if c.requires_manual_review]

    def get_rejected_cases(self) -> List[CourtCase]:
        return [c for c in self.cases.values() if c.verdict == Verdict.REJECTED]

    def get_all_cases(self) -> List[CourtCase]:
        return list(self.cases.values())

    def clear(self) -> None:
        self.cases.clear()
        self.verdict_history.clear()


evidence_court = EvidenceCourt()
