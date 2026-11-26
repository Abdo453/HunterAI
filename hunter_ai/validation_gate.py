"""
HunterAI 7-Question Gate — Authoritative Validation Gate
========================================================
Runs a strict 7-question gate on every finding before it can be reported.
Kills weak findings early — N/A hurts your validity ratio.

Truthfulness Enforcement:
- Q3 & Q4 NEVER trust bare caller-set boolean flags (``poe_verified=True``,
  ``deterministic_proof=True``, ``real_exploit_path=True``) on their own.
- Confirmation REQUIRES a real canonical ``CourtVerdict.CONFIRMED`` judgment
  backed by ``ProofStrength.DERIVED`` from ``core.evidence_court.EvidenceCourt``.

Verdicts: PROVEN | REFUTED | UNPROVEN | INCONCLUSIVE
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, Optional

from core.evidence_court import (
    CausalEvidence,
    CourtJudgment,
    CourtVerdict,
    EvidenceCourt,
    ProofPayload,
    ProofStrength,
)


class GateVerdict(str, Enum):
    PROVEN = "PROVEN"
    REFUTED = "REFUTED"
    UNPROVEN = "UNPROVEN"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass
class GateResult:
    question: str
    passed: bool
    reason: str


@dataclass
class ValidationResult:
    finding_id: str
    title: str
    target: str
    status: GateVerdict = GateVerdict.INCONCLUSIVE
    confidence: float = 0.0
    gates: list[GateResult] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    rationale: str = ""
    timestamp: float = field(default_factory=time.time)
    never_submit: bool = False
    safety_check: Optional[dict[str, Any]] = None
    canonical_verdict: str = CourtVerdict.UNVERIFIED.value
    proof_strength: str = ProofStrength.NONE.value

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "target": self.target,
            "status": self.status.value,
            "canonical_verdict": self.canonical_verdict,
            "proof_strength": self.proof_strength,
            "confidence": self.confidence,
            "gates": [asdict(g) for g in self.gates],
            "evidence": self.evidence,
            "rationale": self.rationale,
            "never_submit": self.never_submit,
            "timestamp": self.timestamp,
            "safety_check": self.safety_check,
        }


class ValidationGate:
    """
    7-Question Gate — kills weak findings before reporting.
    Only findings backed by canonical CourtVerdict.CONFIRMED + ProofStrength.DERIVED
    can earn GateVerdict.PROVEN.
    """

    NEVER_SUBMIT_PATTERNS = [
        "reflection only",
        "theoretical",
        "no impact",
        "out of scope",
        "self-xss",
        "clickjacking without impact",
        "missing hsts",
        "cookie without httponly",
    ]

    def __init__(self, min_confidence: float = 0.85):
        self.min_confidence = min_confidence
        self._safety_loop = None

    @property
    def safety_loop(self):
        if self._safety_loop is None:
            from hunter_ai.safety.neuro_symbolic_loop import (
                KnowledgeGraph,
                NeuroSymbolicSafetyLoop,
            )
            self._safety_loop = NeuroSymbolicSafetyLoop(KnowledgeGraph())
        return self._safety_loop

    @staticmethod
    def _adjudicate_evidence(
        target: str,
        title: str,
        evidence: Dict[str, Any],
        in_scope: bool,
    ) -> CourtJudgment:
        """Evaluate finding evidence through canonical EvidenceCourt (DERIVED only)."""
        existing = evidence.get("court_judgment")
        if isinstance(existing, CourtJudgment):
            return existing

        vuln_class = str(
            evidence.get("vuln_class")
            or evidence.get("vuln_type")
            or title
            or ""
        )
        proof_payload = ProofPayload.from_mapping(evidence.get("proof_payload"))
        causal_ev = evidence.get("causal_evidence")
        if not isinstance(causal_ev, CausalEvidence):
            causal_ev = None

        # Construct ProofPayload if caller supplied raw checkable HTTP response/token fields
        if proof_payload is None and any(
            k in evidence for k in ("response_text", "response_body", "expected_token")
        ):
            proof_payload = ProofPayload(
                response_text=str(evidence.get("response_text") or evidence.get("response_body") or ""),
                baseline_text=str(evidence.get("baseline_text") or evidence.get("baseline_body") or ""),
                artifact_type=str(evidence.get("artifact_type") or vuln_class),
                probed_expression=str(evidence.get("probed_expression") or "53+19"),
                expected_result=str(evidence.get("expected_result") or evidence.get("arithmetic_proof") or "72"),
                expected_token=str(evidence.get("expected_token") or ""),
                metadata=dict(evidence.get("metadata") or {}),
            )

        # Fallback deterministic PoE signature extraction from raw response text
        if proof_payload is None and evidence.get("response"):
            proof_payload = ProofPayload.from_vuln_evidence(vuln_class, str(evidence.get("response")))

        verifier_result: Dict[str, Any] = {
            "reproduced": bool(
                evidence.get("reproduced", False)
                or proof_payload is not None
                or causal_ev is not None
                or (evidence.get("poc") and evidence.get("differential_response"))
            ),
            "is_reflection": bool(evidence.get("is_reflection", False)),
            "length_delta_only": bool(evidence.get("length_delta_only", False)),
            "status_change_only": bool(evidence.get("status_change_only", False)),
        }
        if evidence.get("poe_verified") or evidence.get("deterministic_proof"):
            # Recorded as DECLARED only — canonical EvidenceCourt will NEVER confirm without DERIVED proof!
            verifier_result["deterministic_proof"] = True

        return EvidenceCourt.adjudicate(
            target_url=target,
            parameter=str(evidence.get("parameter") or ""),
            vuln_class=vuln_class,
            finder_claim={"title": title},
            verifier_result=verifier_result,
            is_in_scope=in_scope,
            causal_evidence=causal_ev,
            proof_payload=proof_payload,
            allow_declared_proof=False,
        )

    def validate(
        self,
        finding: dict[str, Any] | str,
        target: str = "",
        evidence: Optional[dict[str, Any]] = None,
        run_safety_check: bool = True,
    ) -> ValidationResult:
        """Run the 7-Question Gate on a finding."""
        if isinstance(finding, str):
            title = finding
            finding_id = hashlib.md5(f"{target}:{title}".encode()).hexdigest()[:8]
            ev = dict(evidence or {})
        else:
            title = finding.get("title", "Untitled Finding")
            target = finding.get("target", target)
            finding_id = finding.get("id", hashlib.md5(f"{target}:{title}".encode()).hexdigest()[:8])
            ev = dict(evidence if evidence is not None else (finding.get("evidence") or {}))

        result = ValidationResult(
            finding_id=finding_id,
            title=title,
            target=target,
            evidence=ev,
        )

        # Neuro-Symbolic Safety Check — runs BEFORE the 7 questions
        if run_safety_check:
            safety_result = self.safety_loop.check_command(
                command=f"validate-finding:{title}",
                target=target,
                require_proof=True,
            )
            result.safety_check = safety_result.to_dict()
            if safety_result.verdict.value == "BLOCKED":
                result.status = GateVerdict.REFUTED
                result.canonical_verdict = CourtVerdict.REJECTED.value
                result.rationale = f"Blocked by safety loop: {safety_result.reason}"
                return result

        # Question 1: Reproducible RIGHT NOW?
        q1 = self._q1_reproducible(ev)
        result.gates.append(q1)
        if not q1.passed:
            result.status = GateVerdict.REFUTED
            result.canonical_verdict = CourtVerdict.REJECTED.value
            result.rationale = "Not reproducible right now (reflection or missing reproduction artifact)"
            return result

        # Question 2: In scope?
        q2 = self._q2_in_scope(target)
        result.gates.append(q2)
        if not q2.passed:
            result.status = GateVerdict.REFUTED
            result.canonical_verdict = CourtVerdict.REJECTED.value
            result.rationale = "Target out of authorized scope"
            return result

        # Authoritative Evidence Court adjudication (DERIVED proof required; caller booleans rejected)
        judgment = self._adjudicate_evidence(target=target, title=title, evidence=ev, in_scope=q2.passed)
        result.canonical_verdict = judgment.canonical_verdict.value
        result.proof_strength = judgment.proof_strength

        # Question 3: Deterministic proof (canonical CONFIRMED + DERIVED)?
        q3 = self._q3_deterministic_proof(ev, judgment=judgment)
        result.gates.append(q3)
        if not q3.passed:
            if judgment.canonical_verdict == CourtVerdict.REJECTED:
                result.status = GateVerdict.REFUTED
            else:
                result.status = GateVerdict.UNPROVEN
            result.rationale = q3.reason
            return result

        # Question 4: Real bug, not theoretical (backed by canonical CONFIRMED)?
        q4 = self._q4_real_bug(ev, judgment=judgment)
        result.gates.append(q4)
        if not q4.passed:
            result.status = GateVerdict.REFUTED
            result.rationale = q4.reason
            return result

        # Question 5: Impact clear?
        q5 = self._q5_impact(ev)
        result.gates.append(q5)

        # Question 6: Evidence complete?
        q6 = self._q6_evidence_complete(ev)
        result.gates.append(q6)

        # Question 7: Worth reporting?
        q7 = self._q7_worth_reporting(ev)
        result.gates.append(q7)

        passed = all(g.passed for g in result.gates)
        confidence = sum(1 for g in result.gates if g.passed) / len(result.gates)
        result.confidence = confidence

        if passed and confidence >= self.min_confidence:
            result.status = GateVerdict.PROVEN
            result.rationale = "All 7 gate questions passed with canonical DERIVED Evidence Court proof — reportable"
        elif confidence >= 0.60:
            result.status = GateVerdict.UNPROVEN
            result.rationale = "Partial gate pass — needs more evidence"
        else:
            result.status = GateVerdict.REFUTED
            result.rationale = "Failed gate questions — suppressed"

        # Never-submit check
        text = (title + " " + json.dumps(ev, ensure_ascii=False, default=str)).lower()
        for pattern in self.NEVER_SUBMIT_PATTERNS:
            if pattern in text:
                result.never_submit = True
                if result.status == GateVerdict.PROVEN:
                    result.status = GateVerdict.REFUTED
                    result.canonical_verdict = CourtVerdict.REJECTED.value
                    result.rationale = f"Never-submit pattern matched: {pattern}"
                break

        return result

    # ── Gate Questions ──────────────────────────────────────────

    def _q1_reproducible(self, evidence: dict) -> GateResult:
        """Q1: Can an attacker do this RIGHT NOW?"""
        has_poc = bool(evidence.get("poc") or evidence.get("reproduction"))
        has_artifact = bool(
            evidence.get("proof_payload")
            or evidence.get("causal_evidence")
            or isinstance(evidence.get("court_judgment"), CourtJudgment)
            or evidence.get("nonce")
            or evidence.get("arithmetic_proof")
            or evidence.get("differential_response")
        )
        if has_poc and has_artifact:
            return GateResult("Q1: Reproducible RIGHT NOW?", True, "PoC and checkable reproduction artifact present")
        return GateResult("Q1: Reproducible RIGHT NOW?", False, "Missing PoC or verifiable reproduction artifact")

    def _q2_in_scope(self, target: str) -> GateResult:
        """Q2: Is it in scope?"""
        from hunter_ai.core.scope_engine import StrictScopeEngine
        engine = StrictScopeEngine()
        if engine.is_allowed(target):
            return GateResult("Q2: In scope?", True, f"{target} is authorized")
        return GateResult("Q2: In scope?", False, f"{target} is outside authorized scope")

    def _q3_deterministic_proof(
        self,
        evidence: dict,
        judgment: Optional[CourtJudgment] = None,
    ) -> GateResult:
        """Q3: Is there canonical CONFIRMED + DERIVED deterministic proof?"""
        if judgment is None:
            judgment = self._adjudicate_evidence(
                target=str(evidence.get("target") or ""),
                title="",
                evidence=evidence,
                in_scope=True,
            )
        if (
            judgment.verdict == CourtVerdict.CONFIRMED
            and judgment.proof_strength == ProofStrength.DERIVED.value
        ):
            return GateResult(
                "Q3: Deterministic proof?",
                True,
                f"Canonical EvidenceCourt CONFIRMED with DERIVED proof ({judgment.proof_kind}): {judgment.proof_detail}",
            )
        return GateResult(
            "Q3: Deterministic proof?",
            False,
            f"Canonical EvidenceCourt did not confirm with DERIVED proof "
            f"(verdict={judgment.canonical_verdict.value}, proof_strength={judgment.proof_strength}): "
            f"{judgment.adjudication_rationale}",
        )

    def _q4_real_bug(
        self,
        evidence: dict,
        judgment: Optional[CourtJudgment] = None,
    ) -> GateResult:
        """Q4: Real bug, not theoretical (must be backed by canonical DERIVED confirmation)?"""
        if (
            judgment is not None
            and judgment.verdict == CourtVerdict.CONFIRMED
            and judgment.proof_strength == ProofStrength.DERIVED.value
        ):
            return GateResult("Q4: Real bug?", True, "Exploitability established by canonical DERIVED court proof")
        return GateResult("Q4: Real bug?", False, "Unconfirmed or theoretical only without canonical DERIVED proof")

    def _q5_impact(self, evidence: dict) -> GateResult:
        """Q5: Impact clear?"""
        impact = str(evidence.get("impact") or "")
        if impact and len(impact) > 10:
            return GateResult("Q5: Impact clear?", True, f"Impact: {impact[:80]}")
        return GateResult("Q5: Impact clear?", False, "Impact not described")

    def _q6_evidence_complete(self, evidence: dict) -> GateResult:
        """Q6: Evidence complete?"""
        has_req = bool(evidence.get("request_hash") or evidence.get("request"))
        has_resp = bool(
            evidence.get("response_hash")
            or evidence.get("response")
            or evidence.get("response_text")
            or evidence.get("proof_payload")
        )
        if has_req and has_resp:
            return GateResult("Q6: Evidence complete?", True, "Request/response artifacts present")
        return GateResult("Q6: Evidence complete?", False, "Missing request/response artifacts")

    def _q7_worth_reporting(self, evidence: dict) -> GateResult:
        """Q7: Worth reporting?"""
        severity = str(evidence.get("severity") or "").lower()
        if severity in ("critical", "high", "medium"):
            return GateResult("Q7: Worth reporting?", True, f"Severity: {severity}")
        return GateResult("Q7: Worth reporting?", False, "Low or unknown severity")


def validate_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Convenience function — validate a finding dict."""
    gate = ValidationGate()
    result = gate.validate(finding)
    return result.to_dict()
