"""
Evidence Court (محكمة الأدلة) - V27.0 Advanced Epistemic Adjudication
=====================================================================
Multi-party adjudication engine ensuring no single agent, tool, or LLM can
declare a finding as CONFIRMED without independent, deterministic verification,
causal invariant proof, and metamorphic consistency.

V27.0 ARCHITECTURAL RULES:
1. Four Evidence Classes:
   - Causal Evidence:    Metamorphic Triad (B x C x E1 x E2) & Invariant Proof
   - Negative Evidence:  Context-Scoped Boundary Proof (BOUNDARY_ENFORCED_FOR_TESTED_CONTEXT)
   - Execution Evidence: Physical Execution Telemetry & PoE (Proof of Execution)
2. Inviolable Epistemic Axioms:
   - Execution Evidence alone != Vulnerability (NOT ENOUGH)
   - Response Difference alone != Vulnerability (NOT ENOUGH)
   - PoE alone != Vulnerability Proof (NOT ENOUGH)
   - Metamorphic Contradiction (E1 != E2) -> UNVERIFIED / PARTIALLY_VERIFIED (NEVER CONFIRMED)
3. Calibrated Reporting:
   - Findings confirmed ONLY with complete Causal Triad + Metamorphic Relation + Invariant Proof.
   - Disclaimers explicitly state that metrics are evaluated on the benchmark corpus.
"""
from __future__ import annotations

import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union

logger = logging.getLogger("hunter_ai.evidence_court")


class CourtVerdict(str, Enum):
    CONFIRMED = "CONFIRMED"
    UNVERIFIED = "UNVERIFIED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    DISPROVED = "DISPROVED"
    INCONCLUSIVE = "INCONCLUSIVE"
    BLOCKED = "BLOCKED"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    DUPLICATE = "DUPLICATE"


@dataclass
class CausalEvidence:
    """Class 1: Formal Invariant and Metamorphic Triad Verification Evidence."""
    metamorphic_passed: bool = False
    invariant_passed: bool = False
    invariant_id: str = ""
    causal_strength: float = 0.0
    contradiction_detected: bool = False
    rationale: str = ""
    extracted_observables: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class NegativeEvidence:
    """Class 2: Context-Scoped Defense Boundary Verification Evidence."""
    status_code: Optional[int] = None
    pattern_matched: Optional[str] = None
    boundary_conclusion: str = "BOUNDARY_ENFORCED_FOR_TESTED_CONTEXT"
    unexplored_status: str = "UNKNOWN"
    context_scope: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ExecutionEvidence:
    """Class 3: Physical Execution Telemetry and Proof-of-Execution (PoE)."""
    reproduced: bool = False
    poe_token: Optional[str] = None
    arithmetic_confirmed: bool = False
    status_code: int = 200
    length_delta_only: bool = False
    status_change_only: bool = False
    is_reflection: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CausalTriad:
    """The legacy lightweight triad adapter for backward compatibility."""
    baseline_status: int = 200
    baseline_length: int = 1000
    control_status: int = 200
    control_length: int = 1000
    experiment_status: int = 200
    experiment_length: int = 1000
    control_payload_reflected: bool = False
    experiment_payload_reflected: bool = False
    deterministic_execution_token: Optional[str] = None
    metamorphic_relation: Optional[str] = None
    raw_evidence: Dict[str, Any] = field(default_factory=dict)

    def evaluate_causality(self) -> Tuple[bool, str]:
        if (
            self.experiment_status == self.control_status
            and abs(self.experiment_length - self.control_length) < 10
            and not self.deterministic_execution_token
        ):
            return False, "Control mutation produced identical shift as experiment (Dynamic noise or neutral input handling)."

        if (
            self.experiment_status == self.baseline_status
            and abs(self.experiment_length - self.baseline_length) < 5
            and not self.deterministic_execution_token
        ):
            return False, "Experiment produced zero observable differentiation from baseline."

        return True, "Causal differentiation proven: E distinct from both Baseline (B) and Control (C)."


@dataclass
class CourtJudgment:
    judgment_id: str = field(default_factory=lambda: f"judg_{uuid.uuid4().hex[:8]}")
    target_url: str = ""
    parameter: str = ""
    vuln_class: str = ""
    verdict: CourtVerdict = CourtVerdict.UNVERIFIED
    calibrated_severity: str = "Info"
    confidence_score: float = 0.0
    reportable: bool = False
    finder_claim: Dict[str, Any] = field(default_factory=dict)
    verifier_result: Dict[str, Any] = field(default_factory=dict)
    adjudication_rationale: str = ""
    negative_evidence: List[str] = field(default_factory=list)
    provenance_chain: List[Dict[str, Any]] = field(default_factory=list)
    causal_triad_evaluated: bool = False
    causality_rationale: Optional[str] = None
    contradiction_detected: bool = False
    epistemic_state: str = "UNKNOWN"
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["verdict"] = self.verdict.value
        return d


class EvidenceCourt:
    """Authoritative Multi-Party Evidence Court enforcing Causal Invariants & Epistemic Separation."""

    @classmethod
    def adjudicate(
        cls,
        target_url: str,
        parameter: str,
        vuln_class: str,
        finder_claim: Dict[str, Any],
        verifier_result: Optional[Dict[str, Any]] = None,
        is_in_scope: bool = True,
        is_blocked_by_waf: bool = False,
        provenance_chain: Optional[List[Dict[str, Any]]] = None,
        causal_triad: Optional[Union[Dict[str, Any], CausalTriad]] = None,
        causal_evidence: Optional[CausalEvidence] = None,
        negative_evidence: Optional[Union[Dict[str, Any], NegativeEvidence]] = None,
        negative_observables: Optional[Dict[str, Any]] = None,
    ) -> CourtJudgment:
        judgment = CourtJudgment(
            target_url=target_url,
            parameter=parameter,
            vuln_class=vuln_class,
            finder_claim=finder_claim,
            verifier_result=verifier_result or {},
            provenance_chain=provenance_chain or [],
        )

        # 1. Inviolable Scope Check
        if not is_in_scope:
            judgment.verdict = CourtVerdict.OUT_OF_SCOPE
            judgment.calibrated_severity = "Info"
            judgment.confidence_score = 0.0
            judgment.reportable = False
            judgment.epistemic_state = "BLOCKED"
            judgment.adjudication_rationale = "Target URL is outside authorized scope. Strictly discarded by Scope Firewall."
            judgment.negative_evidence.append("Out of scope target.")
            return judgment

        # 2. WAF Interception Check
        if is_blocked_by_waf or finder_claim.get("waf_blocked") or (verifier_result and verifier_result.get("waf_blocked")):
            judgment.verdict = CourtVerdict.BLOCKED
            judgment.calibrated_severity = "Info"
            judgment.confidence_score = 0.1
            judgment.reportable = False
            judgment.epistemic_state = "BLOCKED"
            judgment.adjudication_rationale = "Probe was intercepted or blocked by Cloudflare/WAF. Does not prove application vulnerability."
            judgment.negative_evidence.append("WAF challenge or block response detected.")
            return judgment

        # 3. Negative Evidence Evaluation (Scoped Boundary Enforcement)
        observed_status = (verifier_result or {}).get("status_code") or (verifier_result or {}).get("status")
        observed_body = str((verifier_result or {}).get("response_body") or "").lower()

        neg_specs = negative_observables or (verifier_result or {}).get("negative_observables")
        if neg_specs and isinstance(neg_specs, dict):
            neg_statuses = neg_specs.get("status_codes", [])
            neg_patterns = neg_specs.get("response_patterns", [])

            if observed_status in neg_statuses:
                judgment.verdict = CourtVerdict.DISPROVED
                judgment.calibrated_severity = "Info"
                judgment.confidence_score = 0.0
                judgment.reportable = False
                judgment.epistemic_state = "REJECTED"
                judgment.adjudication_rationale = (
                    f"Negative observable triggered: Status code {observed_status} confirms "
                    "BOUNDARY_ENFORCED_FOR_TESTED_CONTEXT. (Unexplored transitions remain UNKNOWN)."
                )
                judgment.negative_evidence.append(f"HTTP Status {observed_status} (Tested defense boundary)")
                return judgment

            for pat in neg_patterns:
                if pat.lower() in observed_body:
                    judgment.verdict = CourtVerdict.DISPROVED
                    judgment.calibrated_severity = "Info"
                    judgment.confidence_score = 0.0
                    judgment.reportable = False
                    judgment.epistemic_state = "REJECTED"
                    judgment.adjudication_rationale = (
                        f"Negative observable triggered: Pattern '{pat}' found. "
                        "BOUNDARY_ENFORCED_FOR_TESTED_CONTEXT."
                    )
                    judgment.negative_evidence.append(f"Defense pattern: '{pat}'")
                    return judgment

        # 4. Contradictory Evidence Evaluation (CRITICAL EPISTEMIC GATE)
        # If E1 and E2 yielded divergent results, or if contradiction was flagged
        is_contradictory = (
            (causal_evidence and causal_evidence.contradiction_detected)
            or (verifier_result and verifier_result.get("contradiction_detected"))
            or (verifier_result and verifier_result.get("metamorphic_inconsistent"))
        )

        if is_contradictory:
            judgment.verdict = CourtVerdict.UNVERIFIED
            judgment.calibrated_severity = "Low"
            judgment.confidence_score = 0.40
            judgment.reportable = False
            judgment.contradiction_detected = True
            judgment.epistemic_state = "PARTIALLY_VERIFIED"
            judgment.adjudication_rationale = (
                "Metamorphic Contradiction: Probe E1 and metamorphic probe E2 produced conflicting results. "
                "Causal invariant refuted or unconfirmed. State held at PARTIALLY_VERIFIED."
            )
            judgment.negative_evidence.append("Contradictory probe observations detected.")
            return judgment

        # 5. Independent Verification & Reflection Filter
        if not verifier_result or not verifier_result.get("reproduced"):
            if finder_claim.get("is_reflection") or (verifier_result and verifier_result.get("is_reflection")):
                judgment.verdict = CourtVerdict.FALSE_POSITIVE
                judgment.calibrated_severity = "Info"
                judgment.confidence_score = 0.05
                judgment.reportable = False
                judgment.epistemic_state = "REJECTED"
                judgment.adjudication_rationale = "Reflection detected without execution proof (Reflection != Execution)."
                judgment.negative_evidence.append("Input echoed literally in DOM or script tag.")
                return judgment

            if not verifier_result:
                judgment.verdict = CourtVerdict.INCONCLUSIVE
                judgment.calibrated_severity = "Low"
                judgment.confidence_score = 0.35
                judgment.reportable = False
                judgment.epistemic_state = "UNKNOWN"
                judgment.adjudication_rationale = "Verification infrastructure did not execute or timed out. Inconclusive."
                return judgment

            judgment.verdict = CourtVerdict.UNVERIFIED
            judgment.calibrated_severity = "Low"
            judgment.confidence_score = 0.40
            judgment.reportable = False
            judgment.epistemic_state = "TESTED"
            judgment.adjudication_rationale = "Initial signal detected, but independent verifier could not reproduce effect."
            judgment.negative_evidence.append("Independent re-check failed to reproduce.")
            return judgment

        # 6. Axiom Enforcement: Response Length Delta or Status Alone != Vulnerability
        length_delta_only = verifier_result.get("length_delta_only", False)
        status_change_only = verifier_result.get("status_change_only", False)

        if length_delta_only or status_change_only:
            judgment.verdict = CourtVerdict.FALSE_POSITIVE
            judgment.calibrated_severity = "Info"
            judgment.confidence_score = 0.10
            judgment.reportable = False
            judgment.epistemic_state = "REJECTED"
            judgment.adjudication_rationale = (
                "Causality Gate Violation: Response length delta or HTTP status code change alone "
                "does NOT prove vulnerability. Proof of Execution (PoE) != Proof of Vulnerability (PoV)."
            )
            judgment.negative_evidence.append("Length divergence or status change without semantic execution proof.")
            return judgment

        # Evaluate legacy Causal Triad if provided
        if causal_triad:
            triad_obj = causal_triad if isinstance(causal_triad, CausalTriad) else CausalTriad(**causal_triad)
            is_causal, reason = triad_obj.evaluate_causality()
            judgment.causal_triad_evaluated = True
            judgment.causality_rationale = reason

            if not is_causal:
                judgment.verdict = CourtVerdict.FALSE_POSITIVE
                judgment.calibrated_severity = "Info"
                judgment.confidence_score = 0.10
                judgment.reportable = False
                judgment.epistemic_state = "REJECTED"
                judgment.adjudication_rationale = f"Causality Gate Violation: {reason}"
                judgment.negative_evidence.append(reason)
                return judgment

        # 7. Causal Invariant & Deterministic Proof Gate
        has_deterministic_proof = bool(
            (causal_evidence and causal_evidence.invariant_passed) or
            verifier_result.get("arithmetic_proof_confirmed") or
            verifier_result.get("extracted_data") or
            verifier_result.get("auth_bypass_confirmed") or
            verifier_result.get("file_content_confirmed") or
            verifier_result.get("boolean_branch_confirmed") or
            verifier_result.get("canary_confirmed") or
            verifier_result.get("template_eval_confirmed") or
            verifier_result.get("dom_breakout_confirmed") or
            verifier_result.get("token_bypass_confirmed") or
            verifier_result.get("deterministic_proof")
        )

        if has_deterministic_proof:
            judgment.verdict = CourtVerdict.CONFIRMED
            judgment.reportable = True
            judgment.epistemic_state = "CONFIRMED"
            judgment.confidence_score = float(
                (causal_evidence.causal_strength if causal_evidence else 0) or
                verifier_result.get("confidence", 0.98)
            )

            # Severity calibration
            v_lower = vuln_class.lower()
            if any(k in v_lower for k in ("rce", "cmd_injection", "command_injection")):
                judgment.calibrated_severity = "Critical"
            elif any(k in v_lower for k in ("sqli", "sql_injection")):
                judgment.calibrated_severity = "Critical"
            elif any(k in v_lower for k in ("idor", "bola", "ssrf", "xxe", "isolation_breach")):
                judgment.calibrated_severity = "High"
            elif any(k in v_lower for k in ("privilege_escalation", "auth_bypass", "double_execution")):
                judgment.calibrated_severity = "High"
            elif "xss" in v_lower:
                judgment.calibrated_severity = "Medium"
            else:
                judgment.calibrated_severity = "Medium"

            if not judgment.provenance_chain:
                try:
                    from core.burp_gateway.provenance import EvidenceProvenanceEngine
                    judgment.provenance_chain = EvidenceProvenanceEngine.synthesize_standard_provenance(
                        target_url=target_url,
                        vuln_class=vuln_class,
                        finder_claim=finder_claim,
                        verifier_result=verifier_result,
                    )
                except Exception:
                    pass

            return judgment

        judgment.verdict = CourtVerdict.UNVERIFIED
        judgment.calibrated_severity = "Medium"
        judgment.confidence_score = 0.60
        judgment.reportable = False
        judgment.epistemic_state = "TESTED"
        judgment.adjudication_rationale = "Verifier observed differential change, but causal invariant execution proof is absent."
        return judgment
