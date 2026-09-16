"""
Evidence Court (محكمة الأدلة) - V27.0 Causal Verification Engine
================================================================
Multi-party adjudication engine ensuring no single agent, tool, or LLM can
declare a finding as CONFIRMED without independent, deterministic verification
and causal invariant proof.

V27.0 CAUSALITY GATE & TRIAD VERIFICATION:
- Baseline (B) ∧ Control (C) ∧ Experiment (E)
- Strictly forbids CONFIRMED verdict if based merely on status == 200, length delta,
  or string reflection.
- Distinguishes Proof of Execution (PoE) from Proof of Vulnerability (PoV).
- Enforces Negative Observables: disproves hypotheses when application defense
  boundaries (403, 401, error messages) are triggered.

Verdicts:
- CONFIRMED: Deterministic proof confirmed with independent verification and causal triad separation.
- UNVERIFIED: Plausible signal or hypothesis exists, but proof not yet obtained.
- FALSE_POSITIVE: Proven to be reflection, dynamic page shift, or control mutation identical to probe.
- DISPROVED: Negative observable or independent re-check conclusively refutes exploitability.
- INCONCLUSIVE: Verification infrastructure failed, timed out, or incomplete.
- BLOCKED: Target protected or interrupted by WAF/Cloudflare.
- OUT_OF_SCOPE: Target or dependency outside authorized scope.
- DUPLICATE: Finding already confirmed on identical underlying component.
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
class CausalTriad:
    """
    The formal B x C x E verification triad:
      - Baseline (B): Normal unperturbed transaction
      - Control (C): Benign syntactic mutation (no exploit payload)
      - Experiment (E): Active security probe mutation
    """
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
        """
        Determines if the differential effect is genuinely caused by the exploit payload,
        or merely dynamic site jitter / harmless reflection.
        """
        # 1. Check if experiment is identical to control (benign mutation produced identical shift)
        if (
            self.experiment_status == self.control_status
            and abs(self.experiment_length - self.control_length) < 10
            and not self.deterministic_execution_token
        ):
            return False, "Control mutation produced identical shift as experiment (Dynamic noise or neutral input handling)."

        # 2. Check if experiment has zero differentiation from baseline
        if (
            self.experiment_status == self.baseline_status
            and abs(self.experiment_length - self.baseline_length) < 5
            and not self.deterministic_execution_token
        ):
            return False, "Experiment produced zero observable differentiation from baseline."

        # 3. Metamorphic validation passed
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
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["verdict"] = self.verdict.value
        return d


class EvidenceCourt:
    """The authoritative Evidence Court adjudicating finding authenticity with Causal Gates"""

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
        negative_observables: Optional[Dict[str, Any]] = None,
    ) -> CourtJudgment:
        judgment = CourtJudgment(
            target_url=target_url,
            parameter=parameter,
            vuln_class=vuln_class,
            finder_claim=finder_claim,
            verifier_result=verifier_result or {},
            provenance_chain=provenance_chain or []
        )

        # 1. Inviolable Scope Check
        if not is_in_scope:
            judgment.verdict = CourtVerdict.OUT_OF_SCOPE
            judgment.calibrated_severity = "Info"
            judgment.confidence_score = 0.0
            judgment.reportable = False
            judgment.adjudication_rationale = "Target URL is outside authorized scope. Strictly discarded by Scope Firewall."
            judgment.negative_evidence.append("Out of scope target.")
            return judgment

        # 2. WAF Interception Check
        if is_blocked_by_waf or finder_claim.get("waf_blocked") or (verifier_result and verifier_result.get("waf_blocked")):
            judgment.verdict = CourtVerdict.BLOCKED
            judgment.calibrated_severity = "Info"
            judgment.confidence_score = 0.1
            judgment.reportable = False
            judgment.adjudication_rationale = "Probe was intercepted or blocked by Cloudflare/WAF. Does not prove application vulnerability."
            judgment.negative_evidence.append("WAF challenge or block response detected.")
            return judgment

        # 3. Negative Observables Evaluation (Disproof Gate)
        # Check if probe received an explicit negative observable (e.g. 403 Forbidden, 401 Unauthorized)
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
                judgment.adjudication_rationale = (
                    f"Negative observable triggered: Status code {observed_status} matches defense boundary. "
                    "Hypothesis conclusively disproved."
                )
                judgment.negative_evidence.append(f"HTTP Status {observed_status} (Expected defense response)")
                return judgment

            for pat in neg_patterns:
                if pat.lower() in observed_body:
                    judgment.verdict = CourtVerdict.DISPROVED
                    judgment.calibrated_severity = "Info"
                    judgment.confidence_score = 0.0
                    judgment.reportable = False
                    judgment.adjudication_rationale = (
                        f"Negative observable triggered: Pattern '{pat}' found in response. "
                        "Hypothesis conclusively disproved."
                    )
                    judgment.negative_evidence.append(f"Defense pattern: '{pat}'")
                    return judgment

        # 4. Independent Verification Requirement
        if not verifier_result or not verifier_result.get("reproduced"):
            if finder_claim.get("is_reflection") or (verifier_result and verifier_result.get("is_reflection")):
                judgment.verdict = CourtVerdict.FALSE_POSITIVE
                judgment.calibrated_severity = "Info"
                judgment.confidence_score = 0.05
                judgment.reportable = False
                judgment.adjudication_rationale = "Reflection detected without execution proof (Reflection != Execution)."
                judgment.negative_evidence.append("Input echoed literally in DOM or script tag.")
                return judgment

            if not verifier_result:
                judgment.verdict = CourtVerdict.INCONCLUSIVE
                judgment.calibrated_severity = "Low"
                judgment.confidence_score = 0.35
                judgment.reportable = False
                judgment.adjudication_rationale = "Verification infrastructure did not execute or timed out. Inconclusive."
                return judgment

            judgment.verdict = CourtVerdict.UNVERIFIED
            judgment.calibrated_severity = "Low"
            judgment.confidence_score = 0.40
            judgment.reportable = False
            judgment.adjudication_rationale = "Initial signal detected, but independent verifier could not reproduce effect."
            judgment.negative_evidence.append("Independent re-check failed to reproduce.")
            return judgment

        # 5. V27 CAUSALITY GATE: Triad & Delta Validation
        # Strictly rejects byte length divergence or status code alone
        length_delta_only = verifier_result.get("length_delta_only", False)
        status_change_only = verifier_result.get("status_change_only", False)

        if length_delta_only or status_change_only:
            judgment.verdict = CourtVerdict.FALSE_POSITIVE
            judgment.calibrated_severity = "Info"
            judgment.confidence_score = 0.10
            judgment.reportable = False
            judgment.adjudication_rationale = (
                "Causality Gate Violation: Response length delta or HTTP status code change alone "
                "does NOT prove vulnerability. Proof of Execution (PoE) != Proof of Vulnerability (PoV)."
            )
            judgment.negative_evidence.append("Length divergence or status change without semantic execution proof.")
            return judgment

        # Evaluate Causal Triad if provided
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
                judgment.adjudication_rationale = f"Causality Gate Violation: {reason}"
                judgment.negative_evidence.append(reason)
                return judgment

        # 6. Proof of Execution / Proof of Invariant Violation Gate
        has_deterministic_proof = bool(
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
            judgment.confidence_score = float(verifier_result.get("confidence", 0.98))

            # Calibrate severity according to vulnerability class
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
                        verifier_result=verifier_result
                    )
                except Exception:
                    pass

            return judgment

        # Fallback: verifier reproduced change, but lacked causal proof
        judgment.verdict = CourtVerdict.UNVERIFIED
        judgment.calibrated_severity = "Medium"
        judgment.confidence_score = 0.60
        judgment.reportable = False
        judgment.adjudication_rationale = "Verifier observed differential change, but deterministic execution proof is absent."
        return judgment

    @classmethod
    def adjudicate_causal_contract(
        cls,
        contract: Any,
        execution_record: Any,
        causal_triad: Optional[Union[Dict[str, Any], CausalTriad]] = None,
    ) -> CourtJudgment:
        """
        High-level entrypoint directly adjudicating an ExperimentContract and ExperimentExecutionRecord.
        """
        target_url = getattr(contract, "target_endpoint", "")
        vuln_class = getattr(contract, "category", "BUSINESS_LOGIC")
        neg_observables = getattr(contract, "negative_observables", {})

        resp = getattr(execution_record, "response", None)
        status_code = getattr(resp, "status_code", 200) if resp else 200
        resp_body = getattr(resp, "body", "") if resp else ""
        diff = getattr(execution_record, "response_diff", {})

        finder_claim = {
            "hypothesis_id": getattr(contract, "hypothesis_id", ""),
            "category": vuln_class,
        }

        # Check if response matches negative observables
        is_negative = False
        neg_statuses = neg_observables.get("status_codes", [])
        if status_code in neg_statuses:
            is_negative = True

        verifier_result = {
            "reproduced": not is_negative and (status_code in range(200, 300)),
            "status_code": status_code,
            "response_body": resp_body,
            "negative_observables": neg_observables,
            "length_delta_only": bool(diff and not any(k in diff for k in ("unauthorized_data", "execution_proof"))),
            "auth_bypass_confirmed": getattr(execution_record, "auth_bypass_confirmed", False),
            "deterministic_proof": getattr(execution_record, "deterministic_proof", None),
        }

        return cls.adjudicate(
            target_url=target_url,
            parameter="",
            vuln_class=vuln_class,
            finder_claim=finder_claim,
            verifier_result=verifier_result,
            is_in_scope=True,
            causal_triad=causal_triad,
            negative_observables=neg_observables,
        )
