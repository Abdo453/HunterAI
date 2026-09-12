"""
Evidence Court (محكمة الأدلة)
=============================
Multi-party adjudication engine ensuring no single agent, tool, or LLM can
declare a finding as CONFIRMED without independent, deterministic verification.

Pipeline:
Finder Agent -> Evidence Collector -> Verifier Agent -> Independent Re-check -> Evidence Court

Verdicts:
- CONFIRMED: Deterministic proof confirmed with independent verification.
- UNVERIFIED: Plausible signal or hypothesis exists, but proof not yet obtained.
- FALSE_POSITIVE: Proven to be reflection, dynamic page shift, or normal navigation.
- DISPROVED: Negative control or independent re-check conclusively refutes exploitability.
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
from typing import Any, Dict, List, Optional

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
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["verdict"] = self.verdict.value
        return d


class EvidenceCourt:
    """The authoritative Evidence Court adjudicating finding authenticity"""

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
        provenance_chain: Optional[List[Dict[str, Any]]] = None
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

        # 3. Independent Verification Requirement
        # Rule: No single agent can declare CONFIRMED
        if not verifier_result or not verifier_result.get("reproduced"):
            # Check if reflection was detected
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

        # 4. Proof of Execution Gate
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
            elif any(k in v_lower for k in ("idor", "bola", "ssrf", "xxe")):
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

        # Fallback: verifier said reproduced, but lacked deterministic proof
        judgment.verdict = CourtVerdict.UNVERIFIED
        judgment.calibrated_severity = "Medium"
        judgment.confidence_score = 0.60
        judgment.reportable = False
        judgment.adjudication_rationale = "Verifier observed differential change, but deterministic execution proof is absent."
        return judgment