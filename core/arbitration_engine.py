"""
Evidence Arbitration Layer
==========================
Arbitrates between conflicting agents and models (e.g. xploiter says Real, Qwen says False),
and applies deterministic verification rules to prevent speculative LLMs from promoting
unproven reflections into Critical vulnerabilities.
"""
import logging
from typing import Dict, Any, List, Optional
from core.evidence_contract import EvidenceContract, LifecycleStage

logger = logging.getLogger("arbitration_engine")

class EvidenceArbitrationEngine:
    """
    Arbitrates evidence and resolves model contradictions.
    Rule: Deterministic Evidence > LLM Speculation.
    """

    @classmethod
    def arbitrate(
        cls,
        tool_name: str,
        target_url: str,
        param_name: str,
        vuln_type: str,
        tool_output: Dict[str, Any],
        xploiter_decision: Optional[Dict[str, Any]] = None,
        qwen_decision: Optional[Dict[str, Any]] = None,
        is_in_scope: bool = True
    ) -> EvidenceContract:
        contract = EvidenceContract(
            target=target_url,
            parameter=param_name,
            vulnerability=vuln_type,
            scope_valid=is_in_scope
        )

        if not is_in_scope:
            contract.stage = LifecycleStage.REJECTED
            contract.negative_evidence.append("Out of scope target discarded by Scope Guard.")
            contract.reportable = False
            return contract

        # 1. Inspect deterministic proof in tool output
        has_arithmetic_proof = bool(tool_output.get("reproduced") and "72" in str(tool_output.get("evidence", "")))
        has_extracted_data = bool(tool_output.get("extracted_data") or tool_output.get("objective_met"))
        has_auth_bypass = bool(tool_output.get("type") == "unauthenticated_object_access" and tool_output.get("verified"))
        has_executable_xss = bool(tool_output.get("vuln_type") == "xss" and tool_output.get("verified") and "<" in str(tool_output.get("payload_used", "")))

        # 2. Check for negative evidence / contradictions
        logs = tool_output.get("logs", [])
        reflection_detected = any("REFLECTION DETECTED" in str(l) or "Reflection != Execution" in str(l) for l in logs)
        waf_detected = any("WAF" in str(l) or "Cloudflare" in str(l) or "403" in str(l) for l in logs)
        failed_count_cols = any("COUNT_COLS" in str(l) and "failed" in str(l).lower() for l in logs)

        if reflection_detected:
            contract.negative_evidence.append("Literal input reflection detected without command execution proof.")
        if waf_detected:
            contract.negative_evidence.append("Response indicates WAF challenge or blocking page.")
        if failed_count_cols:
            contract.negative_evidence.append("SQL column count determination failed; query not injectable.")

        # 3. Model Arbitration (xploiter vs Qwen)
        x_real = xploiter_decision.get("is_real_vuln", False) if xploiter_decision else None
        q_real = qwen_decision.get("is_real_vuln", False) if qwen_decision else None

        # If models disagree, look at deterministic proof
        if x_real is True and q_real is False:
            logger.info(f"[ARBITRATION] Conflict: xploiter=True, Qwen=False on {param_name}. Checking deterministic proof...")
            if not (has_arithmetic_proof or has_extracted_data or has_auth_bypass or has_executable_xss):
                contract.stage = LifecycleStage.UNVERIFIED
                contract.negative_evidence.append("Model disagreement (xploiter vs Qwen) without deterministic execution proof.")
                contract.arbitration_verdict = "REJECTED_DUE_TO_CONTRADICTION"
                contract.reportable = False
                return contract

        # 4. Final Verdict Resolution
        is_verified = tool_output.get("verified", False) or tool_output.get("objective_met", False)

        if is_verified and len(contract.negative_evidence) == 0:
            contract.stage = LifecycleStage.CONFIRMED
            contract.confidence = float(tool_output.get("confidence", 0.95))
            contract.independent_verification = True
            contract.reproduction = {"confirmed": True, "payload": tool_output.get("payload_used", "")}
            contract.evidence.append({"type": "deterministic_proof", "data": tool_output.get("evidence", "")})
            contract.arbitration_verdict = "VERIFIED_CONFIRMED"
        else:
            if reflection_detected or waf_detected:
                contract.stage = LifecycleStage.REJECTED
                contract.confidence = 0.10
                contract.arbitration_verdict = "REJECTED_REFLECTION_OR_WAF"
            else:
                contract.stage = LifecycleStage.UNVERIFIED
                contract.confidence = 0.40
                contract.arbitration_verdict = "UNVERIFIED_SIGNAL_ONLY"

        contract.evaluate_reportability()
        return contract
