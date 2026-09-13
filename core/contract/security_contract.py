"""
HunterAI Security Finding Contract Engine
=========================================
Establishes inviolable, formal contracts defining the exact mathematical & forensic
evidence required before any vulnerability claim can be ruled "CONFIRMED".

Guarantees:
- Zero LLM heuristic confirmation: A finding cannot be confirmed via model opinion alone.
- Mandatory tripartite evidence items (Baseline, Negative Control, Active Test).
- Multi-run independent reproduction threshold.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class RequirementStatus(str, Enum):
    FULFILLED = "FULFILLED"
    UNFULFILLED = "UNFULFILLED"
    WAIVED_BY_POLICY = "WAIVED_BY_POLICY"
    FAILED_VALIDATION = "FAILED_VALIDATION"


@dataclass
class EvidenceRequirement:
    requirement_id: str
    name: str
    description: str
    validator_key: str
    is_mandatory: bool = True
    status: RequirementStatus = RequirementStatus.UNFULFILLED
    failure_reason: str = ""

    def evaluate(self, evidence_payload: Dict[str, Any]) -> RequirementStatus:
        if self.validator_key not in evidence_payload:
            self.status = RequirementStatus.UNFULFILLED
            self.failure_reason = f"Missing mandatory evidence item '{self.validator_key}'."
            return self.status

        val = evidence_payload[self.validator_key]
        if not val or val is False:
            self.status = RequirementStatus.FAILED_VALIDATION
            self.failure_reason = f"Evidence item '{self.validator_key}' evaluated to falsy/invalid value."
            return self.status

        self.status = RequirementStatus.FULFILLED
        self.failure_reason = ""
        return self.status


@dataclass
class ContractEvaluationResult:
    contract_id: str
    vulnerability_family: str
    verdict: str  # "CONFIRMED", "REFUTED", "INSUFFICIENT_EVIDENCE"
    is_satisfied: bool
    reproduction_count: int
    required_reproductions: int
    fulfilled_requirements: List[str] = field(default_factory=list)
    unfulfilled_requirements: List[str] = field(default_factory=list)
    contract_notes: str = ""


@dataclass
class SecurityFindingContract:
    contract_id: str
    vulnerability_family: str
    cwe_id: str
    requirements: List[EvidenceRequirement]
    min_reproductions: int = 2
    disallow_heuristic_confirmation: bool = True

    def evaluate(
        self,
        evidence_payload: Dict[str, Any],
        reproduction_count: int = 0
    ) -> ContractEvaluationResult:
        fulfilled = []
        unfulfilled = []

        for req in self.requirements:
            status = req.evaluate(evidence_payload)
            if status == RequirementStatus.FULFILLED:
                fulfilled.append(req.name)
            elif req.is_mandatory:
                unfulfilled.append(f"{req.name}: {req.failure_reason}")

        reproductions_satisfied = reproduction_count >= self.min_reproductions
        if not reproductions_satisfied:
            unfulfilled.append(
                f"Reproduction threshold not met: {reproduction_count}/{self.min_reproductions} verified runs."
            )

        is_satisfied = (len(unfulfilled) == 0) and reproductions_satisfied
        verdict = "CONFIRMED" if is_satisfied else "INSUFFICIENT_EVIDENCE"

        notes = (
            "All contractual evidence items satisfied deterministically."
            if is_satisfied
            else f"Contract breach: {len(unfulfilled)} unfulfilled mandatory conditions."
        )

        return ContractEvaluationResult(
            contract_id=self.contract_id,
            vulnerability_family=self.vulnerability_family,
            verdict=verdict,
            is_satisfied=is_satisfied,
            reproduction_count=reproduction_count,
            required_reproductions=self.min_reproductions,
            fulfilled_requirements=fulfilled,
            unfulfilled_requirements=unfulfilled,
            contract_notes=notes,
        )


class SecurityContractEngine:
    """Registry and evaluator for finding security contracts"""

    _CONTRACTS: Dict[str, SecurityFindingContract] = {
        "BOLA": SecurityFindingContract(
            contract_id="CTR-BOLA-V1",
            vulnerability_family="Broken Object Level Authorization (BOLA/IDOR)",
            cwe_id="CWE-639",
            requirements=[
                EvidenceRequirement("REQ-TENANT-A", "Tenant A Object Access Proof", "Successful access by lawful owner", "tenant_a_access"),
                EvidenceRequirement("REQ-TENANT-B", "Tenant B Cross-Tenant Token Replay", "Replay of Tenant B token against Tenant A object", "tenant_b_replay"),
                EvidenceRequirement("REQ-DIFF-BODY", "Differential Body Payload Match", "Identity B sees sensitive data without 403 Forbidden", "differential_data_matched"),
                EvidenceRequirement("REQ-HARMFREE-CONTROL", "Harmless Negative Control Rejection", "Invalid token receives strict 401/403 rejection", "invalid_token_rejected"),
            ],
            min_reproductions=2
        ),
        "SQLI": SecurityFindingContract(
            contract_id="CTR-SQLI-V1",
            vulnerability_family="SQL Injection",
            cwe_id="CWE-89",
            requirements=[
                EvidenceRequirement("REQ-BASELINE-STABLE", "Stable Baseline Response", "Baseline probe returns consistent 200 OK or expected view", "baseline_stable"),
                EvidenceRequirement("REQ-ARITHMETIC-NONCE", "Arithmetic Computational Nonce", "Calculated numeric evaluation e.g. 1+(53-52)=2 or $((41+1))=42 verified in response", "computational_nonce_proven"),
                EvidenceRequirement("REQ-SYNTAX-CONTROL", "Differential Syntax Breakage", "Unbalanced quotes or break sequences provoke deterministic failure", "syntax_differential_proven"),
                EvidenceRequirement("REQ-NEGATIVE-CONTROL", "Harmless Control Preserved", "Harmless alphanumeric probe leaves response unaltered", "negative_control_passed"),
            ],
            min_reproductions=2
        ),
        "CMDI": SecurityFindingContract(
            contract_id="CTR-CMDI-V1",
            vulnerability_family="Command Injection",
            cwe_id="CWE-78",
            requirements=[
                EvidenceRequirement("REQ-BASELINE-STABLE", "Stable Baseline", "Diagnostic utility functions normally on valid input", "baseline_stable"),
                EvidenceRequirement("REQ-NONCE-EXEC", "Deterministic Arithmetic Nonce Execution", "Arbitrary arithmetic expression $((53+19))->72 calculated by shell and reflected", "arithmetic_nonce_reflected"),
                EvidenceRequirement("REQ-NEGATIVE-CONTROL", "Benign Metacharacter Rejection", "Isolated benign character does not trigger command execution", "negative_control_passed"),
            ],
            min_reproductions=2
        ),
        "SSRF": SecurityFindingContract(
            contract_id="CTR-SSRF-V1",
            vulnerability_family="Server-Side Request Forgery",
            cwe_id="CWE-918",
            requirements=[
                EvidenceRequirement("REQ-DNS-INTERACTION", "Out-of-Band Callback / Nonce Verification", "Target server triggers HTTP/DNS interaction with proof nonce token", "oob_nonce_verified"),
                EvidenceRequirement("REQ-NEGATIVE-CONTROL", "Localhost Filter Evaluation", "Strict verification that external callback occurred without RFC1918 egress", "loopback_egress_prevented"),
            ],
            min_reproductions=2
        ),
    }

    @classmethod
    def get_contract(cls, vuln_family: str) -> Optional[SecurityFindingContract]:
        vuln_upper = vuln_family.upper()
        for k, contract in cls._CONTRACTS.items():
            if k in vuln_upper or vuln_upper in k:
                return contract
        return None

    @classmethod
    def evaluate_claim(
        cls,
        vuln_family: str,
        evidence_payload: Dict[str, Any],
        reproduction_count: int = 0
    ) -> ContractEvaluationResult:
        contract = cls.get_contract(vuln_family)
        if not contract:
            # Generic fallback contract requiring minimum 2 reproductions and baseline differential
            generic_contract = SecurityFindingContract(
                contract_id="CTR-GENERIC-V1",
                vulnerability_family=vuln_family,
                cwe_id="CWE-Unknown",
                requirements=[
                    EvidenceRequirement("REQ-DIFF-PROOF", "Deterministic Differential Proof", "Active probe differs measurably from baseline", "differential_proven"),
                    EvidenceRequirement("REQ-CONTROL-STABLE", "Negative Control Invariance", "Negative control does not trigger flaw", "negative_control_passed"),
                ],
                min_reproductions=2
            )
            return generic_contract.evaluate(evidence_payload, reproduction_count)

        return contract.evaluate(evidence_payload, reproduction_count)
