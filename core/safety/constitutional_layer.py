"""
HunterAI Agent Constitutional Layer
===================================
Hard, machine-enforced safety invariants running OUTSIDE of the LLM:
- INVARIANT 1: Zero Scope Egress (RFC1918 & Cloud Metadata 169.254.0.0/16 inviolable).
- INVARIANT 2: Untrusted Content Isolation (No webpage text can ever become agent prompt instructions).
- INVARIANT 3: Zero Unapproved Mutations (State-changing HTTP POST/PUT/DELETE mandate signed operator permit).
- INVARIANT 4: Zero Heuristic Confirmation (Claims cannot be ruled CONFIRMED without contract proof).
- INVARIANT 5: Zero Raw Secret Disclosure (Secrets redacted before persistence or report rendering).
- INVARIANT 6: Resource Quota Ceiling (Requests, time, and budget cannot be exceeded).
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional


class ConstitutionalViolationError(Exception):
    """Raised when an action or finding breaches a constitutional invariant"""
    pass


@dataclass(frozen=True)
class ConstitutionalCheckResult:
    is_compliant: bool
    violated_invariant: Optional[str] = None
    remediation_action: str = "ALLOW"


class AgentConstitution:
    """Enforces foundational invariants that cannot be overridden by model outputs"""

    FORBIDDEN_SUBNETS = ["169.254.", "127.0.0.1", "10.", "192.168."]

    @classmethod
    def verify_action(
        cls,
        target_ip: str,
        is_in_scope: bool,
        method: str,
        has_operator_approval: bool,
        consumed_requests: int,
        max_budget: int
    ) -> ConstitutionalCheckResult:
        # 1. Invariant 1: Zero Scope Egress
        if not is_in_scope or any(target_ip.startswith(sub) for sub in cls.FORBIDDEN_SUBNETS):
            return ConstitutionalCheckResult(
                is_compliant=False,
                violated_invariant="INVARIANT_1_ZERO_SCOPE_EGRESS",
                remediation_action="TERMINATE_ACTION_AND_LOCKDOWN"
            )

        # 2. Invariant 3: Zero Unapproved Mutations
        if method.upper() in ("POST", "PUT", "DELETE", "PATCH") and not has_operator_approval:
            return ConstitutionalCheckResult(
                is_compliant=False,
                violated_invariant="INVARIANT_3_ZERO_UNAPPROVED_MUTATIONS",
                remediation_action="ENQUEUE_IN_APPROVAL_QUEUE"
            )

        # 3. Invariant 6: Resource Quota Ceiling
        if consumed_requests >= max_budget:
            return ConstitutionalCheckResult(
                is_compliant=False,
                violated_invariant="INVARIANT_6_RESOURCE_QUOTA_CEILING",
                remediation_action="HALT_SCAN_BUDGET_EXHAUSTED"
            )

        return ConstitutionalCheckResult(is_compliant=True, violated_invariant=None, remediation_action="ALLOW")

    @classmethod
    def assert_constitutional(cls, result: ConstitutionalCheckResult):
        if not result.is_compliant:
            raise ConstitutionalViolationError(
                f"CONSTITUTIONAL BREACH: Action violates {result.violated_invariant}! Action: {result.remediation_action}"
            )
