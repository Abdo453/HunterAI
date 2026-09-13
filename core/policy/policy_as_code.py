"""
HunterAI Policy-as-Code & Versioning
====================================
Every security action and finding is explicitly governed by and bound to an
immutable, versioned Policy document (e.g. Policy v1.4).

Guarantees:
- Findings explicitly preserve the Policy Version under which they were confirmed.
- Audit trail: If enterprise policy changes from v1.0 to v2.0, past results remain forensically accountable.
- Environment-aware gating (LAB vs STAGING vs PRODUCTION).
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class EnvironmentTier(str, Enum):
    LAB = "LAB"
    STAGING = "STAGING"
    PRODUCTION = "PRODUCTION"


class PolicyDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"


@dataclass(frozen=True)
class PolicyReceipt:
    receipt_id: str
    policy_version: str
    environment: EnvironmentTier
    target: str
    action_type: str
    decision: PolicyDecision
    justification: str
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "policy_version": self.policy_version,
            "environment": self.environment.value,
            "target": self.target,
            "action_type": self.action_type,
            "decision": self.decision.value,
            "justification": self.justification,
            "timestamp": self.timestamp,
        }


class PolicyAsCodeEngine:
    """Evaluates proposed actions against versioned, environment-aware rulesets"""

    def __init__(self, policy_version: str = "v1.4", environment: EnvironmentTier = EnvironmentTier.STAGING):
        self.policy_version = policy_version
        self.environment = environment
        self._receipt_log: Dict[str, PolicyReceipt] = {}
        self._counter = 0

    def evaluate_action(
        self,
        target: str,
        action_type: str,
        is_state_mutating: bool,
        is_in_scope: bool
    ) -> PolicyReceipt:
        self._counter += 1
        receipt_id = f"POL-{self.policy_version.replace('.', '')}-{self._counter:04d}"

        # 1. Out of scope is always DENIED across all environments
        if not is_in_scope:
            receipt = PolicyReceipt(
                receipt_id=receipt_id,
                policy_version=self.policy_version,
                environment=self.environment,
                target=target,
                action_type=action_type,
                decision=PolicyDecision.DENY,
                justification=f"Target '{target}' violates authorized scope boundary."
            )
            self._receipt_log[receipt_id] = receipt
            return receipt

        # 2. Production Environment: Mutating actions DENIED or require strict human sign-off
        if self.environment == EnvironmentTier.PRODUCTION:
            if is_state_mutating:
                receipt = PolicyReceipt(
                    receipt_id=receipt_id,
                    policy_version=self.policy_version,
                    environment=self.environment,
                    target=target,
                    action_type=action_type,
                    decision=PolicyDecision.APPROVAL_REQUIRED,
                    justification="Production environment: state-mutating requests mandate human operator approval."
                )
            else:
                receipt = PolicyReceipt(
                    receipt_id=receipt_id,
                    policy_version=self.policy_version,
                    environment=self.environment,
                    target=target,
                    action_type=action_type,
                    decision=PolicyDecision.ALLOW,
                    justification="Production environment: passive read probe authorized."
                )
            self._receipt_log[receipt_id] = receipt
            return receipt

        # 3. Lab Environment: Permissive execution within scope
        if self.environment == EnvironmentTier.LAB:
            receipt = PolicyReceipt(
                receipt_id=receipt_id,
                policy_version=self.policy_version,
                environment=self.environment,
                target=target,
                action_type=action_type,
                decision=PolicyDecision.ALLOW,
                justification="Lab sandbox environment: active testing authorized."
            )
            self._receipt_log[receipt_id] = receipt
            return receipt

        # 4. Staging Environment
        if is_state_mutating:
            receipt = PolicyReceipt(
                receipt_id=receipt_id,
                policy_version=self.policy_version,
                environment=self.environment,
                target=target,
                action_type=action_type,
                decision=PolicyDecision.APPROVAL_REQUIRED,
                justification="Staging environment: state mutation held in ApprovalQueue."
            )
        else:
            receipt = PolicyReceipt(
                receipt_id=receipt_id,
                policy_version=self.policy_version,
                environment=self.environment,
                target=target,
                action_type=action_type,
                decision=PolicyDecision.ALLOW,
                justification="Staging environment: read probe authorized."
            )

        self._receipt_log[receipt_id] = receipt
        return receipt

    def get_receipt(self, receipt_id: str) -> Optional[PolicyReceipt]:
        return self._receipt_log.get(receipt_id)
