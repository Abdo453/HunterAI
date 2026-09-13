"""
HunterAI Risk Budgeting & Approval Queue
=======================================
Enforces strict operational boundaries:
- Tiered Risk Budget quotas (Passive, Low, Medium, High, Destructive)
- Approval Queue holding state-mutating actions until explicit human operator sign-off
Prevents collateral target degradation and unintended destructive testing.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class RiskTier(str, Enum):
    PASSIVE = "PASSIVE"          # Unlimited
    LOW_RISK = "LOW_RISK"        # Default budget: 1000
    MEDIUM_RISK = "MEDIUM_RISK"  # Default budget: 100
    HIGH_RISK = "HIGH_RISK"      # Default budget: 10 (State-mutating)
    DESTRUCTIVE = "DESTRUCTIVE"  # Default budget: 0 (Hard blocked)


class RiskBudgetExceededError(PermissionError):
    """Raised when an agent attempts action exceeding the allocated risk budget"""
    pass


@dataclass
class PendingApprovalItem:
    approval_id: str = field(default_factory=lambda: f"APV-{uuid.uuid4().hex[:6].upper()}")
    action_id: str = ""
    target: str = ""
    endpoint: str = ""
    method: str = "POST"
    risk_tier: RiskTier = RiskTier.HIGH_RISK
    expected_impact: str = ""
    status: str = "PENDING"  # PENDING, APPROVED, REJECTED
    requested_at: float = field(default_factory=time.time)
    reviewed_at: Optional[float] = None
    reviewer: Optional[str] = None


class RiskBudgetManager:
    """Tracks and enforces limits across risk tiers"""

    def __init__(
        self,
        passive_limit: Optional[int] = None,
        low_limit: int = 1000,
        medium_limit: int = 100,
        high_limit: int = 10,
        destructive_limit: int = 0
    ):
        self.limits: Dict[RiskTier, Optional[int]] = {
            RiskTier.PASSIVE: passive_limit,
            RiskTier.LOW_RISK: low_limit,
            RiskTier.MEDIUM_RISK: medium_limit,
            RiskTier.HIGH_RISK: high_limit,
            RiskTier.DESTRUCTIVE: destructive_limit
        }
        self.consumed: Dict[RiskTier, int] = {tier: 0 for tier in RiskTier}

    def can_execute(self, tier: RiskTier) -> bool:
        limit = self.limits.get(tier)
        if limit is None:
            return True  # Unlimited
        return self.consumed.get(tier, 0) < limit

    def consume_budget(self, tier: RiskTier):
        if not self.can_execute(tier):
            limit = self.limits.get(tier, 0)
            raise RiskBudgetExceededError(
                f"GOVERNANCE CEILING REACHED: Risk budget for '{tier.value}' ({limit} actions) has been exhausted."
            )
        self.consumed[tier] += 1

    def get_budget_status(self) -> Dict[str, Any]:
        return {
            tier.value: {
                "limit": self.limits[tier],
                "consumed": self.consumed[tier],
                "remaining": None if self.limits[tier] is None else max(0, self.limits[tier] - self.consumed[tier])
            }
            for tier in RiskTier
        }


class ApprovalQueue:
    """Holds state-mutating high-risk actions pending human confirmation"""

    def __init__(self):
        self.queue: Dict[str, PendingApprovalItem] = {}

    def enqueue(
        self,
        action_id: str,
        target: str,
        endpoint: str,
        method: str,
        risk_tier: RiskTier,
        expected_impact: str
    ) -> PendingApprovalItem:
        item = PendingApprovalItem(
            action_id=action_id,
            target=target,
            endpoint=endpoint,
            method=method,
            risk_tier=risk_tier,
            expected_impact=expected_impact
        )
        self.queue[item.approval_id] = item
        return item

    def approve(self, approval_id: str, operator_name: str = "security_lead") -> bool:
        item = self.queue.get(approval_id)
        if item and item.status == "PENDING":
            item.status = "APPROVED"
            item.reviewed_at = time.time()
            item.reviewer = operator_name
            return True
        return False

    def reject(self, approval_id: str, operator_name: str = "security_lead") -> bool:
        item = self.queue.get(approval_id)
        if item and item.status == "PENDING":
            item.status = "REJECTED"
            item.reviewed_at = time.time()
            item.reviewer = operator_name
            return True
        return False

    def get_pending_items(self) -> List[Dict[str, Any]]:
        return [asdict(item) for item in self.queue.values() if item.status == "PENDING"]
