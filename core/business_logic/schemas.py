"""
HunterAI Business Logic Reasoning Schemas
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional


class BusinessResourceState(str, Enum):
    INITIAL = "INITIAL"
    CREATED = "CREATED"
    PENDING_PAYMENT = "PENDING_PAYMENT"
    PAID = "PAID"
    FULFILLED = "FULFILLED"
    REFUNDED = "REFUNDED"
    CANCELLED = "CANCELLED"
    EXPIRED = "EXPIRED"


class BusinessActionType(str, Enum):
    CREATE_ORDER = "CREATE_ORDER"
    APPLY_COUPON = "APPLY_COUPON"
    SUBMIT_PAYMENT = "SUBMIT_PAYMENT"
    REQUEST_REFUND = "REQUEST_REFUND"
    DOWNLOAD_ASSET = "DOWNLOAD_ASSET"
    CHANGE_QUANTITY = "CHANGE_QUANTITY"
    CANCEL_ORDER = "CANCEL_ORDER"
    ELEVATE_ROLE = "ELEVATE_ROLE"


@dataclass
class BusinessInvariant:
    """Formal business rule that must NEVER be violated in a compliant application"""
    invariant_id: str
    name: str
    description: str
    target_resource: str
    severity: str = "HIGH"


@dataclass
class BusinessLogicViolationReport:
    """Formal finding emitted when a state mutation breaks a business invariant"""
    finding_id: str
    invariant_id: str
    invariant_name: str
    violating_action: str
    initial_state: str
    resulting_state: str
    payload_mutation: Dict[str, Any]
    security_impact: str
    evidence_proof: str
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "invariant_id": self.invariant_id,
            "invariant_name": self.invariant_name,
            "violating_action": self.violating_action,
            "initial_state": self.initial_state,
            "resulting_state": self.resulting_state,
            "payload_mutation": self.payload_mutation,
            "security_impact": self.security_impact,
            "evidence_proof": self.evidence_proof,
        }
