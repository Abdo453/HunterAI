"""
HunterAI Attack Opportunity & Semantic Parameter Schemas
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class SemanticParameterRole(str, Enum):
    FINANCIAL_VALUE = "FINANCIAL_VALUE"         # price, amount, balance, discount
    IDENTITY_REFERENCE = "IDENTITY_REFERENCE"   # id, user_id, account_id, tenant_id
    ROLE_FLAG = "ROLE_FLAG"                     # role, is_admin, verified, tier
    STATE_TRANSITION = "STATE_TRANSITION"       # status, state, step, action
    REDIRECT_TARGET = "REDIRECT_TARGET"         # redirect, return_url, next, callback
    FILE_PATH = "FILE_PATH"                     # file, path, filename, doc
    QUERY_FILTER = "QUERY_FILTER"               # search, q, filter, order_by


@dataclass
class SemanticParameterProfile:
    """Deep contextual analysis of a parameter beyond its raw string name"""
    parameter_name: str
    semantic_role: SemanticParameterRole
    state_impact: str
    risk_hypotheses: List[str] = field(default_factory=list)


@dataclass
class AttackOpportunity:
    """A concrete, actionable attack vector bound to an endpoint and parameter context"""
    opportunity_id: str
    endpoint: str
    method: str
    vuln_vector: str                           # e.g., 'IDOR', 'MASS_ASSIGNMENT', 'PRICE_TAMPERING'
    target_parameter: Optional[str] = None
    semantic_role: Optional[SemanticParameterRole] = None
    expected_information_gain: float = 0.8     # Information gain metric
    test_priority: str = "HIGH"                # CRITICAL, HIGH, MEDIUM, LOW
    rationale: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "opportunity_id": self.opportunity_id,
            "endpoint": self.endpoint,
            "method": self.method,
            "vuln_vector": self.vuln_vector,
            "target_parameter": self.target_parameter,
            "semantic_role": self.semantic_role.value if self.semantic_role else None,
            "expected_information_gain": self.expected_information_gain,
            "test_priority": self.test_priority,
            "rationale": self.rationale,
        }
