"""
HunterAI Identity Graph & Authorization Schemas
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class AuthZAnomalyType(str, Enum):
    BOLA_HORIZONTAL_ACCESS = "BOLA_HORIZONTAL_ACCESS"
    BFLA_VERTICAL_PRIVILEGE_ESCALATION = "BFLA_VERTICAL_PRIVILEGE_ESCALATION"
    UNAUTHENTICATED_INFORMATION_LEAK = "UNAUTHENTICATED_INFORMATION_LEAK"
    CROSS_TENANT_BREACH = "CROSS_TENANT_BREACH"
    ROLE_CONFUSION = "ROLE_CONFUSION"


@dataclass
class IdentityContext:
    """Represents an active security identity with sessions, tokens, and tenant scoping"""
    identity_id: str                          # e.g., 'user_a', 'user_b', 'admin', 'anonymous'
    tenant_id: str = "tenant_1"
    roles: List[str] = field(default_factory=lambda: ["user"])
    tokens: Dict[str, str] = field(default_factory=dict)     # Bearer, CSRF, APIKey
    cookies: Dict[str, str] = field(default_factory=dict)    # session_id, remember_me
    headers: Dict[str, str] = field(default_factory=dict)    # X-Tenant-ID, custom headers
    mfa_verified: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_anonymous(self) -> bool:
        return self.identity_id.lower() == "anonymous" or not (self.tokens or self.cookies)

    def is_admin(self) -> bool:
        return "admin" in [r.lower() for r in self.roles]


@dataclass
class AuthZDifferentialResult:
    """Outcome of replaying a transaction across different identity contexts"""
    endpoint: str
    method: str
    target_object_id: str
    base_identity: str
    tested_identity: str
    is_anomaly: bool
    anomaly_type: Optional[AuthZAnomalyType] = None
    baseline_status: int = 200
    tested_status: int = 200
    baseline_content_length: int = 0
    tested_content_length: int = 0
    sensitive_data_leaked: bool = False
    evidence_rationale: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "method": self.method,
            "target_object_id": self.target_object_id,
            "base_identity": self.base_identity,
            "tested_identity": self.tested_identity,
            "is_anomaly": self.is_anomaly,
            "anomaly_type": self.anomaly_type.value if self.anomaly_type else None,
            "baseline_status": self.baseline_status,
            "tested_status": self.tested_status,
            "sensitive_data_leaked": self.sensitive_data_leaked,
            "evidence_rationale": self.evidence_rationale,
        }
