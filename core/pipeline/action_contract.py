"""
HunterAI Action Contract (Planner -> Policy Engine -> Executor)
==============================================================
The Planner is strictly forbidden from constructing or dispatching raw HTTP requests.
It must emit a structured ProposedAction object. The Policy Engine inspects the action
and issues an authorized ExecutionPermit to the Executor.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ActionRiskLevel(str, Enum):
    PASSIVE = "PASSIVE"        # Zero side-effects (GET discovery)
    LOW = "LOW"                # Parameter probe with deterministic nonce
    MEDIUM = "MEDIUM"          # Arithmetic SQLi / SSTI probe
    HIGH = "HIGH"              # State-mutating POST / SSRF / Auth bypass
    CRITICAL = "CRITICAL"      # File upload / RCE verification


@dataclass
class ProposedAction:
    action_id: str = field(default_factory=lambda: f"ACT-{uuid.uuid4().hex[:8].upper()}")
    target: str = ""
    endpoint: str = ""
    method: str = "GET"
    parameter: str = ""
    mutation_type: str = "none"  # "arithmetic_nonce", "context_breakout", "auth_token"
    risk_level: ActionRiskLevel = ActionRiskLevel.LOW
    reason: str = ""
    expected_evidence: str = ""
    plugin_id: str = "generic"
    payload_template: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["risk_level"] = self.risk_level.value
        return d


@dataclass
class ExecutionPermit:
    permit_id: str = field(default_factory=lambda: f"PMT-{uuid.uuid4().hex[:8].upper()}")
    action_id: str = ""
    is_authorized: bool = False
    policy_name: str = "scope_v1"
    denial_reason: Optional[str] = None
    rate_limit_delay_sec: float = 0.0
    requires_human_approval: bool = False
    human_approved: bool = False
    granted_at: float = field(default_factory=time.time)

    @classmethod
    def grant(cls, action_id: str, policy_name: str = "scope_v1", delay: float = 0.0) -> ExecutionPermit:
        return cls(action_id=action_id, is_authorized=True, policy_name=policy_name, rate_limit_delay_sec=delay)

    @classmethod
    def deny(cls, action_id: str, reason: str, policy_name: str = "scope_v1") -> ExecutionPermit:
        return cls(action_id=action_id, is_authorized=False, policy_name=policy_name, denial_reason=reason)
