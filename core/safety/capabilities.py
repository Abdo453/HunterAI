"""
HunterAI Capability-Based Access Control
========================================
Implements the Principle of Least Privilege for autonomous agents.
Subagents and plugins receive minimal capability tokens.
An agent without CAP_MUTATE_STATE cannot propose state-altering payloads,
and an agent without CAP_SIGN_REPORT cannot access cryptographic keys.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class AgentCapability(str, Enum):
    CAP_READ_DISCOVERY = "CAP_READ_DISCOVERY"    # Read HTML, JS, DNS, sitemaps
    CAP_ANALYZE_EVIDENCE = "CAP_ANALYZE_EVIDENCE" # Parse AST, diffs, baselines
    CAP_PROPOSE_TEST = "CAP_PROPOSE_TEST"        # Propose low/medium risk probes
    CAP_MUTATE_STATE = "CAP_MUTATE_STATE"        # Propose high/critical mutations
    CAP_COMMIT_FINDING = "CAP_COMMIT_FINDING"    # Submit finding to Evidence Court
    CAP_SIGN_REPORT = "CAP_SIGN_REPORT"          # Access cryptographic audit keys


class UnauthorizedCapabilityError(PermissionError):
    """Raised when an agent attempts an action exceeding its assigned capabilities"""
    pass


@dataclass
class CapabilityToken:
    token_id: str = field(default_factory=lambda: f"CAP-{uuid.uuid4().hex[:8].upper()}")
    agent_role: str = "generic_agent"
    capabilities: Set[AgentCapability] = field(default_factory=set)
    issued_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + 3600)

    def has_capability(self, cap: AgentCapability) -> bool:
        return cap in self.capabilities and time.time() <= self.expires_at


class CapabilityGate:
    """Enforces capability checks across agent pipeline operations"""

    @classmethod
    def create_token(
        cls,
        agent_role: str,
        capabilities: List[AgentCapability],
        ttl_seconds: float = 3600
    ) -> CapabilityToken:
        return CapabilityToken(
            agent_role=agent_role,
            capabilities=set(capabilities),
            issued_at=time.time(),
            expires_at=time.time() + ttl_seconds
        )

    @classmethod
    def enforce(cls, token: CapabilityToken, required_cap: AgentCapability):
        if not token.has_capability(required_cap):
            raise UnauthorizedCapabilityError(
                f"SECURITY POLICY VIOLATION: Agent '{token.agent_role}' attempted operation "
                f"requiring '{required_cap.value}' without valid capability token."
            )
