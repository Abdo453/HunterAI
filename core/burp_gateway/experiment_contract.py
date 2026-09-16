"""
HunterAI Burp Control & Sensor Layer (BCSL) — Experiment Execution Contract
===========================================================================
Defines the formal epistemic contract between HunterAI Brain and Burp Suite:
- The LLM / Agent NEVER calls Burp APIs directly
- The Agent formulates a structured ExperimentContract
- BCSL validates Scope, Policy, and Safety prior to execution
- Burp executes the experiment through Proxy/Repeater
- BCSL computes differential, captures state before/after, and returns an
  immutable ExperimentExecutionRecord with complete 7-stage provenance.
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from core.burp_gateway.correlation import BurpCorrelationContext
from core.burp_gateway.traffic_normalizer import CanonicalRequest, CanonicalResponse


@dataclass
class StateSnapshot:
    """State of the target session or data resource before/after experiment."""
    observed_cookies: Dict[str, str] = field(default_factory=dict)
    csrf_token: Optional[str] = None
    bearer_token_fingerprint: Optional[str] = None
    account_balance: Optional[float] = None
    workflow_step: Optional[str] = None
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ExperimentContract:
    """
    Formal Experiment Request from HunterAI Brain to Burp Suite.
    """
    hypothesis_id: str
    source_request_id: str
    identity_context: str = "ANONYMOUS"  # e.g., 'User A', 'User B', 'Admin'
    target_endpoint: str = ""
    mutation_plan: Dict[str, Any] = field(default_factory=dict)
    expected_observation: str = ""
    success_conditions: Dict[str, Any] = field(default_factory=dict)
    scope_requirements: List[str] = field(default_factory=list)
    safety_policy: Dict[str, Any] = field(default_factory=dict)
    correlation_id: str = field(default_factory=lambda: f"corr_{uuid.uuid4().hex[:8]}")
    created_at: float = field(default_factory=time.time)
    experiment_id: Optional[str] = None
    http_method: str = "GET"
    risk_tier: str = "LOW_RISK"
    state_precondition: Optional[str] = None
    expected_invariants: List[str] = field(default_factory=list)
    negative_observables: Dict[str, Any] = field(default_factory=dict)
    risk_budget: float = 1.0
    category: str = "SECURITY_EXPERIMENT"
    candidate_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ExperimentContract:
        valid_keys = {
            "hypothesis_id", "source_request_id", "identity_context",
            "target_endpoint", "mutation_plan", "expected_observation",
            "success_conditions", "scope_requirements", "safety_policy",
            "correlation_id", "created_at", "experiment_id", "http_method", "risk_tier",
            "state_precondition", "expected_invariants", "negative_observables",
            "risk_budget", "category", "candidate_id"
        }
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered)


@dataclass
class ExperimentExecutionRecord:
    """
    Formal Forensic Result returned from BCSL to HunterAI Brain & Evidence Court.
    """
    experiment_id: str
    request_id: str
    parent_request_id: str
    correlation_id: str
    identity_id: str
    timestamp: float
    request: CanonicalRequest
    response: CanonicalResponse
    response_diff: Dict[str, Any]
    state_before: StateSnapshot
    state_after: StateSnapshot
    execution_status: str  # EXECUTED, BLOCKED_SCOPE, BLOCKED_RISK, FAILED
    provenance: List[str] = field(default_factory=list)
    audit_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "experiment_id": self.experiment_id,
            "request_id": self.request_id,
            "parent_request_id": self.parent_request_id,
            "correlation_id": self.correlation_id,
            "identity_id": self.identity_id,
            "timestamp": self.timestamp,
            "request": self.request.to_dict(),
            "response": self.response.to_dict(),
            "response_diff": self.response_diff,
            "state_before": self.state_before.to_dict(),
            "state_after": self.state_after.to_dict(),
            "execution_status": self.execution_status,
            "provenance": self.provenance,
            "audit_hash": self.audit_hash,
        }
