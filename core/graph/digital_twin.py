"""
HunterAI Target Digital Twin & Dynamic Attack Surface Graph
===========================================================
Living internal representation of the target environment:
- Data Classification: PUBLIC, INTERNAL, SENSITIVE, SECRET
- Dynamic Node States: DISCOVERED, QUEUED, TESTED, VERIFIED, UNTESTED, BLOCKED, HIGH_RISK
- Attack Path Simulator: Dry-run simulation before active network execution
"""
from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class DataClassification(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    SENSITIVE = "SENSITIVE"
    SECRET = "SECRET"


class NodeLifecycleState(str, Enum):
    DISCOVERED = "DISCOVERED"
    QUEUED = "QUEUED"
    TESTED = "TESTED"
    VERIFIED = "VERIFIED"
    UNTESTED = "UNTESTED"
    BLOCKED = "BLOCKED"
    HIGH_RISK = "HIGH_RISK"


@dataclass
class TwinParameterNode:
    name: str
    location: str = "query"  # query, body, header, path
    inferred_type: str = "string"
    classification: DataClassification = DataClassification.PUBLIC
    has_injection_history: bool = False


@dataclass
class TwinEndpointNode:
    path: str
    method: str = "GET"
    requires_auth: bool = False
    parameters: Dict[str, TwinParameterNode] = field(default_factory=dict)
    state: NodeLifecycleState = NodeLifecycleState.DISCOVERED
    classification: DataClassification = DataClassification.PUBLIC
    associated_findings: List[str] = field(default_factory=list)


@dataclass
class TwinTechnologyNode:
    name: str
    version: Optional[str] = None
    category: str = "web_framework"  # server, framework, library, cms
    evidence: str = ""


@dataclass
class TwinIdentityNode:
    role: str  # anonymous, user_a, user_b, admin
    account_id: str
    session_state: str = "AUTHENTICATED"  # LOGGED_OUT, AUTHENTICATED, REFRESHED, REVOKED
    permissions: List[str] = field(default_factory=list)


class TargetDigitalTwin:
    """Dynamic in-memory digital twin representing the observed attack surface"""

    def __init__(self, root_domain: str):
        self.root_domain = root_domain
        self.endpoints: Dict[str, TwinEndpointNode] = {}
        self.technologies: Dict[str, TwinTechnologyNode] = {}
        self.identities: Dict[str, TwinIdentityNode] = {}
        self.created_at = time.time()

    def _ep_key(self, path: str, method: str) -> str:
        return f"{method.upper()}:{path}"

    def register_endpoint(
        self,
        path: str,
        method: str = "GET",
        requires_auth: bool = False,
        classification: DataClassification = DataClassification.PUBLIC
    ) -> TwinEndpointNode:
        key = self._ep_key(path, method)
        if key not in self.endpoints:
            # Infer classification if path contains sensitive keywords
            if any(k in path.lower() for k in ["admin", "secret", "token", "password", "key"]):
                classification = DataClassification.SECRET
            elif any(k in path.lower() for k in ["user", "order", "profile", "billing", "account"]):
                classification = DataClassification.SENSITIVE

            self.endpoints[key] = TwinEndpointNode(
                path=path,
                method=method.upper(),
                requires_auth=requires_auth,
                classification=classification,
                state=NodeLifecycleState.HIGH_RISK if classification in (DataClassification.SENSITIVE, DataClassification.SECRET) else NodeLifecycleState.DISCOVERED
            )
        return self.endpoints[key]

    def add_parameter(
        self,
        path: str,
        method: str,
        param_name: str,
        location: str = "query",
        inferred_type: str = "string"
    ):
        key = self._ep_key(path, method)
        if key in self.endpoints:
            classification = DataClassification.PUBLIC
            if any(k in param_name.lower() for k in ["token", "key", "secret", "auth", "pwd"]):
                classification = DataClassification.SECRET
            elif any(k in param_name.lower() for k in ["id", "user", "doc", "account"]):
                classification = DataClassification.SENSITIVE

            self.endpoints[key].parameters[param_name] = TwinParameterNode(
                name=param_name,
                location=location,
                inferred_type=inferred_type,
                classification=classification
            )

    def register_technology(self, name: str, version: Optional[str] = None, category: str = "framework", evidence: str = "") -> TwinTechnologyNode:
        tech = TwinTechnologyNode(name=name, version=version, category=category, evidence=evidence)
        self.technologies[name.lower()] = tech
        return tech

    def register_identity(self, role: str, account_id: str, session_state: str = "AUTHENTICATED", permissions: Optional[List[str]] = None) -> TwinIdentityNode:
        ident = TwinIdentityNode(role=role, account_id=account_id, session_state=session_state, permissions=permissions or [])
        self.identities[role] = ident
        return ident

    def update_node_state(self, path: str, method: str, new_state: NodeLifecycleState, finding_id: Optional[str] = None):
        key = self._ep_key(path, method)
        if key in self.endpoints:
            self.endpoints[key].state = new_state
            if finding_id:
                self.endpoints[key].associated_findings.append(finding_id)

    def simulate_attack_path(self, path: str, method: str, executor_role: str = "anonymous") -> Dict[str, Any]:
        """Simulates path risk and recommends prioritization before active execution"""
        key = self._ep_key(path, method)
        ep = self.endpoints.get(key)
        if not ep:
            return {"recommended_priority": 5, "risk": "UNKNOWN", "simulation_rationale": "Unregistered endpoint."}

        has_object_id = any(p.classification == DataClassification.SENSITIVE for p in ep.parameters.values())
        has_secret_param = any(p.classification == DataClassification.SECRET for p in ep.parameters.values())
        is_sensitive_resource = ep.classification in (DataClassification.SENSITIVE, DataClassification.SECRET)

        reasons = []
        priority = 5

        if is_sensitive_resource and has_object_id:
            priority = 1
            reasons.append("High-consequence BOLA/IDOR vector: Sensitive resource exposed via object identifier.")
        elif has_secret_param:
            priority = 1
            reasons.append("Authentication/Secret vector: Secret parameters observed.")
        elif is_sensitive_resource:
            priority = 2
            reasons.append(f"Sensitive resource node classified as {ep.classification.value}.")
        elif method.upper() in ("POST", "PUT", "DELETE"):
            priority = 3
            reasons.append(f"State-mutating HTTP verb {method.upper()}.")

        return {
            "endpoint": path,
            "method": method.upper(),
            "recommended_priority": priority,
            "classification": ep.classification.value,
            "has_object_id": has_object_id,
            "simulated_risk": "CRITICAL" if priority == 1 else "HIGH" if priority == 2 else "MEDIUM" if priority == 3 else "LOW",
            "simulation_rationale": "; ".join(reasons) or "Standard testing surface."
        }

    def export_topology(self) -> Dict[str, Any]:
        """Exports full topology graph summary"""
        state_breakdown = {}
        for ep in self.endpoints.values():
            state_breakdown[ep.state.value] = state_breakdown.get(ep.state.value, 0) + 1

        return {
            "root_domain": self.root_domain,
            "total_endpoints": len(self.endpoints),
            "technologies": [asdict(t) for t in self.technologies.values()],
            "identities": [asdict(i) for i in self.identities.values()],
            "state_distribution": state_breakdown,
            "endpoints": [
                {
                    "path": ep.path,
                    "method": ep.method,
                    "state": ep.state.value,
                    "classification": ep.classification.value,
                    "parameters_count": len(ep.parameters),
                    "associated_findings": ep.associated_findings
                }
                for ep in self.endpoints.values()
            ]
        }
