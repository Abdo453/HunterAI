"""
HunterAI Security Digital Twin
==============================
Maintains an evolving cognitive model of the target web application:
- Assets & Endpoints
- Identities, Roles & Sessions
- Data Resources & Ownership Relationships
- Access Control State Model

The Agent plans tests first inside the Digital Twin, recalculating risk
and only sending live network requests when a viable attack path is modeled.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class RoleTier(str, Enum):
    ANONYMOUS = "ANONYMOUS"
    AUTHENTICATED_USER = "AUTHENTICATED_USER"
    TENANT_ADMIN = "TENANT_ADMIN"
    SUPER_ADMIN = "SUPER_ADMIN"


@dataclass
class AssetIdentityModel:
    identity_id: str
    role: RoleTier
    auth_token: Optional[str]
    accessible_resources: Set[str] = field(default_factory=set)


@dataclass
class ResourceNode:
    resource_id: str
    resource_type: str  # e.g., "order", "medical_record", "invoice"
    owner_identity: str
    sensitivity: str = "HIGH"  # "PUBLIC", "INTERNAL", "HIGH", "CRITICAL"


@dataclass
class AttackPathHypothesis:
    path_id: str
    source_identity: str
    target_resource: str
    vulnerability_vector: str  # e.g., "BOLA_DIRECT_ID", "UNAUTHENTICATED_ACCESS"
    projected_risk: str
    simulation_rationale: str
    is_authorized_by_policy: bool = True


class SecurityDigitalTwin:
    """In-memory evolving world model of the target security architecture"""

    def __init__(self, target_host: str):
        self.target_host = target_host
        self.identities: Dict[str, AssetIdentityModel] = {}
        self.resources: Dict[str, ResourceNode] = {}
        self.endpoints: Set[str] = set()
        self.last_updated: float = time.time()

    def register_identity(self, identity_id: str, role: RoleTier, token: Optional[str] = None) -> AssetIdentityModel:
        ident = AssetIdentityModel(identity_id, role, token)
        self.identities[identity_id] = ident
        self.last_updated = time.time()
        return ident

    def register_resource(self, resource_id: str, resource_type: str, owner_id: str, sensitivity: str = "HIGH") -> ResourceNode:
        res = ResourceNode(resource_id, resource_type, owner_id, sensitivity)
        self.resources[resource_id] = res
        if owner_id in self.identities:
            self.identities[owner_id].accessible_resources.add(resource_id)
        self.last_updated = time.time()
        return res

    def register_endpoint(self, endpoint: str):
        self.endpoints.add(endpoint)
        self.last_updated = time.time()

    def simulate_cross_tenant_access_paths(self) -> List[AttackPathHypothesis]:
        """Simulates whether Identity A can plausibly reach resources owned by Identity B"""
        hypotheses: List[AttackPathHypothesis] = []
        id_list = list(self.identities.values())

        for attacker in id_list:
            for res_id, res in self.resources.items():
                if res.owner_identity != attacker.identity_id and res_id not in attacker.accessible_resources:
                    hyp_id = f"PATH-BOLA-{attacker.identity_id}-TO-{res_id}"
                    hypotheses.append(AttackPathHypothesis(
                        path_id=hyp_id,
                        source_identity=attacker.identity_id,
                        target_resource=res_id,
                        vulnerability_vector="BOLA_CROSS_TENANT_REPLAY",
                        projected_risk="HIGH" if res.sensitivity in ("HIGH", "CRITICAL") else "MEDIUM",
                        simulation_rationale=(
                            f"Identity '{attacker.identity_id}' ({attacker.role.value}) lacks legitimate ownership "
                            f"of '{res_id}' owned by '{res.owner_identity}'. Test cross-tenant token replay."
                        )
                    ))
        return hypotheses
