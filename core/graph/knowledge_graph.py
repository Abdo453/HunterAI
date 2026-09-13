"""
HunterAI Structural Knowledge Graph
===================================
The central structural brain connecting:
Asset -> Host -> Endpoint -> Parameter/Method -> Identity -> Resource -> Finding -> Evidence
Enables semantic reasoning and attack path prioritization rather than flat fuzzing.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class SensitivityLevel(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED_PII = "RESTRICTED_PII"


@dataclass
class IdentityNode:
    role: str  # "anonymous", "standard_user_a", "standard_user_b", "admin"
    account_id: str
    tokens: Dict[str, str] = field(default_factory=dict)
    accessible_resources: Set[str] = field(default_factory=set)


@dataclass
class ResourceNode:
    resource_id: str
    resource_type: str  # "order", "medical_record", "document", "financial_profile"
    owner_identity: str
    sensitivity: SensitivityLevel = SensitivityLevel.CONFIDENTIAL
    endpoint_path: str = ""


@dataclass
class GraphEndpointNode:
    path: str
    method: str = "GET"
    parameters: List[str] = field(default_factory=list)
    requires_auth: bool = False
    linked_resources: List[str] = field(default_factory=list)
    associated_findings: List[str] = field(default_factory=list)


class KnowledgeGraph:
    """Relational knowledge graph representing the entire observed target domain"""

    def __init__(self, root_asset: str):
        self.root_asset = root_asset
        self.identities: Dict[str, IdentityNode] = {}
        self.resources: Dict[str, ResourceNode] = {}
        self.endpoints: Dict[str, GraphEndpointNode] = {}
        self.finding_links: Dict[str, List[str]] = {}

    def register_identity(self, role: str, account_id: str, tokens: Optional[Dict[str, str]] = None) -> IdentityNode:
        ident = IdentityNode(role=role, account_id=account_id, tokens=tokens or {})
        self.identities[role] = ident
        return ident

    def register_resource(self, res_id: str, res_type: str, owner_role: str, endpoint_path: str) -> ResourceNode:
        res = ResourceNode(resource_id=res_id, resource_type=res_type, owner_identity=owner_role, endpoint_path=endpoint_path)
        self.resources[res_id] = res
        if owner_role in self.identities:
            self.identities[owner_role].accessible_resources.add(res_id)
        return res

    def register_endpoint(self, path: str, method: str = "GET", params: Optional[List[str]] = None) -> GraphEndpointNode:
        key = f"{method.upper()}:{path}"
        if key not in self.endpoints:
            self.endpoints[key] = GraphEndpointNode(path=path, method=method.upper(), parameters=params or [])
        return self.endpoints[key]

    def link_finding_evidence(self, finding_id: str, evidence_id: str, endpoint_key: str):
        if finding_id not in self.finding_links:
            self.finding_links[finding_id] = []
        self.finding_links[finding_id].append(evidence_id)
        if endpoint_key in self.endpoints:
            self.endpoints[endpoint_key].associated_findings.append(finding_id)