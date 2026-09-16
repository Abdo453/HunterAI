"""
HunterAI Unified Application Digital Twin
=========================================
Maintains an evolving, coherent, and centralized cognitive world model
of the target application, unifying:
- Active Identity contexts & roles
- Data Resources, ownership, and sensitivity
- Endpoints, methods, and parameter semantic roles
- Workflow state machines and transitions
- Discovered security invariants
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("hunter_ai.application_twin")


class ResourceSensitivity(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"


@dataclass
class TwinResource:
    resource_id: str
    resource_type: str
    owner_identity: str
    tenant_id: str = "tenant_1"
    sensitivity: ResourceSensitivity = ResourceSensitivity.CONFIDENTIAL
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TwinEndpoint:
    endpoint_path: str
    method: str
    required_role: str = "ANONYMOUS"
    accepted_parameters: List[str] = field(default_factory=list)
    state_mutating: bool = False
    observed_status_codes: Set[int] = field(default_factory=set)


@dataclass
class WorkflowStateNode:
    workflow_name: str
    current_state: str
    allowed_transitions: Dict[str, str] = field(default_factory=dict)  # action -> next_state
    terminal: bool = False


class ApplicationDigitalTwin:
    """
    Authoritative cognitive target representation.
    Synchronized from Browser, Burp, JS analysis, and API schemas.
    """

    def __init__(self, target_host: str = "target.local"):
        self.target_host = target_host
        self.identities: Dict[str, Dict[str, Any]] = {}
        self.resources: Dict[str, TwinResource] = {}
        self.endpoints: Dict[str, TwinEndpoint] = {}
        self.workflows: Dict[str, Dict[str, WorkflowStateNode]] = {}
        self.invariants: List[Dict[str, Any]] = []
        self._initialize_core_model()

    def _initialize_core_model(self):
        # Register standard identity contexts
        self.register_identity("anonymous", role="ANONYMOUS", tenant="none")
        self.register_identity("user_a", role="USER", tenant="tenant_alpha")
        self.register_identity("user_b", role="USER", tenant="tenant_beta")
        self.register_identity("admin", role="ADMIN", tenant="tenant_alpha")

    def register_identity(self, identity_id: str, role: str, tenant: str = "tenant_1", tokens: Optional[Dict[str, str]] = None):
        self.identities[identity_id] = {
            "identity_id": identity_id,
            "role": role,
            "tenant_id": tenant,
            "tokens": tokens or {},
            "registered_at": time.time()
        }

    def register_resource(self, resource_id: str, resource_type: str, owner: str, sensitivity: ResourceSensitivity = ResourceSensitivity.CONFIDENTIAL, tenant: str = "tenant_1"):
        res = TwinResource(
            resource_id=resource_id,
            resource_type=resource_type,
            owner_identity=owner,
            tenant_id=tenant,
            sensitivity=sensitivity
        )
        self.resources[resource_id] = res

    def register_endpoint(self, endpoint_path: str, method: str, params: Optional[List[str]] = None, required_role: str = "ANONYMOUS", mutating: bool = False):
        key = f"{method.upper()}:{endpoint_path}"
        ep = TwinEndpoint(
            endpoint_path=endpoint_path,
            method=method.upper(),
            required_role=required_role,
            accepted_parameters=params or [],
            state_mutating=mutating
        )
        self.endpoints[key] = ep

    def register_workflow_state(self, workflow: str, state: str, allowed_actions: Dict[str, str], terminal: bool = False):
        if workflow not in self.workflows:
            self.workflows[workflow] = {}
        self.workflows[workflow][state] = WorkflowStateNode(
            workflow_name=workflow,
            current_state=state,
            allowed_transitions=allowed_actions,
            terminal=terminal
        )

    def ingest_wire_observation(self, method: str, url: str, status_code: int, caller_identity: str = "anonymous", body_hint: str = ""):
        """Dynamically updates twin knowledge based on observed wire transactions"""
        path = url.split("?")[0]
        key = f"{method.upper()}:{path}"
        if key not in self.endpoints:
            self.register_endpoint(path, method, mutating=method.upper() in ("POST", "PUT", "DELETE", "PATCH"))
        self.endpoints[key].observed_status_codes.add(status_code)

    def get_summary(self) -> Dict[str, Any]:
        return {
            "target_host": self.target_host,
            "total_identities": len(self.identities),
            "total_resources": len(self.resources),
            "total_endpoints": len(self.endpoints),
            "total_workflows": len(self.workflows),
            "total_invariants": len(self.invariants),
        }
