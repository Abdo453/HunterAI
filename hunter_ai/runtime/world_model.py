"""
HunterAI Runtime: Application World Model & Identity Graph
===========================================================
Represents the target web application not as a collection of disjoint URLs,
but as a coherent mental model comprising:
1. Identity & Role Hierarchy (Anonymous, User, Manager, Admin)
2. Resource Object Ownership (Tenants, Documents, Orders)
3. Multi-Step Workflows & State Machines (Sequences, Transitions)
4. Trust Boundaries & Invariant Enforcements
"""
from __future__ import annotations

import time
import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Any, Set, Tuple


class RoleLevel(int, Enum):
    ANONYMOUS = 0
    UNVERIFIED_USER = 1
    AUTHENTICATED_USER = 2
    PRIVILEGED_USER = 3  # e.g., Manager, Auditor
    ADMINISTRATOR = 4


@dataclass
class UserIdentity:
    """A distinct user persona or tenant session in the world model"""
    user_id: str
    username: str
    role: RoleLevel = RoleLevel.AUTHENTICATED_USER
    session_tokens: Dict[str, str] = field(default_factory=dict)
    owned_object_ids: Set[str] = field(default_factory=set)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "username": self.username,
            "role": self.role.name,
            "owned_object_ids": list(self.owned_object_ids)
        }


@dataclass
class ResourceObject:
    """An identifiable entity/record managed by the application"""
    object_type: str        # e.g., "order", "invoice", "user_profile", "api_key"
    object_id: str
    owner_user_id: str
    is_public: bool = False
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class IdentityGraph:
    """
    Tracks identities, roles, and object ownership.
    Provides cross-tenant test pairs for authorization testing.
    """

    def __init__(self):
        self.identities: Dict[str, UserIdentity] = {}
        self.objects: Dict[str, ResourceObject] = {}

    def register_user(self, user_id: str, username: str, role: RoleLevel = RoleLevel.AUTHENTICATED_USER) -> UserIdentity:
        user = UserIdentity(user_id=user_id, username=username, role=role)
        self.identities[user_id] = user
        return user

    def register_object(self, object_type: str, object_id: str, owner_user_id: str, is_public: bool = False) -> ResourceObject:
        obj = ResourceObject(object_type=object_type, object_id=object_id, owner_user_id=owner_user_id, is_public=is_public)
        self.objects[object_id] = obj
        if owner_user_id in self.identities:
            self.identities[owner_user_id].owned_object_ids.add(object_id)
        return obj

    def get_cross_tenant_test_pairs(self) -> List[Tuple[UserIdentity, ResourceObject]]:
        """
        Returns pairs of (Attacking User, Victim's Private Object)
        where the user does NOT own the object, to test BOLA/IDOR boundaries.
        """
        pairs = []
        for user in self.identities.values():
            for obj in self.objects.values():
                if not obj.is_public and obj.owner_user_id != user.user_id:
                    pairs.append((user, obj))
        return pairs

    def is_authorized(self, user_id: str, object_id: str) -> bool:
        """Ground truth specification: does user actually own the object or have admin role?"""
        user = self.identities.get(user_id)
        obj = self.objects.get(object_id)
        if not user or not obj:
            return False
        if obj.is_public:
            return True
        if user.role == RoleLevel.ADMINISTRATOR:
            return True
        return obj.owner_user_id == user_id


@dataclass
class StateTransition:
    """A step in an application workflow"""
    from_state: str
    to_state: str
    action_name: str
    endpoint: str
    method: str = "POST"
    required_params: List[str] = field(default_factory=list)


class ApplicationStateMachine:
    """
    Models multi-step workflows (e.g., Cart -> Checkout -> Payment -> Delivery).
    Generates negative sequences (skipped steps, replayed steps, out-of-order execution).
    """

    def __init__(self):
        self.workflows: Dict[str, List[StateTransition]] = {}

    def register_workflow(self, workflow_name: str, transitions: List[StateTransition]):
        self.workflows[workflow_name] = transitions

    def get_skipped_step_scenarios(self, workflow_name: str) -> List[Dict[str, Any]]:
        """
        Generates negative test sequences where an intermediate validation step is omitted.
        E.g.: Step 1 -> Step 3 (skipping Step 2).
        """
        transitions = self.workflows.get(workflow_name, [])
        if len(transitions) < 3:
            return []

        scenarios = []
        for i in range(1, len(transitions) - 1):
            skipped = transitions[i]
            target = transitions[i + 1]
            scenarios.append({
                "type": "SKIPPED_STEP",
                "workflow": workflow_name,
                "skipped_step": skipped.action_name,
                "attempted_step": target.action_name,
                "target_endpoint": target.endpoint,
                "expected_enforcement": f"Should reject {target.action_name} because prerequisite {skipped.action_name} was omitted."
            })
        return scenarios

    def get_replayed_step_scenarios(self, workflow_name: str) -> List[Dict[str, Any]]:
        """
        Generates negative test sequences where a completed transition is re-executed
        (e.g., double spend, coupon re-application).
        """
        transitions = self.workflows.get(workflow_name, [])
        scenarios = []
        for t in transitions:
            scenarios.append({
                "type": "REPLAY_STEP",
                "workflow": workflow_name,
                "replayed_step": t.action_name,
                "target_endpoint": t.endpoint,
                "expected_enforcement": f"Should reject duplicate invocation of {t.action_name}."
            })
        return scenarios


class ApplicationWorldModel:
    """
    The complete mental world model representing an application under audit.
    """

    def __init__(self, target_domain: str = ""):
        self.target_domain = target_domain
        self.identity_graph = IdentityGraph()
        self.state_machine = ApplicationStateMachine()
        self.discovered_endpoints: Set[str] = set()

    def record_endpoint(self, endpoint: str):
        self.discovered_endpoints.add(endpoint)

    def to_compact_summary(self) -> Dict[str, Any]:
        """Compact view tailored for LLM reasoning prompt"""
        return {
            "target": self.target_domain,
            "identities_count": len(self.identity_graph.identities),
            "tracked_objects_count": len(self.identity_graph.objects),
            "workflows_count": len(self.state_machine.workflows),
            "endpoints_mapped": len(self.discovered_endpoints),
            "cross_tenant_test_pairs": len(self.identity_graph.get_cross_tenant_test_pairs())
        }
