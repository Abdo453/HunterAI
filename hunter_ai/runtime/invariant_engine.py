"""
HunterAI Runtime: Security Invariant & Rule-Breaking Engine
============================================================
Moves beyond basic payload injection by formally defining and testing application
security invariants (rules that must NEVER be violated under any sequence):
1. Tenant Isolation Invariant: User A must never read/write User B's private objects.
2. Privilege Boundary Invariant: Lower-privileged actors cannot trigger higher-privileged actions.
3. State Sequence Invariant: State X cannot be reached without completing prerequisite State W.
4. Idempotency & Replay Invariant: Non-idempotent business transactions cannot be duplicated.
"""
from __future__ import annotations

import time
import logging
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Any, Callable

from hunter_ai.runtime.world_model import UserIdentity, ResourceObject, RoleLevel

logger = logging.getLogger("hunter_ai.invariant_engine")


class InvariantType(str, Enum):
    TENANT_ISOLATION = "TENANT_ISOLATION"           # IDOR / BOLA
    PRIVILEGE_BOUNDARY = "PRIVILEGE_BOUNDARY"       # BFLA / Privilege Escalation
    STATE_PREREQUISITE = "STATE_PREREQUISITE"       # Workflow / Sequence bypass
    REPLAY_PROTECTION = "REPLAY_PROTECTION"         # Double spend / Race condition


@dataclass
class SecurityInvariant:
    """Specification of an expected application security rule"""
    id: str
    name: str
    invariant_type: InvariantType
    description: str
    expected_failure_status: List[int] = field(default_factory=lambda: [401, 403, 404, 422])


@dataclass
class InvariantViolation:
    """Evidence of a broken application security rule"""
    invariant_id: str
    invariant_type: InvariantType
    endpoint: str
    actor_id: str
    target_object_id: Optional[str]
    observed_status: int
    observed_behavior: str
    expected_behavior: str
    confidence: float
    evidence: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["invariant_type"] = self.invariant_type.value
        return d


class InvariantEngine:
    """
    Evaluates observed application responses against fundamental security invariants
    to detect high-impact business logic and authorization vulnerabilities.
    """

    def __init__(self):
        self._invariants: Dict[str, SecurityInvariant] = {}
        self._violations: List[InvariantViolation] = []
        self._seed_standard_invariants()

    def _seed_standard_invariants(self):
        self.register_invariant(SecurityInvariant(
            id="INV_01_TENANT_ISOLATION",
            name="Strict Tenant Isolation (BOLA/IDOR)",
            invariant_type=InvariantType.TENANT_ISOLATION,
            description="User A cannot retrieve or mutate private objects owned by User B."
        ))
        self.register_invariant(SecurityInvariant(
            id="INV_02_PRIVILEGE_BOUNDARY",
            name="Role Privilege Boundary (BFLA)",
            invariant_type=InvariantType.PRIVILEGE_BOUNDARY,
            description="Standard users cannot access administrative endpoints or functions."
        ))
        self.register_invariant(SecurityInvariant(
            id="INV_03_WORKFLOW_SEQUENCE",
            name="Strict Workflow Progression",
            invariant_type=InvariantType.STATE_PREREQUISITE,
            description="Finalizing an action requires valid completion of all prerequisite steps."
        ))
        self.register_invariant(SecurityInvariant(
            id="INV_04_REPLAY_PROTECTION",
            name="Transaction Replay Protection",
            invariant_type=InvariantType.REPLAY_PROTECTION,
            description="Non-idempotent state alterations (credits, checkout) cannot be replayed."
        ))

    def register_invariant(self, invariant: SecurityInvariant):
        self._invariants[invariant.id] = invariant

    def evaluate_access(
        self,
        actor: UserIdentity,
        target_object: ResourceObject,
        endpoint: str,
        response_status: int,
        response_body: str
    ) -> Optional[InvariantViolation]:
        """
        Tests whether an access attempt broke the Tenant Isolation invariant.
        """
        # If object is public, accessing it is expected
        if target_object.is_public:
            return None

        # If actor owns the object or is admin, accessing it is legitimate
        if actor.user_id == target_object.owner_user_id or actor.role == RoleLevel.ADMINISTRATOR:
            return None

        # Cross-tenant attempt occurred: did the server return 200 with object data?
        if response_status == 200:
            # Check if object ID or unique attributes leaked in the response body
            body_contains_object = (target_object.object_id in response_body)
            has_private_attributes = any(
                str(val) in response_body for val in target_object.attributes.values() if str(val)
            )

            if body_contains_object or has_private_attributes:
                violation = InvariantViolation(
                    invariant_id="INV_01_TENANT_ISOLATION",
                    invariant_type=InvariantType.TENANT_ISOLATION,
                    endpoint=endpoint,
                    actor_id=actor.user_id,
                    target_object_id=target_object.object_id,
                    observed_status=response_status,
                    observed_behavior=f"Actor '{actor.username}' successfully read private object '{target_object.object_id}' owned by User '{target_object.owner_user_id}'.",
                    expected_behavior="Server must return HTTP 403 Forbidden or 404 Not Found.",
                    confidence=0.95,
                    evidence={
                        "object_type": target_object.object_type,
                        "leak_confirmed": True,
                        "response_preview": response_body[:500]
                    }
                )
                self._violations.append(violation)
                logger.warning(f"[InvariantEngine] VIOLATION DETECTED: {violation.observed_behavior}")
                return violation

        return None

    def evaluate_workflow_sequence(
        self,
        workflow_name: str,
        skipped_step: str,
        attempted_step: str,
        endpoint: str,
        response_status: int,
        response_body: str
    ) -> Optional[InvariantViolation]:
        """
        Tests whether skipping a mandatory intermediate step was accepted by the server.
        """
        if response_status in [200, 201]:
            # Step succeeded despite skipping prerequisite
            violation = InvariantViolation(
                invariant_id="INV_03_WORKFLOW_SEQUENCE",
                invariant_type=InvariantType.STATE_PREREQUISITE,
                endpoint=endpoint,
                actor_id="tester",
                target_object_id=None,
                observed_status=response_status,
                observed_behavior=f"Step '{attempted_step}' executed successfully even though prerequisite step '{skipped_step}' was omitted.",
                expected_behavior=f"Server must reject execution until '{skipped_step}' is validated in the session state.",
                confidence=0.90,
                evidence={
                    "workflow": workflow_name,
                    "skipped_step": skipped_step,
                    "attempted_step": attempted_step
                }
            )
            self._violations.append(violation)
            logger.warning(f"[InvariantEngine] WORKFLOW INVARIANT BROKEN: {violation.observed_behavior}")
            return violation
        return None

    def get_violations(self) -> List[InvariantViolation]:
        return list(self._violations)
