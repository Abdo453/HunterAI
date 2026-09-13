"""
HunterAI Security State Machine & Business Logic Specification Engine
=====================================================================
Infers and models application business logic states:
UNAUTHENTICATED -> REGISTERED -> AUTHENTICATED -> PRIVILEGED -> RESOURCE_ACCESSED -> LOGGED_OUT

Allows users to define formal security specifications e.g.:
"unauthenticated_cannot_access_private_resource"
"revoked_session_cannot_mutate_resource"

Detects illegal state transitions and business logic flaws.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set


class ApplicationState(str, Enum):
    UNAUTHENTICATED = "UNAUTHENTICATED"
    AUTHENTICATED_NORMAL = "AUTHENTICATED_NORMAL"
    AUTHENTICATED_PRIVILEGED = "AUTHENTICATED_PRIVILEGED"
    RESOURCE_OWNER = "RESOURCE_OWNER"
    SESSION_EXPIRED = "SESSION_EXPIRED"
    SESSION_REVOKED = "SESSION_REVOKED"


@dataclass
class StateTransition:
    from_state: ApplicationState
    action_route: str
    to_state: ApplicationState
    timestamp: float = field(default_factory=time.time)


@dataclass
class SpecificationViolation:
    violation_id: str
    rule_name: str
    from_state: ApplicationState
    illegal_target_state: ApplicationState
    route: str
    evidence_proof: str
    cwe_id: str = "CWE-841"  # Improper Enforcement of Behavioral Workflow


class SecuritySpecificationEngine:
    """Evaluates business logic transitions against declared security rules"""

    def __init__(self):
        self.rules: Dict[str, Callable[[ApplicationState, str, int, str], bool]] = {}
        self._register_default_invariants()

    def _register_default_invariants(self):
        # Invariant 1: Unauthenticated state cannot produce 200 OK with sensitive data
        self.rules["unauthenticated_cannot_access_private_resource"] = (
            lambda state, route, status, body: not (state == ApplicationState.UNAUTHENTICATED and status == 200 and ("confidential" in body.lower() or "ssn" in body.lower() or "secret" in body.lower()))
        )
        # Invariant 2: Revoked session cannot perform operations
        self.rules["revoked_session_cannot_mutate_resource"] = (
            lambda state, route, status, body: not (state in (ApplicationState.SESSION_REVOKED, ApplicationState.SESSION_EXPIRED) and status in (200, 201, 204))
        )

    def verify_transition(
        self,
        current_state: ApplicationState,
        route: str,
        response_status: int,
        response_body: str
    ) -> Optional[SpecificationViolation]:
        for rule_name, validator in self.rules.items():
            if not validator(current_state, route, response_status, response_body):
                return SpecificationViolation(
                    violation_id=f"VIO-{rule_name[:6].upper()}",
                    rule_name=rule_name,
                    from_state=current_state,
                    illegal_target_state=ApplicationState.RESOURCE_OWNER,
                    route=route,
                    evidence_proof=f"Response {response_status} violated business logic invariant '{rule_name}'."
                )
        return None


class SecurityStateMachine:
    """Tracks active state progression across multi-step user workflows"""

    def __init__(self, session_id: str):
        self.session_id = session_id
        self.current_state: ApplicationState = ApplicationState.UNAUTHENTICATED
        self.history: List[StateTransition] = []
        self.spec_engine = SecuritySpecificationEngine()

    def execute_transition(
        self,
        action_route: str,
        response_status: int,
        response_body: str,
        intended_next_state: ApplicationState
    ) -> Optional[SpecificationViolation]:
        # Check against invariants
        violation = self.spec_engine.verify_transition(
            self.current_state, action_route, response_status, response_body
        )

        # Log transition
        self.history.append(StateTransition(
            from_state=self.current_state,
            action_route=action_route,
            to_state=intended_next_state if not violation else self.current_state
        ))

        if not violation and response_status in (200, 201):
            self.current_state = intended_next_state

        return violation
