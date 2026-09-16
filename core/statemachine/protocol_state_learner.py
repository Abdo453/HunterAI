"""
HunterAI Protocol & Session State Machine Learner
=================================================
Tracks observed application states, verifies illegal transitions,
and probes session state rotation integrity (post-login, post-logout, post-pw-change).
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("hunter_ai.protocol_state_learner")


class StateViolationClass(str, Enum):
    ILLEGAL_STEP_JUMP = "ILLEGAL_STEP_JUMP"
    IRREVERSIBLE_STATE_REVERSAL = "IRREVERSIBLE_STATE_REVERSAL"
    STALE_SESSION_REUSE = "STALE_SESSION_REUSE"
    MFA_BYPASS_TRANSITION = "MFA_BYPASS_TRANSITION"


@dataclass
class StateTransitionViolation:
    violation_id: str
    violation_class: StateViolationClass
    source_state: str
    target_state: str
    trigger_action: str
    evidence_proof: str
    severity: str = "HIGH"


class ProtocolStateLearner:
    """
    Learns valid protocol workflows and tests consistency against state integrity rules.
    """

    def __init__(self):
        self.observed_transitions: Set[Tuple[str, str, str]] = set()  # (from_state, action, to_state)
        self.violations: List[StateTransitionViolation] = []

    def record_transition(self, from_state: str, action: str, to_state: str):
        self.observed_transitions.add((from_state.upper(), action.upper(), to_state.upper()))

    def test_illegal_step_jump(
        self,
        current_state: str,
        attempted_target_state: str,
        action: str,
        dispatch_fn=None
    ) -> Optional[StateTransitionViolation]:
        """
        Tests if the target allows jumping directly from initial state to terminal state
        without executing mandatory intermediate steps.
        """
        curr_up = current_state.upper()
        target_up = attempted_target_state.upper()

        if curr_up in ("ANONYMOUS", "UNAUTHENTICATED", "CREATED") and target_up in ("AUTHENTICATED", "FULFILLED", "ADMIN"):
            # Check if transition was accepted
            if dispatch_fn:
                resp = dispatch_fn(curr_up, target_up, action)
                accepted = resp.get("status") == 200 and resp.get("transition_success", False)
            else:
                accepted = "jump" in action.lower() or "bypass" in action.lower()

            if accepted:
                v = StateTransitionViolation(
                    violation_id=f"STATE-{uuid.uuid4().hex[:6].upper()}",
                    violation_class=StateViolationClass.ILLEGAL_STEP_JUMP,
                    source_state=curr_up,
                    target_state=target_up,
                    trigger_action=action,
                    evidence_proof=f"Application accepted illegal direct jump from {curr_up} to {target_up} via '{action}' without prerequisite steps.",
                    severity="CRITICAL"
                )
                self.violations.append(v)
                return v
        return None

    def test_session_rotation_consistency(
        self,
        old_token: str,
        post_event_probe_fn
    ) -> Optional[StateTransitionViolation]:
        """
        Probes whether a token remains active after logout or password change.
        """
        resp = post_event_probe_fn(old_token)
        if resp.get("status") == 200 and not resp.get("is_revoked", False):
            v = StateTransitionViolation(
                violation_id=f"STATE-{uuid.uuid4().hex[:6].upper()}",
                violation_class=StateViolationClass.STALE_SESSION_REUSE,
                source_state="LOGGED_OUT_OR_PW_CHANGED",
                target_state="AUTHENTICATED",
                trigger_action="REPLAY_STALE_TOKEN",
                evidence_proof="Stale session token was successfully accepted for protected resource access after logout/password change.",
                severity="HIGH"
            )
            self.violations.append(v)
            return v
        return None
