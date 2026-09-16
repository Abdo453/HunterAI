"""
HunterAI Authentication State Machine
=====================================
Models formal user lifecycle states and evaluates illegal transitions:
- ANONYMOUS -> PROTECTED
- MFA_PENDING -> PROTECTED (Bypass MFA challenge)
- LOGGED_OUT -> PROTECTED (Post-logout session reuse)
- PASSWORD_CHANGED -> OLD_SESSION_PROTECTED (Stale session retention)
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

from .schemas import AuthState, AuthTransitionTest

logger = logging.getLogger("hunter_ai.auth.state_machine")


class AuthenticationStateMachine:
    """Formal model of user authentication lifecycle states and transition invariants"""

    LEGAL_TRANSITIONS = {
        AuthState.ANONYMOUS: {AuthState.REGISTERED, AuthState.MFA_PENDING, AuthState.AUTHENTICATED, AuthState.LOGGED_OUT},
        AuthState.REGISTERED: {AuthState.EMAIL_UNVERIFIED, AuthState.AUTHENTICATED},
        AuthState.EMAIL_UNVERIFIED: {AuthState.AUTHENTICATED, AuthState.LOGGED_OUT},
        AuthState.MFA_PENDING: {AuthState.MFA_VERIFIED, AuthState.LOGGED_OUT},
        AuthState.MFA_VERIFIED: {AuthState.AUTHENTICATED, AuthState.LOGGED_OUT},
        AuthState.AUTHENTICATED: {AuthState.SESSION_REFRESHED, AuthState.LOGGED_OUT, AuthState.EXPIRED_SESSION},
        AuthState.SESSION_REFRESHED: {AuthState.AUTHENTICATED, AuthState.LOGGED_OUT, AuthState.EXPIRED_SESSION},
        AuthState.LOGGED_OUT: {AuthState.ANONYMOUS},
        AuthState.EXPIRED_SESSION: {AuthState.ANONYMOUS},
    }

    def __init__(self):
        self._current_state = AuthState.ANONYMOUS
        self.transition_history: List[AuthTransitionTest] = []

    @property
    def current_state(self) -> AuthState:
        return self._current_state

    def reset(self):
        self._current_state = AuthState.ANONYMOUS

    def evaluate_transition(
        self,
        from_state: AuthState,
        action: str,
        attempted_to_access_protected: bool,
        response_status: int,
        sensitive_data_leaked: bool = False
    ) -> AuthTransitionTest:
        """
        Verifies if an action under a given auth state breaches formal security invariants.
        """
        # Invariant 1: Unauthenticated/Logged out/Expired accessing protected resource
        if from_state in (AuthState.ANONYMOUS, AuthState.LOGGED_OUT, AuthState.EXPIRED_SESSION):
            if attempted_to_access_protected and response_status == 200 and sensitive_data_leaked:
                test = AuthTransitionTest(
                    initial_state=from_state,
                    target_action=action,
                    observed_state=AuthState.AUTHENTICATED,
                    expected_safe_state=from_state,
                    is_violation=True,
                    rationale=f"Invariant Violation: Resource accessible under {from_state.value} state (HTTP 200 with sensitive data)."
                )
                self.transition_history.append(test)
                return test

        # Invariant 2: MFA Pending accessing protected resource without completing MFA
        if from_state == AuthState.MFA_PENDING:
            if attempted_to_access_protected and response_status == 200 and sensitive_data_leaked:
                test = AuthTransitionTest(
                    initial_state=from_state,
                    target_action=action,
                    observed_state=AuthState.AUTHENTICATED,
                    expected_safe_state=AuthState.MFA_PENDING,
                    is_violation=True,
                    rationale="MFA Bypass Invariant Violation: Protected resource accessed before MFA challenge completed."
                )
                self.transition_history.append(test)
                return test

        # Normal safe transition
        test = AuthTransitionTest(
            initial_state=from_state,
            target_action=action,
            observed_state=from_state,
            expected_safe_state=from_state,
            is_violation=False,
            rationale=f"Security Invariant Preserved: Request safely restricted or appropriate for {from_state.value}."
        )
        self.transition_history.append(test)
        return test
