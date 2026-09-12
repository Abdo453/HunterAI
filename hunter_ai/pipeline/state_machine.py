"""
HunterAI Finite State Machine
Enforces strict lifecycle invariants:
DISCOVER -> ENUMERATE -> NORMALIZE -> MAP -> CLASSIFY -> SURFACE -> TRIAGE -> HYPOTHESIZE -> TEST -> VERIFY -> CORRELATE -> ASSESS_IMPACT -> REPORT -> COMPLETE

CRITICAL INVARIANT: TEST -> REPORT directly is FORBIDDEN.
Every finding MUST traverse TEST -> VERIFY -> EVIDENCE -> REPORT.
"""
from __future__ import annotations

import logging
import time
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class HunterState(str, Enum):
    INIT = "INIT"
    SCOPE_CHECK = "SCOPE_CHECK"
    DISCOVER = "DISCOVER"          # Passive Recon (subdomains, CT, OSINT)
    ENUMERATE = "ENUMERATE"        # Active Recon (DNS, port scanning)
    NORMALIZE = "NORMALIZE"        # Merge, deduplicate, origin tracking
    MAP = "MAP"                    # Live assets discovery (httpx, status, title, tech)
    CLASSIFY = "CLASSIFY"          # Asset classification (API, Admin, Dev, Upload)
    SURFACE = "SURFACE"            # Attack surface (URLs, endpoints, JS, directories)
    TRIAGE = "TRIAGE"              # Parameter DB & Secret detection
    HYPOTHESIZE = "HYPOTHESIZE"    # Vulnerability hypothesis generation
    TEST = "TEST"                  # Targeted skill execution
    VERIFY = "VERIFY"              # Multi-layer verification (differential proofs)
    CORRELATE = "CORRELATE"        # Evidence correlation & blast radius
    ASSESS_IMPACT = "ASSESS_IMPACT"# Dynamic CVSS v3.1 calculation
    REPORT = "REPORT"              # Executive and technical reporting
    COMPLETE = "COMPLETE"
    ABORTED = "ABORTED"
    ERROR = "ERROR"


class IllegalStateTransitionError(Exception):
    """Raised when an illegal or dangerous state transition is attempted"""
    pass


class HunterStateMachine:
    """
    Finite State Machine governing HunterAI pipeline progression.
    Validates state transitions and enforces security invariants.
    """

    # Allowed forward transitions
    VALID_TRANSITIONS: Dict[HunterState, Set[HunterState]] = {
        HunterState.INIT: {HunterState.SCOPE_CHECK, HunterState.ERROR, HunterState.ABORTED},
        HunterState.SCOPE_CHECK: {HunterState.DISCOVER, HunterState.ABORTED, HunterState.ERROR},
        HunterState.DISCOVER: {HunterState.ENUMERATE, HunterState.NORMALIZE, HunterState.ERROR},
        HunterState.ENUMERATE: {HunterState.NORMALIZE, HunterState.ERROR},
        HunterState.NORMALIZE: {HunterState.MAP, HunterState.ERROR},
        HunterState.MAP: {HunterState.CLASSIFY, HunterState.SURFACE, HunterState.ERROR},
        HunterState.CLASSIFY: {HunterState.SURFACE, HunterState.ERROR},
        HunterState.SURFACE: {HunterState.TRIAGE, HunterState.HYPOTHESIZE, HunterState.ERROR},
        HunterState.TRIAGE: {HunterState.HYPOTHESIZE, HunterState.TEST, HunterState.ERROR},
        HunterState.HYPOTHESIZE: {HunterState.TEST, HunterState.REPORT, HunterState.ERROR},
        HunterState.TEST: {HunterState.VERIFY, HunterState.ERROR},  # NEVER REPORT!
        HunterState.VERIFY: {HunterState.CORRELATE, HunterState.ASSESS_IMPACT, HunterState.TEST, HunterState.REPORT, HunterState.ERROR},
        HunterState.CORRELATE: {HunterState.ASSESS_IMPACT, HunterState.REPORT, HunterState.ERROR},
        HunterState.ASSESS_IMPACT: {HunterState.REPORT, HunterState.ERROR},
        HunterState.REPORT: {HunterState.COMPLETE, HunterState.ERROR},
        HunterState.COMPLETE: set(),
        HunterState.ABORTED: set(),
        HunterState.ERROR: {HunterState.REPORT, HunterState.COMPLETE},
    }

    def __init__(self, target: str, session_id: str):
        self.target = target
        self.session_id = session_id
        self._current_state = HunterState.INIT
        self._history: List[Dict[str, Any]] = [
            {"from": None, "to": HunterState.INIT, "time": time.time(), "reason": "Init"}
        ]

    @property
    def current_state(self) -> HunterState:
        return self._current_state

    @property
    def history(self) -> List[Dict[str, Any]]:
        return list(self._history)

    def transition_to(self, new_state: HunterState, reason: str = "") -> HunterState:
        """
        Transitions to a new state if valid.
        Raises IllegalStateTransitionError if the transition violates workflow invariants.
        """
        if new_state == HunterState.REPORT and self._current_state == HunterState.TEST:
            msg = (
                f"CRITICAL INVARIANT VIOLATION: Cannot jump directly from TEST to REPORT! "
                f"All testing results MUST pass through VERIFY before REPORT."
            )
            logger.error(msg)
            raise IllegalStateTransitionError(msg)

        allowed = self.VALID_TRANSITIONS.get(self._current_state, set())
        if new_state not in allowed:
            msg = (
                f"Illegal state transition attempted: {self._current_state} -> {new_state}. "
                f"Allowed transitions from {self._current_state}: {[s.value for s in allowed]}"
            )
            logger.error(msg)
            raise IllegalStateTransitionError(msg)

        old_state = self._current_state
        self._current_state = new_state
        self._history.append({
            "from": old_state.value,
            "to": new_state.value,
            "time": time.time(),
            "reason": reason
        })
        logger.info(f"[HunterAI FSM] [{self.session_id}] {old_state.value} -> {new_state.value} ({reason})")
        return self._current_state
