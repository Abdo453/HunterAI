"""
HunterAI Evidence State Machine (V1.0)
=====================================
Governs finding lifecycle from initial discovery to definitive Court confirmation.
Eliminates LLM hallucinated verdicts by enforcing deterministic state transitions:

DISCOVERED -> OBSERVED -> HYPOTHESIS -> TESTED -> EVIDENCE_COLLECTED -> VERIFIED -> CONFIRMED
       |           |           |
       |           |           +--> REJECTED
       |           +--------------> INSUFFICIENT_EVIDENCE
       +--------------------------> DISCARDED
"""
from __future__ import annotations

import logging
import time
from enum import Enum
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("hunter_ai.evidence_state_machine")


class FindingState(str, Enum):
    DISCOVERED = "DISCOVERED"
    OBSERVED = "OBSERVED"
    HYPOTHESIS = "HYPOTHESIS"
    TESTED = "TESTED"
    EVIDENCE_COLLECTED = "EVIDENCE_COLLECTED"
    VERIFIED = "VERIFIED"
    CONFIRMED = "CONFIRMED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    REJECTED = "REJECTED"
    DISCARDED = "DISCARDED"


# Permitted valid state transitions
VALID_TRANSITIONS: Dict[FindingState, Set[FindingState]] = {
    FindingState.DISCOVERED: {
        FindingState.OBSERVED,
        FindingState.DISCARDED
    },
    FindingState.OBSERVED: {
        FindingState.HYPOTHESIS,
        FindingState.INSUFFICIENT_EVIDENCE,
        FindingState.DISCARDED
    },
    FindingState.HYPOTHESIS: {
        FindingState.TESTED,
        FindingState.REJECTED,
        FindingState.INSUFFICIENT_EVIDENCE
    },
    FindingState.TESTED: {
        FindingState.EVIDENCE_COLLECTED,
        FindingState.REJECTED,
        FindingState.INSUFFICIENT_EVIDENCE
    },
    FindingState.EVIDENCE_COLLECTED: {
        FindingState.VERIFIED,
        FindingState.INSUFFICIENT_EVIDENCE,
        FindingState.REJECTED
    },
    FindingState.VERIFIED: {
        FindingState.CONFIRMED,
        FindingState.REJECTED
    },
    FindingState.CONFIRMED: set(),  # Terminal state
    FindingState.INSUFFICIENT_EVIDENCE: {
        FindingState.HYPOTHESIS,  # Can re-open if new evidence emerges
        FindingState.DISCARDED
    },
    FindingState.REJECTED: set(),   # Terminal state (False Positive refuted)
    FindingState.DISCARDED: set(),  # Terminal state (Out of scope or irrelevant)
}


class InvalidStateTransitionError(ValueError):
    """Raised when an illegal state transition is attempted"""
    pass


class EvidenceStateMachine:
    """Manages state transitions and historical audit logs for a Finding"""

    def __init__(self, finding_id: str, initial_state: FindingState = FindingState.DISCOVERED):
        self.finding_id = finding_id
        self.current_state: FindingState = initial_state
        self.history: List[Dict[str, Any]] = [{
            "from_state": None,
            "to_state": initial_state.value,
            "timestamp": time.time(),
            "actor": "system",
            "reason": "Initial discovery created."
        }]

    def transition_to(
        self,
        new_state: FindingState,
        actor: str = "agent",
        reason: str = "",
        metadata: Optional[Dict[str, Any]] = None
    ) -> FindingState:
        """Transitions finding to new state if valid according to state invariants"""
        allowed = VALID_TRANSITIONS.get(self.current_state, set())
        if new_state not in allowed:
            err = (
                f"ILLEGAL STATE TRANSITION for {self.finding_id}: "
                f"Cannot move from '{self.current_state.value}' to '{new_state.value}'. "
                f"Allowed transitions: {[s.value for s in allowed]}"
            )
            logger.error(err)
            raise InvalidStateTransitionError(err)

        old_state = self.current_state
        self.current_state = new_state
        record = {
            "from_state": old_state.value,
            "to_state": new_state.value,
            "timestamp": time.time(),
            "actor": actor,
            "reason": reason or f"Transition from {old_state.value} to {new_state.value}",
            "metadata": metadata or {}
        }
        self.history.append(record)
        logger.info(f"[{self.finding_id}] State changed: {old_state.value} -> {new_state.value} ({reason})")
        return self.current_state

    def is_confirmed(self) -> bool:
        return self.current_state == FindingState.CONFIRMED

    def is_rejected(self) -> bool:
        return self.current_state in (FindingState.REJECTED, FindingState.INSUFFICIENT_EVIDENCE, FindingState.DISCARDED)
