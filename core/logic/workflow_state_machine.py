"""
HunterAI Business Logic Workflow State Machine
==============================================
Models multi-step workflows (State A -> Action -> State B):
Created -> Paid -> Cancelled -> Refunded
Identifies illegal state transitions and parameter skipping.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


@dataclass
class WorkflowTransition:
    from_state: str
    action: str
    to_state: str
    allowed: bool = True
    requires_payment: bool = False


class BusinessLogicStateMachine:
    """Validates multi-step workflow states and flags illegal skips"""

    def __init__(self, workflow_name: str, valid_transitions: List[WorkflowTransition]):
        self.workflow_name = workflow_name
        self.valid_transitions: Dict[Tuple[str, str], str] = {
            (t.from_state, t.action): t.to_state for t in valid_transitions if t.allowed
        }

    def can_transition(self, current_state: str, action: str) -> bool:
        return (current_state, action) in self.valid_transitions

    def test_illegal_transition(
        self,
        current_state: str,
        illegal_action: str,
        server_response_status: int,
        server_response_body: str
    ) -> Dict[str, Any]:
        """Evaluates whether backend improperly allowed an illegal state transition"""
        expected_allowed = self.can_transition(current_state, illegal_action)
        if expected_allowed:
            return {"vulnerable": False, "reason": "Transition is legitimately permitted by policy."}

        # If server returns 200/201 and updates state on illegal action, business logic is flawed
        if server_response_status in (200, 201, 204) and "error" not in server_response_body.lower():
            return {
                "vulnerable": True,
                "vuln_class": "Business_Logic_Flaw",
                "confidence": 0.96,
                "reason": f"Server permitted illegal action '{illegal_action}' while entity was in state '{current_state}'.",
                "evidence": f"HTTP {server_response_status}: {server_response_body[:150]}"
            }

        return {
            "vulnerable": False,
            "reason": f"Server rejected illegal transition with HTTP {server_response_status}."
        }