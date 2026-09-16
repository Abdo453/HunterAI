"""
HunterAI Dynamic Security Invariant Discovery Engine
====================================================
Infers security invariants dynamically from observed application behavior:
- Observes multi-step sequences
- Identifies one-way transitions and terminal states
- Synthesizes candidate invariants and automatically tests for breaches
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("hunter_ai.invariant_discovery")


@dataclass
class InferredInvariant:
    invariant_id: str
    rule_statement: str
    resource_type: str
    observed_precondition: str
    prohibited_postcondition: str
    confidence: float = 0.85
    tested: bool = False
    is_breached: bool = False
    evidence_proof: str = ""


class DynamicInvariantDiscoverer:
    """
    Analyzes observed workflow sequences to discover unadvertised business constraints.
    """

    def __init__(self):
        self.inferred_invariants: List[InferredInvariant] = []
        self.state_history: List[Dict[str, Any]] = []

    def observe_workflow_sequence(self, workflow_name: str, sequence_steps: List[str]):
        """
        Observes a sequence e.g. ['CREATED', 'PAID', 'SHIPPED', 'DELIVERED'].
        Infers irreversible progression: once reached SHIPPED, cannot return to CREATED.
        """
        self.state_history.append({"workflow": workflow_name, "steps": sequence_steps})
        if len(sequence_steps) >= 3:
            initial = sequence_steps[0]
            advanced = sequence_steps[-1]
            inv = InferredInvariant(
                invariant_id=f"DYN-INV-{uuid.uuid4().hex[:6].upper()}",
                rule_statement=f"Resource in terminal state '{advanced}' cannot revert to initial state '{initial}'.",
                resource_type=workflow_name,
                observed_precondition=advanced,
                prohibited_postcondition=initial,
                confidence=0.90
            )
            self.inferred_invariants.append(inv)

    def test_inferred_invariant(
        self,
        invariant_id: str,
        attempt_reversal_fn
    ) -> InferredInvariant:
        """
        Attempts to violate the inferred invariant using the provided probe function.
        """
        inv = next((i for i in self.inferred_invariants if i.invariant_id == invariant_id), None)
        if not inv:
            raise ValueError(f"Invariant {invariant_id} not found.")

        result = attempt_reversal_fn(inv.observed_precondition, inv.prohibited_postcondition)
        inv.tested = True
        if result.get("success", False):
            inv.is_breached = True
            inv.evidence_proof = f"State reversal proven: Server transitioned resource from '{inv.observed_precondition}' back to '{inv.prohibited_postcondition}'."
        else:
            inv.is_breached = False
            inv.evidence_proof = f"State integrity intact: Server rejected transition from '{inv.observed_precondition}' to '{inv.prohibited_postcondition}'."

        return inv
