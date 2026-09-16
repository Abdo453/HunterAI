"""
HunterAI V27.0 - Extensible Causal Invariants Framework
========================================================
Decouples causal verification from hardcoded payloads or specific test cases.
Provides formal abstractions modeling:
  - input_relation: The semantic input mutation across B, C, E1, E2
  - expected_output_relation: Formal predicted transformation on target state
  - control_constraint: Conditions that harmless control C must satisfy
  - reproducibility_requirement: Number and consistency of metamorphic probe confirmations
  - invalidation_conditions: Exact conditions that conclusively refute the hypothesis

Adapters:
  - CommandExecutionInvariant
  - BooleanDifferentialInvariant
  - AuthorizationInvariant
  - OOBCorrelationInvariant
  - DOMExecutionInvariant
  - StateTransitionInvariant
"""
from __future__ import annotations

import abc
import logging
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from core.reasoning.triad_verifier import TransactionSnapshot, TriadBundle

logger = logging.getLogger("hunter_ai.causal_invariants")


@dataclass
class InvariantEvaluationResult:
    passed: bool
    confidence: float
    reason: str
    extracted_observables: Dict[str, Any] = field(default_factory=dict)
    invalidation_triggered: bool = False
    invalidation_detail: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class CausalInvariant(abc.ABC):
    """Abstract Base Class for formal causal security invariants."""

    def __init__(
        self,
        invariant_id: str,
        name: str,
        description: str,
        input_relation: Optional[Dict[str, Any]] = None,
        expected_output_relation: Optional[Dict[str, Any]] = None,
        control_constraint: Optional[Dict[str, Any]] = None,
        reproducibility_requirement: Optional[Dict[str, Any]] = None,
        invalidation_conditions: Optional[List[str]] = None,
    ):
        self.invariant_id = invariant_id
        self.name = name
        self.description = description
        self.input_relation = input_relation or {}
        self.expected_output_relation = expected_output_relation or {}
        self.control_constraint = control_constraint or {}
        self.reproducibility_requirement = reproducibility_requirement or {"min_metamorphic_reproductions": 1}
        self.invalidation_conditions = invalidation_conditions or []

    @abc.abstractmethod
    def evaluate(self, bundle: TriadBundle) -> InvariantEvaluationResult:
        """Evaluates whether the observed TriadBundle satisfies the formal invariant."""
        pass


class CommandExecutionInvariant(CausalInvariant):
    """
    Evaluates arbitrary command execution / SSTI / arithmetic evaluation.
    Distinguishes algebraic evaluation from literal string reflection.
    """

    def __init__(
        self,
        expected_token: str = "72",
        e1_expr: str = "53+19",
        e2_expr: str = "41+31",
        control_expr: str = "53+0",
    ):
        super().__init__(
            invariant_id="INV-CMD-EXEC-01",
            name="Command & Code Execution Invariant",
            description="Evaluates algebraic side-effect vs literal reflection across metamorphic probes.",
            input_relation={"e1": e1_expr, "e2": e2_expr, "control": control_expr},
            expected_output_relation={"evaluated_token": expected_token},
            control_constraint={"must_not_contain": expected_token},
            invalidation_conditions=["literal_reflection_without_evaluation", "control_produces_token"],
        )
        self.expected_token = expected_token
        self.e1_expr = e1_expr
        self.e2_expr = e2_expr
        self.control_expr = control_expr

    def evaluate(self, bundle: TriadBundle) -> InvariantEvaluationResult:
        b = bundle.baseline
        c = bundle.control
        e1 = bundle.experiment_1
        e2 = bundle.experiment_2

        # 1. Check control constraint: Control must NOT produce the exploit token
        if self.expected_token in c.body:
            return InvariantEvaluationResult(
                passed=False,
                confidence=0.0,
                reason="Control mutation C unexpectedly contained the target token; token is not causal.",
                invalidation_triggered=True,
                invalidation_detail="control_produces_token",
            )

        # 2. Check for Literal Reflection without Execution
        escaped_expr = re.escape(self.e1_expr)
        reflection_detected = (
            self.e1_expr in e1.body
            or f"$({self.e1_expr})" in e1.body
            or f"$(({self.e1_expr}))" in e1.body
            or f"`{self.e1_expr}`" in e1.body
            or bool(re.search(r'["\']' + escaped_expr + r'["\']', e1.body))
        )
        if reflection_detected and self.expected_token not in e1.body:
            return InvariantEvaluationResult(
                passed=False,
                confidence=0.05,
                reason=f"Literal reflection detected: '{self.e1_expr}' echoed without evaluation.",
                invalidation_triggered=True,
                invalidation_detail="literal_reflection_without_evaluation",
            )

        # 3. Metamorphic Verification across E1 and E2
        e1_has_token = (self.expected_token in e1.body) or (self.expected_token in e1.extracted_tokens)
        e2_has_token = (self.expected_token in e2.body) or (self.expected_token in e2.extracted_tokens)

        if e1_has_token and e2_has_token:
            return InvariantEvaluationResult(
                passed=True,
                confidence=0.99,
                reason=f"Metamorphic Command Execution Invariant satisfied: Both E1 and E2 evaluated to '{self.expected_token}'.",
                extracted_observables={"token": self.expected_token, "e1_verified": True, "e2_verified": True},
            )
        elif e1_has_token and not e2_has_token:
            return InvariantEvaluationResult(
                passed=False,
                confidence=0.40,
                reason="Metamorphic inconsistency: E1 produced token but equivalent probe E2 did not.",
                invalidation_triggered=False,
                invalidation_detail="metamorphic_divergence",
            )
        else:
            return InvariantEvaluationResult(
                passed=False,
                confidence=0.10,
                reason=f"Execution token '{self.expected_token}' absent from probe responses.",
            )


class BooleanDifferentialInvariant(CausalInvariant):
    """
    Evaluates Boolean-based injection (SQLi / LDAP / XPath).
    Requires deterministic state bifurcation between True and False expressions.
    """

    def __init__(self):
        super().__init__(
            invariant_id="INV-BOOLEAN-DIFF-01",
            name="Boolean Differential Invariant",
            description="True condition branches must match baseline, False condition must diverge.",
            invalidation_conditions=["false_condition_matches_true_condition"],
        )

    def evaluate(self, bundle: TriadBundle) -> InvariantEvaluationResult:
        b = bundle.baseline
        c = bundle.control         # Injected False condition (e.g. ' AND 1=2)
        e1 = bundle.experiment_1   # Injected True condition 1 (e.g. ' AND 1=1)
        e2 = bundle.experiment_2   # Injected True condition 2 (e.g. ' AND 2=2)

        # True condition probes (E1, E2) should match Baseline (B)
        e1_matches_b = (e1.status_code == b.status_code) and (abs(e1.body_length - b.body_length) < 20)
        e2_matches_b = (e2.status_code == b.status_code) and (abs(e2.body_length - b.body_length) < 20)

        # False condition probe (C) must diverge significantly from Baseline (B) and True probes (E1, E2)
        c_diverges = (c.status_code != b.status_code) or (abs(c.body_length - b.body_length) > 50)

        if e1_matches_b and e2_matches_b and c_diverges:
            return InvariantEvaluationResult(
                passed=True,
                confidence=0.98,
                reason="Boolean Differential Invariant satisfied: True branches preserve Baseline while False branch diverges.",
                extracted_observables={"boolean_split_confirmed": True},
            )
        else:
            return InvariantEvaluationResult(
                passed=False,
                confidence=0.20,
                reason="Boolean differential failed: Response did not bifurcate consistently on boolean predicate.",
            )


class AuthorizationInvariant(CausalInvariant):
    """
    Evaluates multi-tenant access control and BOLA/IDOR boundaries.
    """

    def __init__(self, resource_id: str, owner_id: str, actor_id: str):
        super().__init__(
            invariant_id=f"INV-AUTHZ-{actor_id}-ON-{resource_id}",
            name="Authorization Boundary Invariant",
            description="Ensures cross-tenant / unprivileged actors cannot read foreign resources.",
            input_relation={"actor": actor_id, "owner": owner_id, "resource": resource_id},
            expected_output_relation={"enforced_status": [401, 403, 404]},
            invalidation_conditions=["foreign_resource_body_exposed", "status_200_with_owner_data"],
        )
        self.resource_id = resource_id
        self.owner_id = owner_id
        self.actor_id = actor_id

    def evaluate(self, bundle: TriadBundle) -> InvariantEvaluationResult:
        e1 = bundle.experiment_1
        e2 = bundle.experiment_2

        e1_denied = e1.status_code in (401, 403) or "unauthorized" in e1.body.lower() or "forbidden" in e1.body.lower()
        e2_denied = e2.status_code in (401, 403) or "unauthorized" in e2.body.lower() or "forbidden" in e2.body.lower()

        if e1_denied and e2_denied:
            return InvariantEvaluationResult(
                passed=True,
                confidence=0.95,
                reason=f"Authorization Invariant enforced: Actor '{self.actor_id}' received 403/401 accessing '{self.resource_id}'.",
                extracted_observables={"boundary_enforced": True, "tested_status": e1.status_code},
            )

        e1_breach = (e1.status_code == 200) and (self.owner_id in e1.body or self.resource_id in e1.body)
        e2_breach = (e2.status_code == 200) and (self.owner_id in e2.body or self.resource_id in e2.body)

        if e1_breach and e2_breach:
            return InvariantEvaluationResult(
                passed=False,
                confidence=0.98,
                reason=f"CRITICAL: Authorization Boundary Breached! Actor '{self.actor_id}' read '{self.resource_id}' owned by '{self.owner_id}'.",
                invalidation_triggered=True,
                invalidation_detail="foreign_resource_body_exposed",
                extracted_observables={"access_control_violation": True},
            )

        return InvariantEvaluationResult(
            passed=False,
            confidence=0.45,
            reason="Inconclusive authorization state: Neither strict denial nor full resource disclosure observed.",
        )


class OOBCorrelationInvariant(CausalInvariant):
    """Evaluates Out-of-Band (OOB) DNS/HTTP callback interactions with unique nonces."""

    def __init__(self, expected_nonce: str):
        super().__init__(
            invariant_id="INV-OOB-CORRELATION-01",
            name="Out-of-Band Callback Invariant",
            description="Validates that external interactions match the unique transaction nonce.",
        )
        self.expected_nonce = expected_nonce

    def evaluate(self, bundle: TriadBundle) -> InvariantEvaluationResult:
        callbacks = bundle.metadata.get("oob_callbacks", [])
        matched = any(self.expected_nonce in str(cb) for cb in callbacks)
        if matched:
            return InvariantEvaluationResult(
                passed=True,
                confidence=0.99,
                reason=f"OOB Callback confirmed with matching nonce '{self.expected_nonce}'.",
                extracted_observables={"oob_nonce_matched": True},
            )
        return InvariantEvaluationResult(
            passed=False,
            confidence=0.10,
            reason=f"No external callback received matching nonce '{self.expected_nonce}'.",
        )


class DOMExecutionInvariant(CausalInvariant):
    """Evaluates context-aware DOM breakout and script execution."""

    def __init__(self, canary: str):
        super().__init__(
            invariant_id="INV-DOM-EXECUTION-01",
            name="DOM Script Execution Invariant",
            description="Verifies unescaped tag breakout vs harmless attribute reflection.",
        )
        self.canary = canary

    def evaluate(self, bundle: TriadBundle) -> InvariantEvaluationResult:
        e1 = bundle.experiment_1
        unescaped_pattern = r'<[^>]+' + re.escape(self.canary) + r'[^>]*>'
        if re.search(unescaped_pattern, e1.body, re.IGNORECASE):
            return InvariantEvaluationResult(
                passed=True,
                confidence=0.97,
                reason=f"DOM Execution Invariant satisfied: Canary '{self.canary}' broke out of HTML attribute context.",
                extracted_observables={"dom_breakout_confirmed": True},
            )
        return InvariantEvaluationResult(
            passed=False,
            confidence=0.15,
            reason="Canary remained safely encoded or inside quoted attribute.",
        )


class StateTransitionInvariant(CausalInvariant):
    """Evaluates business logic workflow transitions and sequence integrity."""

    def __init__(self, prerequisite_step: str, target_step: str):
        super().__init__(
            invariant_id=f"INV-SEQ-{prerequisite_step}-TO-{target_step}",
            name="Workflow Sequence Invariant",
            description="Ensures target state cannot be reached without executing prerequisite.",
        )
        self.prerequisite_step = prerequisite_step
        self.target_step = target_step

    def evaluate(self, bundle: TriadBundle) -> InvariantEvaluationResult:
        e1 = bundle.experiment_1
        if e1.status_code in (400, 409, 412, 422):
            return InvariantEvaluationResult(
                passed=True,
                confidence=0.95,
                reason=f"Workflow Sequence Invariant enforced: Target rejected skipping prerequisite '{self.prerequisite_step}'.",
                extracted_observables={"sequence_enforced": True},
            )
        elif e1.status_code in (200, 201):
            return InvariantEvaluationResult(
                passed=False,
                confidence=0.92,
                reason=f"Sequence Invariant Breached: '{self.target_step}' accepted without '{self.prerequisite_step}'.",
                invalidation_triggered=True,
                invalidation_detail="sequence_violation_permitted",
            )
        return InvariantEvaluationResult(
            passed=False,
            confidence=0.40,
            reason="Inconclusive workflow response status.",
        )


class CausalInvariantRegistry:
    """Registry allowing dynamic lookup and registration of causal invariants."""

    _invariants: Dict[str, CausalInvariant] = {}

    @classmethod
    def register(cls, invariant: CausalInvariant):
        cls._invariants[invariant.invariant_id] = invariant

    @classmethod
    def get(cls, invariant_id: str) -> Optional[CausalInvariant]:
        return cls._invariants.get(invariant_id)

    @classmethod
    def list_invariants(cls) -> List[Dict[str, Any]]:
        return [
            {"id": inv.invariant_id, "name": inv.name, "description": inv.description}
            for inv in cls._invariants.values()
        ]
