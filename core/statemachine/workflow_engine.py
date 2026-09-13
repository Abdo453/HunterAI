"""
HunterAI Advanced Business Logic & Workflow Invariant Engine
============================================================
Models and verifies complex multi-step application workflows:
- E-commerce & Checkout Funnels (Cart -> Discount -> Address -> Payment -> Order)
- Identity & Recovery Flows (Forgot Password -> OTP Request -> OTP Verify -> Password Reset)
- Subscription & Access Tiers (Trial -> Active -> Downgrade -> Feature Access)
- Organization & Role Governance (Invite -> Accept -> Assign Role -> Privileged Operation)

Detects:
1. Step Skipping (Bypassing payment/verification steps)
2. Re-entrancy / Replay (Double-spending discounts, coupon reuse, replay attacks)
3. State Confusion & Parameter Tampering across Funnels
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


class WorkflowFlawType(str, Enum):
    STEP_SKIPPING = "STEP_SKIPPING"
    RE_ENTRANCY = "RE_ENTRANCY"
    PARAMETER_TAMPERING = "PARAMETER_TAMPERING"
    STATE_CONFUSION = "STATE_CONFUSION"
    UNAUTHORIZED_TERMINAL_REACH = "UNAUTHORIZED_TERMINAL_REACH"


@dataclass
class WorkflowStep:
    step_id: str
    name: str
    route: str
    method: str = "POST"
    required_prerequisites: List[str] = field(default_factory=list)
    state_mutations: Dict[str, Any] = field(default_factory=dict)
    is_idempotent: bool = False
    is_terminal: bool = False
    description: str = ""


@dataclass
class WorkflowFlaw:
    flaw_id: str
    flaw_type: WorkflowFlawType
    step_id: str
    route: str
    description: str
    evidence_proof: str
    severity: str = "HIGH"
    cwe_id: str = "CWE-841"  # Improper Enforcement of Behavioral Workflow
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "flaw_id": self.flaw_id,
            "flaw_type": self.flaw_type.value,
            "step_id": self.step_id,
            "route": self.route,
            "description": self.description,
            "evidence_proof": self.evidence_proof,
            "severity": self.severity,
            "cwe_id": self.cwe_id,
            "timestamp": self.timestamp,
        }


class WorkflowGraph:
    """
    Directed Graph modeling multi-step business logic workflows.
    Maintains step nodes, permissible transitions, and invariant rules.
    """

    def __init__(self, workflow_name: str):
        self.workflow_name = workflow_name
        self.steps: Dict[str, WorkflowStep] = {}
        self.edges: Dict[str, Set[str]] = {}  # step_id -> set of allowed next step_ids
        self.invariants: List[Tuple[str, Callable[[Dict[str, Any], List[str]], bool]]] = []

    def add_step(self, step: WorkflowStep) -> WorkflowGraph:
        self.steps[step.step_id] = step
        if step.step_id not in self.edges:
            self.edges[step.step_id] = set()
        return self

    def add_transition(self, from_step_id: str, to_step_id: str) -> WorkflowGraph:
        if from_step_id not in self.steps or to_step_id not in self.steps:
            raise ValueError(f"Both steps must exist in workflow: {from_step_id} -> {to_step_id}")
        self.edges[from_step_id].add(to_step_id)
        # Add to prerequisites of target step if not already present
        if from_step_id not in self.steps[to_step_id].required_prerequisites:
            self.steps[to_step_id].required_prerequisites.append(from_step_id)
        return self

    def add_invariant(
        self,
        name: str,
        rule_fn: Callable[[Dict[str, Any], List[str]], bool]
    ) -> WorkflowGraph:
        """
        Adds a business logic invariant function taking:
        (session_state_dict, completed_steps_list) -> bool (True if valid, False if violated)
        """
        self.invariants.append((name, rule_fn))
        return self


class WorkflowAuditor:
    """
    Audits execution traces against formal WorkflowGraphs to detect
    step-skipping, replay attacks, and state confusion flaws.
    """

    def __init__(self, graph: WorkflowGraph):
        self.graph = graph

    def audit_trace(
        self,
        execution_trace: List[Dict[str, Any]],
        initial_session_state: Optional[Dict[str, Any]] = None
    ) -> List[WorkflowFlaw]:
        """
        Audits a sequence of action steps executed by a client.
        Each entry in execution_trace contains:
        {
            "step_id": str,
            "route": str,
            "status_code": int,
            "payload": Optional[dict],
            "response_body": Optional[str]
        }
        """
        flaws: List[WorkflowFlaw] = []
        completed_steps: List[str] = []
        step_execution_counts: Dict[str, int] = {}
        session_state: Dict[str, Any] = dict(initial_session_state or {})

        for idx, entry in enumerate(execution_trace):
            step_id = entry.get("step_id")
            route = entry.get("route", "unknown")
            status_code = entry.get("status_code", 200)
            payload = entry.get("payload", {})

            # Unknown step in this workflow
            if step_id not in self.graph.steps:
                # Check if route matches any step
                matching_step = next(
                    (s for s in self.graph.steps.values() if s.route == route),
                    None
                )
                if matching_step:
                    step_id = matching_step.step_id
                else:
                    continue

            target_step = self.graph.steps[step_id]
            step_execution_counts[step_id] = step_execution_counts.get(step_id, 0) + 1

            # 1. Check Step-Skipping (Prerequisites Check)
            missing_prereqs = [
                req for req in target_step.required_prerequisites
                if req not in completed_steps
            ]

            if missing_prereqs and status_code in (200, 201, 204):
                flaws.append(WorkflowFlaw(
                    flaw_id=f"FLAW-SKIP-{step_id[:6].upper()}-{idx}",
                    flaw_type=WorkflowFlawType.STEP_SKIPPING,
                    step_id=step_id,
                    route=route,
                    description=(
                        f"Step '{target_step.name}' was executed and accepted ({status_code}) "
                        f"without completing required prerequisite step(s): {missing_prereqs}."
                    ),
                    evidence_proof=(
                        f"Client jumped directly to route '{route}' at step {idx}. "
                        f"Completed steps before execution: {completed_steps}. "
                        f"Missing prerequisites: {missing_prereqs}."
                    ),
                    severity="HIGH" if not target_step.is_terminal else "CRITICAL",
                    cwe_id="CWE-841"
                ))

            # 2. Check Re-entrancy / Replay on non-idempotent operations
            if not target_step.is_idempotent and step_execution_counts[step_id] > 1:
                if status_code in (200, 201, 204):
                    flaws.append(WorkflowFlaw(
                        flaw_id=f"FLAW-REPLAY-{step_id[:6].upper()}-{idx}",
                        flaw_type=WorkflowFlawType.RE_ENTRANCY,
                        step_id=step_id,
                        route=route,
                        description=(
                            f"Non-idempotent step '{target_step.name}' was executed "
                            f"{step_execution_counts[step_id]} times without rejection."
                        ),
                        evidence_proof=(
                            f"Step '{step_id}' at route '{route}' succeeded multiple times ({status_code}) "
                            f"in the same workflow session. Potential double-spend or duplicate discount."
                        ),
                        severity="HIGH",
                        cwe_id="CWE-674"
                    ))

            # Update session state with mutations declared on the step
            session_state.update(target_step.state_mutations)
            if isinstance(payload, dict):
                session_state.update(payload)

            if status_code in (200, 201, 204):
                completed_steps.append(step_id)

            # 3. Check Declarative Invariants
            for inv_name, rule_fn in self.graph.invariants:
                if not rule_fn(session_state, completed_steps):
                    flaws.append(WorkflowFlaw(
                        flaw_id=f"FLAW-INV-{inv_name[:8].upper()}-{idx}",
                        flaw_type=WorkflowFlawType.PARAMETER_TAMPERING,
                        step_id=step_id,
                        route=route,
                        description=f"Workflow invariant '{inv_name}' was violated during execution.",
                        evidence_proof=(
                            f"State {session_state} at step {idx} failed invariant rule '{inv_name}'."
                        ),
                        severity="HIGH",
                        cwe_id="CWE-841"
                    ))

        return flaws


# Built-in Standard Workflows for Rapid Testing & Benchmarking
def create_standard_checkout_workflow() -> WorkflowGraph:
    """Standard 4-step e-commerce checkout workflow"""
    g = WorkflowGraph("E-Commerce Checkout")
    g.add_step(WorkflowStep(
        step_id="STEP_ADD_CART",
        name="Add Items to Cart",
        route="/api/cart/add",
        state_mutations={"cart_initialized": True, "total_price": 100.0}
    ))
    g.add_step(WorkflowStep(
        step_id="STEP_APPLY_DISCOUNT",
        name="Apply Discount Coupon",
        route="/api/cart/coupon",
        is_idempotent=False,
        state_mutations={"discount_applied": True}
    ))
    g.add_step(WorkflowStep(
        step_id="STEP_SHIPPING",
        name="Select Shipping Method",
        route="/api/checkout/shipping",
        state_mutations={"shipping_selected": True}
    ))
    g.add_step(WorkflowStep(
        step_id="STEP_PAYMENT",
        name="Authorize Payment",
        route="/api/checkout/pay",
        is_idempotent=False,
        state_mutations={"payment_settled": True}
    ))
    g.add_step(WorkflowStep(
        step_id="STEP_ORDER_COMPLETE",
        name="Order Confirmation",
        route="/api/order/complete",
        is_terminal=True,
        state_mutations={"order_confirmed": True}
    ))

    # Standard transitions
    g.add_transition("STEP_ADD_CART", "STEP_SHIPPING")
    g.add_transition("STEP_ADD_CART", "STEP_APPLY_DISCOUNT")
    g.add_transition("STEP_APPLY_DISCOUNT", "STEP_SHIPPING")
    g.add_transition("STEP_SHIPPING", "STEP_PAYMENT")
    g.add_transition("STEP_PAYMENT", "STEP_ORDER_COMPLETE")

    # Invariant: Terminal confirmation requires payment_settled == True and total_price >= 0
    g.add_invariant(
        "payment_must_precede_confirmation",
        lambda state, steps: not (
            "STEP_ORDER_COMPLETE" in steps and not state.get("payment_settled", False)
        )
    )
    g.add_invariant(
        "total_price_non_negative",
        lambda state, steps: float(state.get("total_price", 0.0)) >= 0.0
    )

    return g


def create_standard_password_reset_workflow() -> WorkflowGraph:
    """Standard 4-step password recovery workflow"""
    g = WorkflowGraph("Password Recovery")
    g.add_step(WorkflowStep(
        step_id="STEP_REQUEST_RESET",
        name="Request Password Reset",
        route="/auth/password/reset/request",
        state_mutations={"reset_requested": True}
    ))
    g.add_step(WorkflowStep(
        step_id="STEP_VERIFY_OTP",
        name="Verify Recovery Code",
        route="/auth/password/reset/verify",
        is_idempotent=False,
        state_mutations={"otp_verified": True}
    ))
    g.add_step(WorkflowStep(
        step_id="STEP_SET_PASSWORD",
        name="Set New Password",
        route="/auth/password/reset/confirm",
        is_terminal=True,
        state_mutations={"password_updated": True}
    ))

    g.add_transition("STEP_REQUEST_RESET", "STEP_VERIFY_OTP")
    g.add_transition("STEP_VERIFY_OTP", "STEP_SET_PASSWORD")

    g.add_invariant(
        "otp_required_before_reset",
        lambda state, steps: not (
            "STEP_SET_PASSWORD" in steps and not state.get("otp_verified", False)
        )
    )

    return g
