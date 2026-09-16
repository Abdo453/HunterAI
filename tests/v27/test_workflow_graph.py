"""
Tests for Business Logic Workflow Graph (V27.0)
"""
import pytest
from core.reasoning.workflow_graph import (
    CandidateTransitionType,
    CandidateWorkflowTransition,
    WorkflowGraphEngine,
    WorkflowStep,
)


def test_workflow_step_skipping_and_premature_generation():
    engine = WorkflowGraphEngine()

    steps = [
        WorkflowStep(step_id="step_register", name="Register Account", order_index=1, endpoint="/api/register"),
        WorkflowStep(step_id="step_verify_email", name="Verify Email", order_index=2, endpoint="/api/verify_email"),
        WorkflowStep(step_id="step_kyc", name="Submit KYC", order_index=3, endpoint="/api/kyc"),
        WorkflowStep(step_id="step_withdraw", name="Withdraw Funds", order_index=4, endpoint="/api/withdraw", http_method="POST"),
    ]

    engine.register_workflow("user_onboarding", steps)
    transitions = engine.generate_candidate_transitions("user_onboarding")

    types = [t.transition_type for t in transitions]
    assert CandidateTransitionType.STEP_SKIPPING in types
    assert CandidateTransitionType.PREMATURE_INVOCATION in types
    assert CandidateTransitionType.DOUBLE_EXECUTION in types

    # Verify that explicit negative observables are present
    for t in transitions:
        assert t.expected_negative_observable != ""
        assert "HTTP 400" in t.expected_negative_observable


def test_workflow_inference_from_traffic():
    engine = WorkflowGraphEngine()
    traffic = [
        {"url": "/cart/add", "method": "POST"},
        {"url": "/cart/checkout", "method": "GET"},
        {"url": "/cart/pay", "method": "POST"},
    ]
    engine.infer_workflow_from_traffic("ecommerce_flow", traffic)
    assert "ecommerce_flow" in engine.workflows
    assert len(engine.workflows["ecommerce_flow"]) == 3
