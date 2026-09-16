"""
Tests for AutonomousExperimentGenerator (V27.0)
"""
import pytest
from core.reasoning.experiment_generator import AutonomousExperimentGenerator
from core.reasoning.identity_matrix import IdentityMatrixEngine, IdentityPrincipal
from core.reasoning.state_machine_engine import ApplicationStateMachineEngine
from core.reasoning.workflow_graph import WorkflowGraphEngine, WorkflowStep


def test_experiment_generator_synthesizes_contracts_with_negative_observables():
    state_engine = ApplicationStateMachineEngine(target_domain="app.target.com")
    identity_engine = IdentityMatrixEngine()
    workflow_engine = WorkflowGraphEngine()

    # Setup identity matrix
    identity_engine.register_principal(IdentityPrincipal(
        principal_id="tenantA_user",
        tenant_id="tenant_A",
        role="MEMBER",
        session_token="tok_A",
        resource_ownership={"res_A_file"},
    ))
    identity_engine.register_principal(IdentityPrincipal(
        principal_id="tenantB_user",
        tenant_id="tenant_B",
        role="MEMBER",
        session_token="tok_B",
        resource_ownership={"res_B_file"},
    ))

    # Setup workflow
    workflow_engine.register_workflow("order_flow", [
        WorkflowStep(step_id="s1", name="Add Item", order_index=1, endpoint="/api/cart/add"),
        WorkflowStep(step_id="s2", name="Confirm Order", order_index=2, endpoint="/api/cart/confirm"),
        WorkflowStep(step_id="s3", name="Pay", order_index=3, endpoint="/api/cart/pay", http_method="POST"),
    ])

    generator = AutonomousExperimentGenerator(
        state_engine=state_engine,
        identity_engine=identity_engine,
        workflow_engine=workflow_engine,
        allowed_scope=["app.target.com", "/api/"],
    )

    contracts = generator.synthesize_all_candidate_contracts()
    assert len(contracts) > 0

    # Ensure EVERY contract has mandatory V27 fields
    for c in contracts:
        assert c.hypothesis_id != ""
        assert c.target_endpoint != ""
        assert c.negative_observables is not None
        assert "status_codes" in c.negative_observables
        assert "disproof_verdict" in c.negative_observables
        assert len(c.expected_invariants) > 0
        assert c.risk_budget > 0.0
