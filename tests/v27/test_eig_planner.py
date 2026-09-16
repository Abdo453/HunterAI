"""
Tests for Deterministic EIG Experiment Planner
"""
import pytest
from core.burp_gateway.experiment_contract import ExperimentContract
from core.reasoning.attack_surface_graph import AttackSurfaceGraph
from core.reasoning.eig_planner import (
    DeterministicEIGPlanner,
    PlanSelectionStatus,
)
from core.reasoning.negative_evidence import (
    BoundaryScope,
    NuancedNegativeEvidenceLedger,
)


def test_eig_planner_scope_and_boundary_filtering():
    graph = AttackSurfaceGraph(target_domain="app.target.local")
    negative_ledger = NuancedNegativeEvidenceLedger()

    planner = DeterministicEIGPlanner(
        surface_graph=graph,
        negative_ledger=negative_ledger,
        allowed_scope=["app.target.local", "/api/"],
        global_risk_budget=10.0,
    )

    c_out_of_scope = ExperimentContract(
        experiment_id="c_out",
        hypothesis_id="h_out",
        source_request_id="r1",
        target_endpoint="https://external-unauthorized.com/test",
    )
    p1 = planner.evaluate_and_enqueue(c_out_of_scope)
    assert p1.status == PlanSelectionStatus.SKIPPED_SCOPE

    scope = BoundaryScope(
        endpoint="/api/v1/users/42",
        http_method="GET",
        actor_id="guest",
        target_resource_id="42",
    )
    negative_ledger.record_defense(scope, status_code=403)

    c_defended = ExperimentContract(
        experiment_id="c_defended",
        hypothesis_id="h_def",
        source_request_id="r2",
        target_endpoint="/api/v1/users/42",
        identity_context="guest",
        mutation_plan={"resource_id": "42"},
    )
    p2 = planner.evaluate_and_enqueue(c_defended)
    assert p2.status == PlanSelectionStatus.PRUNED_NEGATIVE_BOUNDARY

    c_valid = ExperimentContract(
        experiment_id="c_valid",
        hypothesis_id="h_valid",
        source_request_id="r3",
        target_endpoint="/api/v1/users/43",
        identity_context="guest",
        mutation_plan={"resource_id": "43"},
        category="CROSS_TENANT_ISOLATION_BREACH",
    )
    p3 = planner.evaluate_and_enqueue(c_valid)
    assert p3.status == PlanSelectionStatus.SCHEDULED
    assert p3.composite_score > 0.0

    selected = planner.select_next_experiment()
    assert selected is not None
    assert selected.experiment_id == "c_valid"
