"""
Tests for BayesianExperimentScheduler (V27.0)
"""
import pytest
from core.burp_gateway.experiment_contract import ExperimentContract
from core.reasoning.experiment_scheduler import (
    BayesianExperimentScheduler,
    ExperimentQueueStatus,
    ScheduledExperiment,
)


def test_scheduler_bayesian_ranking_and_prioritization():
    scheduler = BayesianExperimentScheduler(global_risk_budget=10.0)

    c1 = ExperimentContract(
        experiment_id="exp_idor_1",
        hypothesis_id="hyp_idor",
        source_request_id="req1",
        target_endpoint="/api/resources/42",
        category="CROSS_TENANT_ISOLATION_BREACH",
        risk_budget=0.4,
    )
    c2 = ExperimentContract(
        experiment_id="exp_tamper_2",
        hypothesis_id="hyp_tamper",
        source_request_id="req2",
        target_endpoint="/api/orders/tamper",
        category="POST_COMPLETION_TAMPER",
        risk_budget=0.8,
    )

    scheduler.enqueue_candidates([c1, c2])

    # Top item in queue must be CROSS_TENANT (higher evidence value and lower risk)
    top_contract = scheduler.select_next_experiment()
    assert top_contract is not None
    assert top_contract.experiment_id == "exp_idor_1"


def test_scheduler_risk_budget_exhaustion():
    scheduler = BayesianExperimentScheduler(global_risk_budget=0.5)

    c1 = ExperimentContract(
        experiment_id="exp_heavy_1",
        hypothesis_id="hyp_heavy_1",
        source_request_id="req1",
        target_endpoint="/api/heavy",
        category="DOUBLE_EXECUTION",
        risk_budget=0.4,
    )
    c2 = ExperimentContract(
        experiment_id="exp_heavy_2",
        hypothesis_id="hyp_heavy_2",
        source_request_id="req2",
        target_endpoint="/api/heavy_2",
        category="DOUBLE_EXECUTION",
        risk_budget=0.4,
    )

    scheduler.enqueue_candidates([c1, c2])

    # First experiment allowed
    e1 = scheduler.select_next_experiment()
    assert e1 is not None
    scheduler.record_execution_result(e1, verdict="DISPROVED", is_proven_vulnerability=False)

    # Second experiment exceeds budget (0.4 + 0.4 = 0.8 > 0.5)
    e2 = scheduler.select_next_experiment()
    assert e2 is None


def test_scheduler_online_pruning():
    scheduler = BayesianExperimentScheduler(global_risk_budget=20.0)

    contracts = [
        ExperimentContract(
            experiment_id=f"exp_cross_{i}",
            hypothesis_id=f"hyp_{i}",
            source_request_id=f"req_{i}",
            target_endpoint="/api/tenant/documents",
            category="CROSS_TENANT_ISOLATION_BREACH",
            risk_budget=0.4,
        )
        for i in range(5)
    ]
    scheduler.enqueue_candidates(contracts)
    assert len(scheduler.queue) == 5

    # Prune all experiments on /api/tenant/documents
    pruned = scheduler.prune_equivalent_experiments(
        category="CROSS_TENANT_ISOLATION_BREACH",
        target_endpoint="/api/tenant/documents",
        reason="Boundary confirmed 403",
    )
    assert pruned == 5
    assert len(scheduler.queue) == 0
