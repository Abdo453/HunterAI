"""
Tests for EvidenceFeedbackLoop and NegativeEvidenceLedger (V27.0)
"""
import pytest
from core.burp_gateway.experiment_contract import ExperimentContract
from core.evidence_court import CourtJudgment, CourtVerdict, EvidenceCourt
from core.reasoning.experiment_scheduler import BayesianExperimentScheduler
from core.reasoning.feedback_loop import EvidenceFeedbackLoop, NegativeEvidenceLedger
from core.reasoning.identity_matrix import AccessOutcome, IdentityMatrixEngine, IdentityPrincipal
from core.reasoning.state_machine_engine import ApplicationStateMachineEngine


def test_feedback_loop_pruning_and_ledger_chaining():
    state_engine = ApplicationStateMachineEngine()
    identity_engine = IdentityMatrixEngine()
    scheduler = BayesianExperimentScheduler(global_risk_budget=20.0)
    ledger = NegativeEvidenceLedger()

    # Register principal and resource
    p1 = IdentityPrincipal(principal_id="user_A", tenant_id="t1", resource_ownership={"doc_A"})
    p2 = IdentityPrincipal(principal_id="user_B", tenant_id="t2", resource_ownership={"doc_B"})
    identity_engine.register_principal(p1)
    identity_engine.register_principal(p2)

    # Enqueue candidate experiments targeting doc_B
    contract1 = ExperimentContract(
        experiment_id="exp_b1",
        hypothesis_id="hyp_b1",
        source_request_id="req1",
        identity_context="user_A",
        target_endpoint="/api/resources/doc_B",
        mutation_plan={"resource_id": "doc_B"},
        category="CROSS_TENANT_ISOLATION_BREACH",
        risk_budget=0.4,
    )
    contract2 = ExperimentContract(
        experiment_id="exp_b2",
        hypothesis_id="hyp_b2",
        source_request_id="req2",
        identity_context="user_A",
        target_endpoint="/api/resources/doc_B",
        mutation_plan={"resource_id": "doc_B"},
        category="CROSS_TENANT_ISOLATION_BREACH",
        risk_budget=0.4,
    )
    scheduler.enqueue_candidates([contract1, contract2])

    feedback_loop = EvidenceFeedbackLoop(
        identity_engine=identity_engine,
        state_engine=state_engine,
        scheduler=scheduler,
        ledger=ledger,
    )

    # Simulate Court adjudication returning DISPROVED (403 Forbidden)
    judgment = CourtJudgment(
        target_url="/api/resources/doc_B",
        vuln_class="CROSS_TENANT_ISOLATION_BREACH",
        verdict=CourtVerdict.DISPROVED,
        adjudication_rationale="403 Forbidden received; boundary enforced",
        verifier_result={"status_code": 403},
    )

    report = feedback_loop.process_judgment(contract1, judgment)

    # 1. Identity Matrix cell updated to DENIED
    assert identity_engine.grid[("user_A", "doc_B")].outcome == AccessOutcome.DENIED

    # 2. Redundant experiment pruned from scheduler
    assert report["pruned_count"] >= 1
    assert len(scheduler.queue) == 0

    # 3. Negative Evidence Ledger chained
    assert len(ledger.chain) == 1
    rec = ledger.chain[0]
    assert rec.actor_principal_id == "user_A"
    assert rec.target_resource_id == "doc_B"
    assert rec.record_hash != ""
