"""
End-to-End Multi-Tenant Integration Test (V27.0)
Simulates complete cycle:
  Traffic Observation -> State Inference -> Candidate Generation ->
  Bayesian Scheduling -> BCSL Execution Simulation -> Causal Adjudication ->
  Feedback Loop & Pruning
"""
import pytest
from core.burp_gateway.experiment_contract import ExperimentContract
from core.evidence_court import CausalTriad, CourtVerdict, EvidenceCourt
from core.reasoning.experiment_generator import AutonomousExperimentGenerator
from core.reasoning.experiment_scheduler import BayesianExperimentScheduler
from core.reasoning.feedback_loop import EvidenceFeedbackLoop
from core.reasoning.identity_matrix import AccessOutcome, IdentityMatrixEngine, IdentityPrincipal
from core.reasoning.state_machine_engine import ApplicationStateMachineEngine
from core.reasoning.workflow_graph import WorkflowGraphEngine, WorkflowStep


def test_v27_full_pipeline_e2e():
    # 1. Initialize Engines
    state_engine = ApplicationStateMachineEngine(target_domain="saas.target.local")
    identity_engine = IdentityMatrixEngine()
    workflow_engine = WorkflowGraphEngine()
    scheduler = BayesianExperimentScheduler(global_risk_budget=20.0)

    # 2. Ingest Multi-Tenant Traffic
    state_engine.ingest_transaction({
        "tx_id": "tx_t1_login",
        "url": "https://saas.target.local/auth/login",
        "method": "POST",
        "status_code": 200,
        "resp_headers": {"set-cookie": "sess=t1_cookie"},
        "resp_body": '{"tenant": "alpha", "role": "member"}',
    })
    p_alpha = IdentityPrincipal(principal_id="alpha_user", tenant_id="tenant_alpha", session_token="tok_alpha", resource_ownership={"vault_alpha_1"})
    p_beta = IdentityPrincipal(principal_id="beta_user", tenant_id="tenant_beta", session_token="tok_beta", resource_ownership={"vault_beta_1"})
    identity_engine.register_principal(p_alpha)
    identity_engine.register_principal(p_beta)

    workflow_engine.register_workflow("saas_billing", [
        WorkflowStep(step_id="step_create", name="Create Invoice", order_index=1, endpoint="/api/invoices/create"),
        WorkflowStep(step_id="step_review", name="Manager Review", order_index=2, endpoint="/api/invoices/review"),
        WorkflowStep(step_id="step_settle", name="Settle Funds", order_index=3, endpoint="/api/invoices/settle", http_method="POST"),
    ])

    # 3. Autonomous Experiment Synthesis
    generator = AutonomousExperimentGenerator(
        state_engine=state_engine,
        identity_engine=identity_engine,
        workflow_engine=workflow_engine,
        allowed_scope=["saas.target.local", "/api/"],
    )
    contracts = generator.synthesize_all_candidate_contracts()
    assert len(contracts) >= 2

    # 4. Bayesian Scheduling
    scheduler.enqueue_candidates(contracts)
    assert len(scheduler.queue) >= 2

    feedback_loop = EvidenceFeedbackLoop(
        identity_engine=identity_engine,
        state_engine=state_engine,
        scheduler=scheduler,
    )

    # 5. Execute Top Experiment (Cross-Tenant Probe)
    next_exp = scheduler.select_next_experiment()
    assert next_exp is not None

    judgment = EvidenceCourt.adjudicate(
        target_url=next_exp.target_endpoint,
        parameter="",
        vuln_class=next_exp.category,
        finder_claim={"hypothesis": next_exp.hypothesis_id},
        verifier_result={"reproduced": False, "status_code": 403, "response_body": '{"error": "forbidden"}'},
        negative_observables=next_exp.negative_observables,
        is_in_scope=True,
    )

    assert judgment.verdict == CourtVerdict.DISPROVED

    # 6. Online Feedback & Dynamic Pruning
    report = feedback_loop.process_judgment(next_exp, judgment)
    assert report["verdict"] == "DISPROVED"
    assert report["negative_ledger_size"] == 1
