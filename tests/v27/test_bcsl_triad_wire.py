"""
HunterAI V27.1 - BCSL Metamorphic Triad Wire Execution Tests
=============================================================
Verifies that BurpControlSensorLayer executes 4-part Metamorphic Triad contracts:
  - B (Baseline), C (Control), E1 (Security Probe), E2 (Metamorphic Probe)
  - Strict scope policy enforcement
  - Invariant evaluation and 7-stage causal provenance
  - Contradiction and control equivalence isolation
"""
import pytest
from core.burp_gateway.bcsl import BurpControlSensorLayer
from core.burp_gateway.capture_store import CapturedTransaction
from core.burp_gateway.experiment_contract import TriadExperimentContract
from core.burp_gateway.traffic_normalizer import CanonicalRequest, CanonicalResponse
from core.controllers.burp_research_controller import BurpResearchController
from core.governance.risk_budget_queue import RiskBudgetManager
from core.reasoning.causal_invariants import CommandExecutionInvariant
from core.scope_guard import ScopeGuard


def test_bcsl_execute_triad_contract_success_confirmed():
    # Setup mock transport that simulates a vulnerable ping command injection
    def mock_http_transport(req: CanonicalRequest) -> CanonicalResponse:
        body = req.body
        if "53+19" in body or "41+31" in body:
            resp_body = "PING output\n72\nping finished"
        elif "echo 53" in body:
            resp_body = "PING output\n53\nping finished"
        else:
            resp_body = "PING 127.0.0.1: 64 bytes"
        return CanonicalResponse(status_code=200, body=resp_body)

    scope = ScopeGuard(in_scope=["target.local"], out_of_scope=["169.254.169.254"])
    risk = RiskBudgetManager()
    controller = BurpResearchController(
        scope_guard=scope,
        risk_budget_manager=risk,
        http_transport_fn=mock_http_transport,
    )
    bcsl = BurpControlSensorLayer(research_controller=controller, scope_guard=scope, risk_budget=risk)

    # Ingest baseline transaction
    tx_base = CapturedTransaction(
        tx_id="tx_base_ping_001",
        target_host="target.local",
        method="POST",
        url="http://target.local/api/tools/ping",
        status_code=200,
        req_body="host=127.0.0.1",
        resp_body="PING 127.0.0.1: 64 bytes",
    )
    bcsl.ingest_captured(tx_base)

    # Build 4-probe triad contract
    contract = TriadExperimentContract(
        hypothesis_id="hypo_cmd_exec_01",
        source_request_id="tx_base_ping_001",
        target_endpoint="http://target.local/api/tools/ping",
        http_method="POST",
        control_mutation={"body": "host=127.0.0.1; echo 53;"},
        experiment_1_mutation={"body": "host=127.0.0.1; echo $((53+19));"},
        experiment_2_mutation={"body": "host=127.0.0.1; echo $((41+31));"},
        expected_observation="Deterministic arithmetic evaluation 72 across metamorphic variations",
    )

    invariant = CommandExecutionInvariant(expected_token="72", e1_expr="53+19", e2_expr="41+31")
    record = bcsl.execute_triad_contract(contract, invariant=invariant)

    assert record.execution_status == "EXECUTED"
    assert record.triad_verification_result["epistemic_verdict"] == "CONFIRMED"
    assert record.triad_verification_result["is_causally_differentiated"] is True
    assert record.triad_verification_result["metamorphic_consistency"] is True
    assert record.triad_verification_result["contradiction_detected"] is False
    assert len(record.provenance) >= 7
    assert bool(record.audit_hash)
    assert record.experiment_1_response["status_code"] == 200
    assert "72" in record.experiment_1_response["body"]
    assert "72" in record.experiment_2_response["body"]
    assert "72" not in record.control_response["body"]


def test_bcsl_execute_triad_contract_scope_violation():
    scope = ScopeGuard(in_scope=["target.local"], out_of_scope=["169.254.169.254"])
    bcsl = BurpControlSensorLayer(scope_guard=scope)

    tx_base = CapturedTransaction(
        tx_id="tx_base_002",
        target_host="target.local",
        method="GET",
        url="http://target.local/index",
    )
    bcsl.ingest_captured(tx_base)

    contract = TriadExperimentContract(
        hypothesis_id="hypo_ssrf_01",
        source_request_id="tx_base_002",
        target_endpoint="http://169.254.169.254/latest/meta-data",
        control_mutation={"url": "http://169.254.169.254/latest/meta-data"},
        experiment_1_mutation={"url": "http://169.254.169.254/latest/meta-data"},
        experiment_2_mutation={"url": "http://169.254.169.254/latest/meta-data"},
    )

    record = bcsl.execute_triad_contract(contract)
    assert record.execution_status == "BLOCKED_SCOPE"
    assert record.triad_verification_result["epistemic_verdict"] == "REJECTED"
    assert record.triad_verification_result["is_causally_differentiated"] is False


def test_bcsl_execute_triad_contract_control_equivalence_rejected():
    # Both control and experiments return identical static responses -> Benign reflection / noise
    def mock_http_transport(req: CanonicalRequest) -> CanonicalResponse:
        return CanonicalResponse(status_code=200, body="Generic static response from web server")

    scope = ScopeGuard(in_scope=["target.local"])
    controller = BurpResearchController(scope_guard=scope, http_transport_fn=mock_http_transport)
    bcsl = BurpControlSensorLayer(research_controller=controller, scope_guard=scope)

    tx_base = CapturedTransaction(
        tx_id="tx_base_003",
        target_host="target.local",
        method="POST",
        url="http://target.local/api/tools/ping",
        status_code=200,
        req_body="host=127.0.0.1",
        resp_body="Generic static response from web server",
    )
    bcsl.ingest_captured(tx_base)

    contract = TriadExperimentContract(
        hypothesis_id="hypo_noisy_01",
        source_request_id="tx_base_003",
        target_endpoint="http://target.local/api/tools/ping",
        control_mutation={"body": "host=control_val"},
        experiment_1_mutation={"body": "host=probe_val_1"},
        experiment_2_mutation={"body": "host=probe_val_2"},
    )

    record = bcsl.execute_triad_contract(contract)
    assert record.execution_status == "EXECUTED"
    assert record.triad_verification_result["epistemic_verdict"] == "REJECTED"
    assert record.triad_verification_result["is_causally_differentiated"] is False


def test_bcsl_execute_triad_contract_metamorphic_contradiction():
    # E1 succeeds (72), but E2 fails to evaluate the metamorphic variation (contradiction!)
    def mock_http_transport(req: CanonicalRequest) -> CanonicalResponse:
        body = req.body
        if "53+19" in body:
            return CanonicalResponse(status_code=200, body="PING output\n72\nping finished")
        elif "41+31" in body:
            # Metamorphic failed to evaluate
            return CanonicalResponse(status_code=200, body="PING output\n41+31\nping finished")
        elif "echo 53" in body:
            return CanonicalResponse(status_code=200, body="PING output\n53\nping finished")
        return CanonicalResponse(status_code=200, body="PING 127.0.0.1")

    scope = ScopeGuard(in_scope=["target.local"])
    controller = BurpResearchController(scope_guard=scope, http_transport_fn=mock_http_transport)
    bcsl = BurpControlSensorLayer(research_controller=controller, scope_guard=scope)

    tx_base = CapturedTransaction(
        tx_id="tx_base_004",
        target_host="target.local",
        method="POST",
        url="http://target.local/api/tools/ping",
        status_code=200,
        req_body="host=127.0.0.1",
        resp_body="PING 127.0.0.1",
    )
    bcsl.ingest_captured(tx_base)

    contract = TriadExperimentContract(
        hypothesis_id="hypo_cmd_exec_contradictory",
        source_request_id="tx_base_004",
        target_endpoint="http://target.local/api/tools/ping",
        control_mutation={"body": "host=127.0.0.1; echo 53;"},
        experiment_1_mutation={"body": "host=127.0.0.1; echo $((53+19));"},
        experiment_2_mutation={"body": "host=127.0.0.1; echo $((41+31));"},
    )

    invariant = CommandExecutionInvariant(expected_token="72", e1_expr="53+19", e2_expr="41+31")
    record = bcsl.execute_triad_contract(contract, invariant=invariant)

    assert record.execution_status == "EXECUTED"
    assert record.triad_verification_result["epistemic_verdict"] == "PARTIALLY_VERIFIED"
    assert record.triad_verification_result["contradiction_detected"] is True
    assert record.triad_verification_result["is_causally_differentiated"] is False
