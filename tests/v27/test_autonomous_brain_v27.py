"""
HunterAI V27.1 - AutonomousBrain Integration Tests
==================================================
Verifies that AutonomousBrain properly initializes V27.1 engines:
  - attack_surface_graph
  - eig_planner
  - negative_ledger
  - experiment_ledger
  - triad_verifier
  - bcsl
  - execute_triad_experiment
"""
import pytest
from unittest.mock import MagicMock
from core.brain.autonomous_brain import AutonomousBrain
from core.burp_gateway.experiment_contract import TriadExperimentContract
from core.burp_gateway.capture_store import CapturedTransaction
from core.reasoning.causal_invariants import CommandExecutionInvariant
from core.burp_gateway.traffic_normalizer import CanonicalRequest, CanonicalResponse


def test_autonomous_brain_v27_engines_initialized():
    rm = MagicMock()
    tm = MagicMock()
    brain = AutonomousBrain(resource_manager=rm, tool_manager=tm)

    assert brain.attack_surface_graph is not None
    assert brain.eig_planner is not None
    assert brain.negative_ledger is not None
    assert brain.experiment_ledger is not None
    assert brain.triad_verifier is not None
    assert brain.bcsl is not None


def test_autonomous_brain_execute_triad_experiment():
    rm = MagicMock()
    tm = MagicMock()
    brain = AutonomousBrain(resource_manager=rm, tool_manager=tm)

    # Setup transport function on BCSL controller
    def mock_transport(req):
        body = req.body
        if "53+19" in body or "41+31" in body:
            return CanonicalResponse(status_code=200, body="PING 127.0.0.1\n72\n---")
        elif "echo 53" in body:
            return CanonicalResponse(status_code=200, body="PING 127.0.0.1\n53\n---")
        return CanonicalResponse(status_code=200, body="PING 127.0.0.1 (127.0.0.1)")

    brain.bcsl.controller._http_transport_fn = mock_transport

    # Ingest baseline
    tx_base = CapturedTransaction(
        tx_id="tx_brain_001",
        target_host="target.local",
        method="POST",
        url="http://target.local/api/ping",
        status_code=200,
        req_body="host=127.0.0.1",
        resp_body="PING 127.0.0.1",
    )
    brain.bcsl.ingest_captured(tx_base)

    contract = TriadExperimentContract(
        hypothesis_id="hypo_brain_cmd_01",
        source_request_id="tx_brain_001",
        target_endpoint="http://target.local/api/ping",
        control_mutation={"body": "host=127.0.0.1; echo 53;"},
        experiment_1_mutation={"body": "host=127.0.0.1; echo $((53+19));"},
        experiment_2_mutation={"body": "host=127.0.0.1; echo $((41+31));"},
    )

    invariant = CommandExecutionInvariant(expected_token="72", e1_expr="53+19", e2_expr="41+31")
    record = brain.execute_triad_experiment(contract, invariant=invariant)

    assert record.execution_status == "EXECUTED"
    assert record.triad_verification_result["epistemic_verdict"] == "CONFIRMED"
    assert len(brain.experiment_ledger) == 1
    is_valid, _ = brain.experiment_ledger.verify_chain_integrity()
    assert is_valid is True
