"""
HunterAI V27.2 - Brain OODA Loop & Gateway/UI REST Endpoints Test Suite
========================================================================
Comprehensive verification for:
  1. AutonomousBrain.run_scan() OODA Loop integration:
     - Phase 0 (OBSERVE): Attack Surface Graph population
     - Phase 0.5 (ORIENT): Candidate violation edges registration
     - Phase 1 (DECIDE): Deterministic EIG Planner hypothesis prioritization
     - Phase 3 (VERIFY): Evidence Court & Tool Agreement updating surface graph and ledgers
     - run_scan() return payload (graph, ledger, integrity, eig metrics)
  2. BurpGateway REST APIs:
     - GET /api/v27/attack-surface
     - GET /api/v27/ledger/blocks
     - POST /api/v27/triad/execute
     - GET /api/v27/eig/queue
     - POST /api/v27/eig/enqueue
  3. Web UI FastAPI REST APIs:
     - GET /api/v27/attack-surface
     - GET /api/v27/ledger/blocks
     - POST /api/v27/triad/execute
     - GET /api/v27/eig/queue
     - POST /api/v27/eig/enqueue
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient

from core.brain.autonomous_brain import AutonomousBrain
from core.burp_gateway.capture_store import CaptureStore, CapturedTransaction
from core.burp_gateway.gateway import BurpGateway
from core.burp_gateway.traffic_normalizer import CanonicalRequest, CanonicalResponse
from ui.web.app import app, get_burp_gateway


@pytest.mark.asyncio
async def test_brain_ooda_loop_v27_telemetry():
    """Verifies that run_scan executes OODA phases and returns V27 epistemic telemetry."""
    rm = MagicMock()
    tm = MagicMock()
    brain = AutonomousBrain(resource_manager=rm, tool_manager=tm, dry_run=True)

    # Mock _fetch_target to return simple HTML with a form and link
    sample_html = """
    <html>
      <body>
        <a href="/products?category=books">Books</a>
        <form action="/search" method="GET">
          <input name="q" value="test" />
        </form>
      </body>
    </html>
    """
    brain._fetch_target = AsyncMock(return_value=(sample_html, 200, {"content-type": "text/html"}))
    brain._check_burp_online = AsyncMock(return_value=False)

    # Run scan
    res = await brain.run_scan(target="http://target.local", mode="quick", use_browser=False)

    # Verify return dict contains V27 artifacts
    assert "attack_surface_graph" in res
    assert "experiment_ledger" in res
    assert "experiment_ledger_integrity" in res
    assert "eig_planner_metrics" in res

    graph_data = res["attack_surface_graph"]
    assert graph_data is not None
    assert graph_data["nodes_count"] >= 1
    assert "http://target.local" in graph_data["nodes"]
    assert graph_data["nodes"]["http://target.local"]["epistemic_status"] == "OBSERVED"

    assert res["experiment_ledger_integrity"] is True
    assert res["eig_planner_metrics"]["global_risk_budget"] > 0


def test_burp_gateway_v27_endpoints(tmp_path):
    """Verifies BurpGateway V27 REST endpoints for AttackSurfaceGraph, Ledger, Triad, and EIG."""
    store = CaptureStore("gw_test", base_dir=tmp_path)
    gateway = BurpGateway(host="127.0.0.1", port=8085, capture_store=store)
    client = TestClient(gateway.app)

    # 1. GET /api/v27/attack-surface
    res_surface = client.get("/api/v27/attack-surface")
    assert res_surface.status_code == 200
    surf_json = res_surface.json()
    assert "nodes" in surf_json
    assert "status_distribution" in surf_json

    # 2. GET /api/v27/ledger/blocks (empty initially)
    res_ledger = client.get("/api/v27/ledger/blocks")
    assert res_ledger.status_code == 200
    ledger_json = res_ledger.json()
    assert ledger_json["is_valid"] is True
    assert ledger_json["blocks_count"] == 0

    # 3. POST /api/v27/eig/enqueue
    eig_contract_payload = {
        "hypothesis_id": "hypo_eig_test_01",
        "source_request_id": "tx_src_01",
        "target_endpoint": "http://target.local/api/test",
        "category": "COMMAND_INJECTION",
        "risk_budget": 0.5,
    }
    res_enqueue = client.post("/api/v27/eig/enqueue", json=eig_contract_payload)
    assert res_enqueue.status_code == 200
    assert res_enqueue.json()["status"] == "ENQUEUED"

    # 4. GET /api/v27/eig/queue
    res_queue = client.get("/api/v27/eig/queue")
    assert res_queue.status_code == 200
    q_json = res_queue.json()
    assert q_json["queue_length"] >= 1
    assert q_json["items"][0]["contract"]["hypothesis_id"] == "hypo_eig_test_01"

    # 5. POST /api/v27/triad/execute
    # Setup mock transport for Metamorphic Triad
    def mock_triad_transport(req: CanonicalRequest) -> CanonicalResponse:
        body = req.body or ""
        if "53+19" in body or "41+31" in body:
            return CanonicalResponse(status_code=200, body="PING 127.0.0.1\n72\nOK")
        elif "echo 53" in body:
            return CanonicalResponse(status_code=200, body="PING 127.0.0.1\n53\nOK")
        return CanonicalResponse(status_code=200, body="PING 127.0.0.1 (127.0.0.1)")

    gateway.bcsl.controller._http_transport_fn = mock_triad_transport

    triad_payload = {
        "hypothesis_id": "hypo_triad_cmd_01",
        "source_request_id": "tx_gw_triad_001",
        "target_endpoint": "http://target.local/api/ping",
        "control_mutation": {"body": "host=127.0.0.1; echo 53;"},
        "experiment_1_mutation": {"body": "host=127.0.0.1; echo $((53+19));"},
        "experiment_2_mutation": {"body": "host=127.0.0.1; echo $((41+31));"},
        "invariant_id": "CommandExecutionInvariant",
    }
    res_triad = client.post("/api/v27/triad/execute", json=triad_payload)
    assert res_triad.status_code == 200
    triad_json = res_triad.json()
    assert triad_json["execution_status"] == "EXECUTED"
    assert triad_json["triad_verification_result"]["epistemic_verdict"] == "CONFIRMED"

    # 6. Verify ledger has 1 cryptographically verified block
    res_ledger_after = client.get("/api/v27/ledger/blocks")
    assert res_ledger_after.status_code == 200
    ledger_after = res_ledger_after.json()
    assert ledger_after["blocks_count"] == 1
    assert ledger_after["is_valid"] is True
    assert ledger_after["blocks"][0]["hypothesis_id"] == "hypo_triad_cmd_01"

    # 7. Verify surface graph updated to CONFIRMED
    res_surface_after = client.get("/api/v27/attack-surface")
    assert res_surface_after.status_code == 200
    surf_after = res_surface_after.json()
    assert "http://target.local/api/ping" in surf_after["nodes"]
    assert surf_after["nodes"]["http://target.local/api/ping"]["epistemic_status"] == "CONFIRMED"


def test_web_ui_v27_endpoints():
    """Verifies Web UI FastAPI REST endpoints proxy to BurpGateway V27 components."""
    client = TestClient(app)
    gw = get_burp_gateway()

    # 1. GET /api/v27/attack-surface
    res_surface = client.get("/api/v27/attack-surface")
    assert res_surface.status_code == 200
    assert "nodes" in res_surface.json()

    # 2. GET /api/v27/ledger/blocks
    res_ledger = client.get("/api/v27/ledger/blocks")
    assert res_ledger.status_code == 200
    assert "is_valid" in res_ledger.json()
    assert res_ledger.json()["is_valid"] is True

    # 3. GET /api/v27/eig/queue
    res_queue = client.get("/api/v27/eig/queue")
    assert res_queue.status_code == 200
    assert "queue_length" in res_queue.json()

    # 4. POST /api/v27/eig/enqueue
    res_enqueue = client.post("/api/v27/eig/enqueue", json={
        "hypothesis_id": "hypo_ui_eig_01",
        "source_request_id": "tx_ui_01",
        "target_endpoint": "http://target.local/ui/test",
        "category": "SQLI",
        "risk_budget": 0.3,
    })
    assert res_enqueue.status_code == 200
    assert res_enqueue.json()["status"] == "ENQUEUED"

    # 5. POST /api/v27/triad/execute via UI
    def mock_ui_triad_transport(req: CanonicalRequest) -> CanonicalResponse:
        body = req.body or ""
        if "53+19" in body or "41+31" in body:
            return CanonicalResponse(status_code=200, body="PING 127.0.0.1\n72\nOK")
        elif "echo 53" in body:
            return CanonicalResponse(status_code=200, body="PING 127.0.0.1\n53\nOK")
        return CanonicalResponse(status_code=200, body="PING baseline")

    gw.bcsl.controller._http_transport_fn = mock_ui_triad_transport

    triad_payload = {
        "hypothesis_id": "hypo_ui_triad_01",
        "source_request_id": "tx_ui_triad_001",
        "target_endpoint": "http://target.local/api/ui_ping",
        "control_mutation": {"body": "host=127.0.0.1; echo 53;"},
        "experiment_1_mutation": {"body": "host=127.0.0.1; echo $((53+19));"},
        "experiment_2_mutation": {"body": "host=127.0.0.1; echo $((41+31));"},
        "invariant_id": "CommandExecutionInvariant",
    }
    res_triad = client.post("/api/v27/triad/execute", json=triad_payload)
    assert res_triad.status_code == 200
    assert res_triad.json()["execution_status"] == "EXECUTED"
    assert res_triad.json()["triad_verification_result"]["epistemic_verdict"] == "CONFIRMED"
