import json
import socket
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
import pytest

from core.burp_gateway.bcsl import BurpControlSensorLayer
from core.burp_gateway.capture_store import CapturedTransaction
from core.burp_gateway.experiment_contract import TriadExperimentContract
from core.burp_gateway.traffic_normalizer import CanonicalRequest, CanonicalResponse
from core.controllers.burp_research_controller import BurpResearchController
from core.reasoning.causal_invariants import CommandExecutionInvariant
from core.reasoning.experiment_ledger import TamperEvidentExperimentLedger, ExperimentRecord
from core.scope_guard import ScopeGuard
import urllib.request


class RealWireLabHandler(BaseHTTPRequestHandler):
    """
    Real HTTP Request Handler running on an actual TCP socket.
    Serves physical HTTP responses to test genuine network wire transmission.
    """
    def log_message(self, format, *args):
        # Suppress noisy standard HTTP logs during tests
        pass

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else ""
        path = urlparse(self.path).path

        if path == "/api/v1/ping":
            # Command injection vulnerable endpoint
            if "$((53+19))" in body or "$((41+31))" in body:
                resp = "PING 127.0.0.1 (127.0.0.1)\n72\n"
            elif "echo 53" in body:
                resp = "PING 127.0.0.1 (127.0.0.1)\n53\n"
            else:
                resp = "PING 127.0.0.1 (127.0.0.1): 56 data bytes\n64 bytes from 127.0.0.1: icmp_seq=0\n"

            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(resp.encode("utf-8"))))
            self.end_headers()
            self.wfile.write(resp.encode("utf-8"))

        elif path == "/api/v1/safe_profile":
            # Negative control / False Positive Trap
            # Input is safely reflected as literal text; arithmetic is NOT executed!
            params = parse_qs(body)
            name_val = params.get("name", [""])[0]
            resp_data = {"status": "ok", "profile": {"name": name_val, "sanitized": True}}
            resp = json.dumps(resp_data)

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp.encode("utf-8"))))
            self.end_headers()
            self.wfile.write(resp.encode("utf-8"))

        else:
            self.send_response(404)
            self.end_headers()


@pytest.fixture(scope="module")
def wire_server():
    """Binds an actual TCP socket on localhost and runs HTTPServer in a background thread."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    server = HTTPServer(("127.0.0.1", port), RealWireLabHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    base_url = f"http://127.0.0.1:{port}"
    yield base_url

    server.shutdown()
    server.server_close()


def test_real_wire_metamorphic_triad_vulnerable_endpoint(wire_server):
    """
    Executes a real physical Metamorphic Triad (B x C x E1 x E2) over real TCP sockets.
    Tests:
      - Physical network latency > 0.000s
      - B (baseline) produces ping output
      - C (control) produces 53
      - E1 (experiment 1) produces 72
      - E2 (experiment 2) produces 72
      - Verifier returns CONFIRMED
      - Cryptographic ledger records block with valid SHA-256 chain
    """
    scope = ScopeGuard(in_scope=["127.0.0.1"])
    controller = BurpResearchController(scope_guard=scope)

    # Physical wire transport function sending real HTTP requests over the network socket
    def real_wire_transport(req: CanonicalRequest) -> CanonicalResponse:
        t_start = time.perf_counter()
        data = req.body.encode("utf-8") if req.body else None
        headers = dict(req.headers)
        if data is not None:
            headers["Content-Length"] = str(len(data))
        h_req = urllib.request.Request(req.url, data=data, headers=headers, method=req.method)
        try:
            with urllib.request.urlopen(h_req, timeout=5.0) as resp:
                status = resp.status
                body = resp.read().decode("utf-8", errors="replace")
                r_headers = dict(resp.headers)
        except urllib.error.HTTPError as e:
            status = e.code
            body = e.read().decode("utf-8", errors="replace")
            r_headers = dict(e.headers)
        r_time = time.perf_counter() - t_start
        return CanonicalResponse(status_code=status, headers=r_headers, body=body, round_trip_ms=r_time * 1000.0)

    controller._http_transport_fn = real_wire_transport
    bcsl = BurpControlSensorLayer(research_controller=controller, scope_guard=scope)
    ledger = TamperEvidentExperimentLedger()

    target_url = f"{wire_server}/api/v1/ping"

    # Ingest captured baseline
    tx_base = CapturedTransaction(
        tx_id="tx_real_wire_001",
        target_host="127.0.0.1",
        method="POST",
        url=target_url,
        status_code=200,
        req_body="host=127.0.0.1",
        resp_body="PING 127.0.0.1 (127.0.0.1)",
    )
    bcsl.ingest_captured(tx_base)

    contract = TriadExperimentContract(
        hypothesis_id="hypo_wire_cmdi_01",
        source_request_id="tx_real_wire_001",
        target_endpoint=target_url,
        control_mutation={"body": "host=127.0.0.1; echo 53;"},
        experiment_1_mutation={"body": "host=127.0.0.1; echo $((53+19));"},
        experiment_2_mutation={"body": "host=127.0.0.1; echo $((41+31));"},
    )

    invariant = CommandExecutionInvariant(expected_token="72", e1_expr="53+19", e2_expr="41+31")
    t0 = time.perf_counter()
    record = bcsl.execute_triad_contract(contract, invariant=invariant)
    duration = time.perf_counter() - t0

    # 1. Physical execution verification
    assert record.execution_status == "EXECUTED"
    assert duration > 0.0005, "Execution must measure real physical wire latency (>0.0005s)"
    assert record.baseline_response.get("round_trip_ms", 0.0) >= 0.0

    # 2. Epistemic verification over real wire
    assert record.triad_verification_result["epistemic_verdict"] == "CONFIRMED"
    assert record.invariant_result["passed"] is True
    assert record.invariant_result["confidence"] >= 0.90

    # 3. Append to Tamper-Evident Ledger
    exp_rec = ExperimentRecord(
        experiment_id=record.triad_id,
        hypothesis_id=record.hypothesis_id,
        source_transaction={"target": target_url},
        observations=[record.triad_verification_result["rationale"]],
        causal_strength=0.95,
        execution_provenance=[{"stage": p} for p in record.provenance],
    )
    ledger.append(exp_rec)
    assert len(ledger) == 1
    is_valid, _ = ledger.verify_chain_integrity()
    assert is_valid is True


def test_real_wire_metamorphic_triad_safe_negative_control(wire_server):
    """
    Executes a real physical Metamorphic Triad against the Safe Negative Control trap.
    Proves:
      - Reflection != Execution
      - The server reflects 'name=53+19' verbatim in JSON without evaluating to 72
      - The verifier returns UNVERIFIED (never CONFIRMED)
      - Zero False Positive is mathematically enforced over real physical wire traffic
    """
    scope = ScopeGuard(in_scope=["127.0.0.1"])
    controller = BurpResearchController(scope_guard=scope)

    def real_wire_transport(req: CanonicalRequest) -> CanonicalResponse:
        t_start = time.perf_counter()
        data = req.body.encode("utf-8") if req.body else None
        headers = dict(req.headers)
        if data is not None:
            headers["Content-Length"] = str(len(data))
        h_req = urllib.request.Request(req.url, data=data, headers=headers, method=req.method)
        try:
            with urllib.request.urlopen(h_req, timeout=5.0) as resp:
                status = resp.status
                body = resp.read().decode("utf-8", errors="replace")
                r_headers = dict(resp.headers)
        except urllib.error.HTTPError as e:
            status = e.code
            body = e.read().decode("utf-8", errors="replace")
            r_headers = dict(e.headers)
        r_time = time.perf_counter() - t_start
        return CanonicalResponse(status_code=status, headers=r_headers, body=body, round_trip_ms=r_time * 1000.0)

    controller._http_transport_fn = real_wire_transport
    bcsl = BurpControlSensorLayer(research_controller=controller, scope_guard=scope)

    target_url = f"{wire_server}/api/v1/safe_profile"

    tx_base = CapturedTransaction(
        tx_id="tx_real_wire_safe_002",
        target_host="127.0.0.1",
        method="POST",
        url=target_url,
        status_code=200,
        req_body="name=john",
        resp_body='{"status": "ok", "profile": {"name": "john", "sanitized": true}}',
    )
    bcsl.ingest_captured(tx_base)

    # Attempt invariant breach against safe profile
    contract = TriadExperimentContract(
        hypothesis_id="hypo_wire_safe_trap_02",
        source_request_id="tx_real_wire_safe_002",
        target_endpoint=target_url,
        control_mutation={"body": "name=53"},
        experiment_1_mutation={"body": "name=$((53+19))"},
        experiment_2_mutation={"body": "name=$((41+31))"},
    )

    invariant = CommandExecutionInvariant(expected_token="72", e1_expr="53+19", e2_expr="41+31")
    record = bcsl.execute_triad_contract(contract, invariant=invariant)

    # In safe trap: Token '72' was NEVER produced (only literal $((53+19)) was reflected)
    assert record.execution_status == "EXECUTED"
    assert record.triad_verification_result["epistemic_verdict"] != "CONFIRMED"
    assert record.triad_verification_result["epistemic_verdict"] in ("UNVERIFIED", "PARTIALLY_VERIFIED")
    assert record.invariant_result["passed"] is False
    assert "token '72' absent" in record.invariant_result["reason"].lower()
