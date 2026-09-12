"""
Unit Tests for HunterAI Burp Suite Gateway & Bridge Subsystem
=============================================================
Verifies:
1. CaptureStore (engagement directory layout, stream persistence, identity/parameter extraction)
2. TaskQueue (context-menu task dispatch, priority queue, status transitions)
3. BurpIssueExporter (converts Evidence Court findings to Burp IScanIssue schema)
4. BurpGateway REST API (/health, /api/traffic, /api/tasks, /api/scope, /api/issues/export)
"""
import asyncio
import json
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from core.burp_gateway.capture_store import CaptureStore, CapturedTransaction
from core.burp_gateway.issue_exporter import BurpIssueExporter
from core.burp_gateway.task_queue import BurpTask, TaskAction, TaskQueue, TaskStatus
from core.burp_gateway.gateway import BurpGateway
from core.burp_gateway.provenance import EvidenceProvenanceEngine, ProvenanceStage, ProvenanceTrace
from core.burp_gateway.handoff_contract import AgentHandoffContract
from core.evidence_court import EvidenceCourt, CourtVerdict


def test_capture_store_lifecycle(tmp_path):
    store = CaptureStore("target.com", base_dir=tmp_path)

    tx = CapturedTransaction(
        tx_id="tx_test_01",
        target_host="target.com",
        method="GET",
        url="https://target.com/api/v1/users/42?filter=active",
        status_code=200,
        req_headers={"Authorization": "Bearer eyJhbGciOi...", "User-Agent": "Mozilla/5.0"},
        req_body="",
        resp_headers={"Content-Type": "application/json"},
        resp_body='{"id": 42, "name": "Alice"}',
        tool_source="proxy"
    )

    tx_id = store.store_transaction(tx)
    assert tx_id == "tx_test_01"

    # Check filesystem persistence
    assert (tmp_path / "target_com" / "requests" / "tx_test_01.json").exists()
    assert (tmp_path / "target_com" / "responses" / "tx_test_01.json").exists()

    # Check endpoint and parameter extraction
    assert "https://target.com/api/v1/users/42" in store.endpoints
    assert "filter" in store.parameters

    # Check identity mapping
    assert len(store.identities) == 1
    id_key = list(store.identities.keys())[0]
    assert id_key.startswith("BEARER_")

    # Add hypothesis and finding
    store.add_hypothesis(
        vuln_type="BOLA",
        endpoint="/api/v1/users/42",
        rationale="Object ID exposed in URL with Bearer auth",
        required_evidence=["Cross-tenant ID probe", "Different auth context"]
    )
    assert len(store.hypotheses) == 1

    store.record_finding({
        "title": "BOLA / IDOR in User Profile",
        "severity": "High",
        "lifecycle_verdict": "CONFIRMED",
        "endpoint": "https://target.com/api/v1/users/42"
    })
    assert len(store.findings) == 1
    assert len(store.timeline) >= 2


@pytest.mark.asyncio
async def test_task_queue_execution():
    executed_tasks = []

    async def mock_executor(task: BurpTask):
        executed_tasks.append(task)
        return {"status": "SUCCESS", "target": task.target_url}

    queue = TaskQueue(executor_fn=mock_executor)
    await queue.start()

    task = queue.enqueue(TaskAction.SCAN, "https://target.com", {"mode": "full"})
    assert task.status == TaskStatus.QUEUED

    # Wait briefly for worker execution
    await asyncio.sleep(0.1)

    t_done = queue.get_task(task.task_id)
    assert t_done.status == TaskStatus.COMPLETED
    assert t_done.result["status"] == "SUCCESS"
    assert len(executed_tasks) == 1

    await queue.stop()


def test_burp_issue_exporter():
    finding = {
        "title": "OS Command Injection via Ping Parameter",
        "type": "cmd_injection",
        "severity": "Critical",
        "lifecycle_verdict": "CONFIRMED",
        "endpoint": "https://api.target.com/v1/tools/ping",
        "payload_used": "; echo $((53+19));",
        "evidence": "Arithmetic evaluation strictly evaluated to 72 in HTTP response.",
        "remediation": "Use subprocess with shell=False and strict whitelist validation.",
        "raw_request": "POST /v1/tools/ping HTTP/1.1\r\nHost: api.target.com\r\n\r\nhost=127.0.0.1; echo $((53+19));",
        "raw_response": "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n72"
    }

    issue = BurpIssueExporter.format_finding_for_burp(finding)
    assert "[HunterAI] OS Command Injection" in issue["issue_name"]
    assert issue["severity"] == "High"  # Mapped from Critical
    assert issue["confidence"] == "Certain"  # Mapped from CONFIRMED
    assert issue["host"] == "api.target.com"
    assert "HunterAI Evidence Court Verdict" in issue["issue_detail"]
    assert len(issue["http_messages"]) == 1
    assert "72" in issue["http_messages"][0]["response"]


def test_burp_gateway_rest_api(tmp_path):
    store = CaptureStore("test_target", base_dir=tmp_path)
    gateway = BurpGateway(host="127.0.0.1", port=8085, capture_store=store)
    client = TestClient(gateway.app)

    # 1. Health check
    res_health = client.get("/health")
    assert res_health.status_code == 200
    assert res_health.json()["status"] == "online"

    # 2. Ingest traffic
    payload = {
        "host": "api.test.local",
        "port": 443,
        "protocol": "https",
        "request": "POST /api/v1/login HTTP/1.1\r\nHost: api.test.local\r\n\r\nuser=admin&pass=secret",
        "response": "HTTP/1.1 200 OK\r\nSet-Cookie: session=xyz123\r\n\r\n{\"token\": \"ok\"}",
        "tool": "proxy"
    }
    res_traffic = client.post("/api/traffic", json=payload)
    assert res_traffic.status_code == 200
    assert res_traffic.json()["status"] == "INGESTED"

    # 3. Create context-menu task
    task_payload = {
        "action": "SCAN",
        "target_url": "https://api.test.local/api/v1/login",
        "payload": {"method": "POST"}
    }
    res_task = client.post("/api/tasks", json=task_payload)
    assert res_task.status_code == 200
    assert res_task.json()["status"] == "QUEUED"

    # List tasks
    res_tasks = client.get("/api/tasks")
    assert len(res_tasks.json()["tasks"]) >= 1

    # 4. Scope update
    res_scope = client.post("/api/scope", json={"host": "api.test.local"})
    assert res_scope.status_code == 200
    assert "api.test.local" in res_scope.json()["scope"]["include"]

    # 5. Native Burp issue ingestion
    burp_issue = {
        "name": "SQL Injection",
        "url": "https://api.test.local/search?q=test",
        "severity": "High"
    }
    res_burp_iss = client.post("/api/issues/burp", json=burp_issue)
    assert res_burp_iss.status_code == 200

    # 6. Export confirmed findings to Burp Target tab
    gateway.register_confirmed_finding({
        "title": "SQLi in search parameter",
        "severity": "High",
        "lifecycle_verdict": "CONFIRMED",
        "endpoint": "https://api.test.local/search"
    })
    res_export = client.get("/api/issues/export")
    assert res_export.status_code == 200
    assert res_export.json()["issues_count"] == 1
    assert "[HunterAI] SQLi in search parameter" in res_export.json()["issues"][0]["issue_name"]

    # 7. Lineage endpoint
    res_lineage = client.get(f"/api/traffic/{res_traffic.json()['tx_id']}/lineage")
    assert res_lineage.status_code == 200
    assert res_lineage.json()["lineage_depth"] == 1

    # 8. Case contract endpoint
    case_payload = {
        "case_id": "case_api_01",
        "target": "api.test.local",
        "endpoint": "/api/v1/login",
        "vuln_class": "sqli",
        "status": "OPEN",
        "source_agent": "WebAgent",
        "assigned_agent": "VerifierAgent"
    }
    res_case = client.post("/api/cases", json=case_payload)
    assert res_case.status_code == 200
    assert res_case.json()["case_id"] == "case_api_01"

    res_get_case = client.get("/api/cases/case_api_01")
    assert res_get_case.status_code == 200
    assert res_get_case.json()["assigned_agent"] == "VerifierAgent"


def test_request_lineage_and_session_context(tmp_path):
    store = CaptureStore("target.local", base_dir=tmp_path)

    # Request 1: Login
    tx1 = CapturedTransaction(
        tx_id="req_01_login",
        target_host="target.local",
        method="POST",
        url="https://target.local/api/login",
        status_code=200,
        req_headers={"Content-Type": "application/json"},
        req_body='{"user": "admin", "pass": "secret"}',
        resp_headers={"Set-Cookie": "session=tok123; Path=/", "Content-Type": "application/json"},
        resp_body='{"token": "tok123"}'
    )
    store.store_transaction(tx1)
    assert "user" in tx1.parameter_ids
    assert tx1.cookies.get("session") == "tok123"

    # Request 2: Profile list (Child of Login)
    tx2 = CapturedTransaction(
        tx_id="req_02_users",
        parent_request="req_01_login",
        target_host="target.local",
        method="GET",
        url="https://target.local/api/users?page=1",
        status_code=200,
        req_headers={"Cookie": "session=tok123"},
        resp_headers={"Content-Type": "application/json"},
        resp_body='[{"id": 42}]'
    )
    store.store_transaction(tx2)
    assert "page" in tx2.parameter_ids

    # Request 3: Specific vulnerable profile (Child of Profile list)
    tx3 = CapturedTransaction(
        tx_id="req_03_profile",
        parent_request="req_02_users",
        target_host="target.local",
        method="GET",
        url="https://target.local/api/users/42?debug=true",
        status_code=200,
        req_headers={"Cookie": "session=tok123"},
        resp_headers={"Content-Type": "application/json"},
        resp_body='{"id": 42, "role": "admin"}'
    )
    store.store_transaction(tx3)

    # Verify Lineage Traversal
    lineage = store.get_request_lineage("req_03_profile")
    assert len(lineage) == 3
    assert lineage[0]["tx_id"] == "req_01_login"
    assert lineage[1]["tx_id"] == "req_02_users"
    assert lineage[2]["tx_id"] == "req_03_profile"


def test_evidence_provenance_engine():
    engine = EvidenceProvenanceEngine()
    trace = engine.create_trace(
        target="https://target.local/api/search",
        vuln_class="sqli",
        case_id="case_sqli_01",
        initial_observation="Single quote provoked 500 internal error differential"
    )

    # Verify initial step
    assert len(trace.steps) == 1
    assert trace.steps[0].stage == ProvenanceStage.OBSERVATION

    # Add downstream causal steps
    trace.add_step(ProvenanceStage.BURP_REQUEST, "Repeater request with test' payload", {"param": "q"})
    trace.add_step(ProvenanceStage.BURP_RESPONSE, "500 syntax error from SQL engine", {"status": 500})
    trace.add_step(ProvenanceStage.ANALYSIS, "DOM difference confirms unhandled error branch", {"delta": 0.85})
    trace.add_step(ProvenanceStage.HYPOTHESIS, "Hypothesized classic error-based SQL injection", {"confidence": 0.8})
    trace.add_step(ProvenanceStage.TEST, "Injected arithmetic boolean probe ' AND 53=53--", {"payload": "53=53"})
    trace.add_step(ProvenanceStage.VERIFICATION, "Arithmetic condition reflected 200 OK deterministically", {"proof": "200"})

    # Verify integrity
    is_valid, errors = trace.verify_integrity()
    assert is_valid is True
    assert len(errors) == 0
    assert len(trace.steps) == 7

    # ASCII flow verification
    ascii_repr = trace.to_ascii_flow()
    assert "OBSERVATION" in ascii_repr
    assert "VERIFICATION" in ascii_repr

    # Test out-of-order detection
    broken_trace = ProvenanceTrace(target="https://bad.local")
    broken_trace.add_step(ProvenanceStage.VERIFICATION, "Premature verification without test")
    broken_trace.add_step(ProvenanceStage.OBSERVATION, "Belated observation")
    bad_valid, bad_errors = broken_trace.verify_integrity()
    assert bad_valid is False
    assert len(bad_errors) >= 1


def test_agent_handoff_contract(tmp_path):
    contract = AgentHandoffContract(
        case_id="case_idor_99",
        target="https://api.target.com",
        endpoint="/api/v1/accounts/101",
        vuln_class="idor",
        source_agent="WebAgent",
        assigned_agent="FinderAgent",
        next_action="PROBE"
    )

    # 1. Record test execution
    contract.record_test(
        test_name="guest_id_probe",
        payload="/api/v1/accounts/102",
        result={"status": 403, "msg": "Unauthorized"},
        succeeded=False,
        error="Guest denied access"
    )
    assert len(contract.tests_performed) == 1
    assert len(contract.tests_failed) == 1

    # 2. Add verified evidence
    contract.add_evidence(
        evidence_type="header_analysis",
        raw_data={"X-Account-Owner": "101"},
        explanation="Header reveals explicit account tenancy boundary"
    )
    assert len(contract.evidence) == 1

    # 3. Transfer custody to VerifierAgent
    contract.transfer(to_agent="VerifierAgent", next_action="VERIFY", confidence_delta=0.45)
    assert contract.source_agent == "FinderAgent"
    assert contract.assigned_agent == "VerifierAgent"
    assert contract.next_action == "VERIFY"
    assert contract.confidence == 0.45

    # 4. Filesystem persistence
    cases_dir = tmp_path / "cases"
    contract.save(cases_dir)
    loaded = AgentHandoffContract.load("case_idor_99", cases_dir)
    assert loaded is not None
    assert loaded.case_id == "case_idor_99"
    assert loaded.assigned_agent == "VerifierAgent"
    assert len(loaded.tests_performed) == 1


def test_evidence_court_provenance_integration():
    judgment = EvidenceCourt.adjudicate(
        target_url="https://api.target.com/run",
        parameter="cmd",
        vuln_class="cmd_injection",
        finder_claim={"claim": "OS injection in run", "raw_request": "POST /run?cmd=id"},
        verifier_result={
            "reproduced": True,
            "arithmetic_proof_confirmed": True,
            "confidence": 0.99,
            "proof_detail": "Evaluated 53+19 to 72"
        },
        is_in_scope=True
    )
    assert judgment.verdict == CourtVerdict.CONFIRMED
    assert judgment.reportable is True
    # Verify that EvidenceCourt automatically attached the 7-stage causal provenance chain
    assert len(judgment.provenance_chain) == 7
    stages = [s.get("stage") for s in judgment.provenance_chain]
    assert stages == [
        "OBSERVATION",
        "BURP_REQUEST",
        "BURP_RESPONSE",
        "ANALYSIS",
        "HYPOTHESIS",
        "TEST",
        "VERIFICATION"
    ]

