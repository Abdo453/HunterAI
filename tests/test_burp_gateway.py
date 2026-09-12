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
