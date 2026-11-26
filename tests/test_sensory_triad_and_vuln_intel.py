"""
Phase 5 Integration & Regression Tests:
Authorized Sensory Triad Repair & `core/vuln_intel/` Production Wiring
======================================================================
100% hermetic / offline — zero external network calls, zero synthetic fallbacks.
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

import httpx
import pytest
from rest_framework.test import APIRequestFactory

from core.brain.autonomous_brain import AutonomousBrain
from core.browser.browser_brain_loop import BrowserBrainLoop
from core.burp_adapter import BurpAdapter, BurpAdapterConfig, BurpAdapterError
from core.burp_gateway.capture_store import CaptureStore, CapturedTransaction
from core.burp_gateway.gateway import BurpGateway
from core.code_intel.agent import CodeIntelligenceAgent
from core.evidence_court import CourtVerdict
from core.scope_enforcer import ScopeEnforcer
from core.scope_guard import ScopeGuard
from core.vuln_intel.db import VulnerabilityStore
from core.vuln_intel.models import (
    AffectedPackage,
    Confidence,
    CvssData,
    Ecosystem,
    Provenance,
    Severity,
    VulnStatus,
    VulnerabilityRecord,
)
from hunter_ai.pipeline.pipeline_orchestrator import HunterPipelineOrchestrator
from hunter_ai.pipeline.schemas import LiveAssetRecord
from hunter_ai.runtime.tool_registry import build_default_tool_registry
from hunter_ai.tools.cve_scan import scan_cves
from hunter_backend.apps.intelligence_api import (
    OpenCodeSkillFileSaveView,
    VulnIntelCoverageView,
    VulnIntelSearchView,
    VulnIntelSyncView,
    VulnIntelTriageView,
)
from hunter_backend.testing import ASGISyncClient


def _seed_vuln_store(db_path: Path) -> VulnerabilityStore:
    store = VulnerabilityStore(db_path)
    rec = VulnerabilityRecord(
        source_id="nvd",
        source_record_id="CVE-2024-50001",
        canonical_id="CVE-2024-50001",
        title="Symfony HTTP Kernel Reflected XSS",
        description="Improper input neutralization in symfony/http-kernel enables cross-site scripting.",
        summary="XSS in symfony/http-kernel < 5.4.20",
        published_at=datetime(2024, 6, 15, 12, 0, tzinfo=timezone.utc),
        vuln_status=VulnStatus.ANALYZED,
        severity=Severity.HIGH,
        cvss=CvssData(version="3.1", score=7.5, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
        cwes=["CWE-79"],
        affected=[
            AffectedPackage(
                ecosystem=Ecosystem.COMPOSER,
                vendor="symfony",
                product="http-kernel",
                package_name="symfony/http-kernel",
                version_start_including="5.0.0",
                version_end_excluding="5.4.20",
                fixed_version="5.4.20",
            )
        ],
        fixed_versions=["5.4.20"],
        confidence=Confidence.CONFIRMED_BY_AUTHORITATIVE_SOURCE,
        provenance=[
            Provenance(
                source_id="nvd",
                source_record_id="CVE-2024-50001",
                url="https://nvd.nist.gov/vuln/detail/CVE-2024-50001",
            )
        ],
    )
    store.upsert_vulnerability(rec)
    return store


# ---------------------------------------------------------------------------
# 1. Burp Sensory Triad Repair (BurpAdapter <-> BurpGateway + CaptureStore + Extension)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_burp_adapter_gateway_route_alignment_and_bearer_auth(tmp_path: Path):
    token = "phase5-burp-secret-token-987654"
    store = CaptureStore("app.example.com", base_dir=tmp_path)
    gateway = BurpGateway(
        host="127.0.0.1",
        port=8085,
        capture_store=store,
        api_token=token,
        require_auth=True,
    )
    gateway.set_scope(include=["app.example.com", "*.example.com"], exclude=[])

    enforcer = ScopeEnforcer(ScopeGuard(in_scope=["app.example.com", "*.example.com"]))

    # 1. Unauthenticated adapter must be rejected on protected /api/* routes (401)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=gateway.app),
        base_url="http://127.0.0.1:8085",
    ) as raw_client:
        unauth_adapter = BurpAdapter(
            config=BurpAdapterConfig(gateway_base_url="http://127.0.0.1:8085", api_token=""),
            scope_enforcer=enforcer,
            http_client=raw_client,
        )
        # Ensure env tokens do not leak into the unauth adapter
        health = await unauth_adapter.health_check()
        assert health["available"] is True

        with pytest.raises(BurpAdapterError) as exc_info:
            await unauth_adapter.retrieve_authorized_http_history(target="app.example.com")
        assert exc_info.value.category == "UNAUTHORIZED"

        # 2. Authenticated adapter succeeds across all aligned BurpGateway routes
        auth_adapter = BurpAdapter(
            config=BurpAdapterConfig(gateway_base_url="http://127.0.0.1:8085", api_token=token),
            scope_enforcer=enforcer,
            http_client=raw_client,
        )
        assert (await auth_adapter.health_check())["available"] is True

        # /api/scope
        scope_upd = await auth_adapter.update_scope(include=["app.example.com", "api.example.com"])
        assert scope_upd["status"] == "UPDATED"
        scope_now = await auth_adapter.get_scope()
        assert "api.example.com" in scope_now["include"]

        # /api/traffic (POST + GET list + GET by tx_id)
        ingested = await auth_adapter.ingest_traffic({
            "host": "app.example.com",
            "port": 443,
            "protocol": "https",
            "request": (
                "POST /api/v1/login?next=/home HTTP/1.1\r\n"
                "Host: app.example.com\r\n"
                "Authorization: Bearer supersecretjwtvalue123456\r\n"
                "Cookie: session=mysecretcookie999\r\n\r\n"
                "api_key=sk-abcdef1234567890"
            ),
            "response": "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}",
            "tool": "proxy",
        })
        assert ingested["status"] == "INGESTED"
        tx_id = ingested["tx_id"]

        history = await auth_adapter.retrieve_authorized_http_history(target="app.example.com", limit=10)
        assert len(history) == 1
        tx = history[0]
        assert tx.tx_id == tx_id
        assert tx.method == "POST"
        assert "supersecretjwtvalue123456" not in str(tx.req_headers)
        assert "mysecretcookie999" not in str(tx.req_headers)
        assert "sk-abcdef1234567890" not in tx.req_body

        single_tx = await auth_adapter.retrieve_request(tx_id)
        assert single_tx is not None
        assert single_tx.tx_id == tx_id

        # /api/tasks (POST + GET + GET/{id})
        submitted = await auth_adapter.submit_supported_analysis_job(
            target="https://app.example.com/api/v1/login",
            job_type="passive_scan",
        )
        assert submitted["accepted"] is True
        task_id = submitted["task_id"]
        task_info = await auth_adapter.retrieve_analysis_results(task_id)
        assert task_info["found"] is True
        assert task_info["task_id"] == task_id
        assert len(await auth_adapter.list_tasks()) >= 1

        # /api/issues/burp & /api/issues/export
        iss_resp = await auth_adapter.submit_burp_issue({
            "name": "Reflected XSS",
            "url": "https://app.example.com/search?q=1",
            "severity": "High",
            "confidence": "Firm",
            "detail": "Payload reflected; Bearer secret_token_1234567890",
            "verified_by_burp": True,
        })
        assert iss_resp["status"] == "INGESTED"
        imported = await auth_adapter.import_supported_findings()
        assert len(imported) == 1
        assert imported[0].issue_name == "Reflected XSS"
        assert "secret_token_1234567890" not in imported[0].evidence

        gateway.register_confirmed_finding({
            "title": "Confirmed SQLi",
            "endpoint": "https://app.example.com/items?id=1",
            "severity": "High",
            "lifecycle_verdict": "CONFIRMED",
        })
        exported = await auth_adapter.fetch_exported_issues()
        assert exported["issues_count"] == 1

        # /api/cases
        case_res = await auth_adapter.upsert_case({
            "case_id": "case_p5_01",
            "target": "app.example.com",
            "endpoint": "/api/v1/login",
            "vuln_class": "auth",
            "status": "OPEN",
            "source_agent": "BurpAdapter",
            "assigned_agent": "VerifierAgent",
        })
        assert case_res["status"] == "STORED"
        assert len(await auth_adapter.list_cases()) == 1
        got_case = await auth_adapter.get_case("case_p5_01")
        assert got_case is not None and got_case["case_id"] == "case_p5_01"

        # /api/research/*
        queued_exp = await auth_adapter.research_queue_experiment(
            url="https://app.example.com/api/v1/profile",
            method="GET",
        )
        assert queued_exp["status"] == "QUEUED"
        exp_id = queued_exp["experiment_id"]
        q_list = await auth_adapter.research_list_queue()
        assert len(q_list["items"]) >= 1
        cancelled = await auth_adapter.research_cancel_experiment(exp_id)
        assert cancelled["status"] == "CANCELLED"

        rep = await auth_adapter.research_send_to_repeater(
            url="https://app.example.com/api/v1/profile",
            tab_name="Phase5Tab",
        )
        assert rep["status"] == "PROVISIONED"


def test_capture_store_structured_transaction_rows_and_disk_redaction(tmp_path: Path):
    store = CaptureStore("shop.example.com", base_dir=tmp_path)
    tx = CapturedTransaction(
        tx_id="tx_struct_01",
        target_host="shop.example.com",
        method="POST",
        url="https://shop.example.com/api/checkout?step=2",
        status_code=201,
        req_headers={
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.payloadsecret.sigsecret",
            "Cookie": "sid=supersecretcookieval; Path=/",
            "Content-Type": "application/json",
        },
        req_body='{"card_token": "' + "sk_" + 'live_1234567890abcdef12345678"}',
        resp_headers={"Content-Type": "application/json"},
        resp_body='{"order_id": 77, "status": "created"}',
        tool_source="proxy",
    )
    store.store_transaction(tx)

    # Disk files must have secrets scrubbed
    req_disk = (tmp_path / "shop_example_com" / "requests" / "tx_struct_01.json").read_text(encoding="utf-8")
    assert "payloadsecret" not in req_disk
    assert "supersecretcookieval" not in req_disk
    assert ("sk_" + "live_1234567890abcdef12345678") not in req_disk

    # Structured rows must carry all canonical fields
    rows = store.query_structured_transactions(limit=10)
    assert len(rows) == 1
    row = rows[0]
    required_keys = {"id", "time", "method", "host", "path", "status", "length", "request_headers", "response_status"}
    assert required_keys.issubset(row.keys())
    assert row["id"] == "tx_struct_01"
    assert isinstance(row["time"], str) and "T" in row["time"]
    assert row["method"] == "POST"
    assert row["host"] == "shop.example.com"
    assert row["path"] == "/api/checkout?step=2"
    assert row["status"] == 201
    assert row["response_status"] == 201
    assert row["length"] == len(tx.resp_body)
    assert "payloadsecret" not in str(row["request_headers"])
    assert "supersecretcookieval" not in str(row["request_headers"])

    # Live inspection helper includes scrubbed bodies & filters by target
    live_rows = store.query_live_inspection_rows(target="shop.example.com", limit=10)
    assert len(live_rows) == 1
    assert ("sk_" + "live_1234567890abcdef12345678") not in live_rows[0]["req_body"]
    assert store.query_live_inspection_rows(target="other.example.com", limit=10) == []


def test_burp_extension_non_blocking_queue_auth_header_and_task_poller(monkeypatch):
    import agents.burp_agent.integrations.burp_extension.hunter_burp_extension as ext_mod

    sent_requests: List[Dict[str, Any]] = []
    polled_tasks = [
        {
            "task_id": "task_rep_1",
            "action": "SCAN",
            "status": "QUEUED",
            "target_url": "https://app.example.com/api/orders/1",
            "payload": {
                "burp_action": "REPEATER",
                "dispatch_to_burp": True,
                "tab_name": "OrderProbe",
                "method": "GET",
            },
        },
        {
            "task_id": "task_probe_2",
            "action": "PROBE",
            "status": "QUEUED",
            "target_url": "https://app.example.com/api/ping",
            "payload": {"dispatch_to_burp": True, "method": "GET"},
        },
    ]

    class _FakeUrlResp:
        def __init__(self, body: bytes):
            self._body = body

        def read(self) -> bytes:
            return self._body

    def fake_urlopen(req, timeout=2.0):
        full_url = req.get_full_url()
        headers = {k.lower(): v for k, v in req.header_items()}
        sent_requests.append({"url": full_url, "headers": headers, "data": req.data})
        if full_url.endswith("/api/tasks") and req.data is None:
            return _FakeUrlResp(json.dumps({"tasks": polled_tasks}).encode("utf-8"))
        return _FakeUrlResp(b'{"status":"OK"}')

    monkeypatch.setattr(ext_mod.urllib2, "urlopen", fake_urlopen)

    repeater_calls: List[tuple] = []
    http_exec_calls: List[tuple] = []

    class FakeHelpers:
        def bytesToString(self, b):
            return b.decode("utf-8") if isinstance(b, bytes) else str(b)

        def stringToBytes(self, s):
            return s.encode("utf-8")

        def buildHttpService(self, host, port, protocol):
            return (host, port, protocol)

    class FakeCallbacks:
        TOOL_PROXY = 4
        TOOL_REPEATER = 64

        def getHelpers(self):
            return FakeHelpers()

        def setExtensionName(self, _name):
            pass

        def registerContextMenuFactory(self, _):
            pass

        def registerHttpListener(self, _):
            pass

        def registerScannerListener(self, _):
            pass

        def registerExtensionStateListener(self, _):
            pass

        def addSuiteTab(self, _):
            pass

        def printOutput(self, _msg):
            pass

        def sendToRepeater(self, host, port, use_https, req_bytes, caption):
            repeater_calls.append((host, port, use_https, caption))

        def makeHttpRequest(self, service, req_bytes):
            http_exec_calls.append((service, req_bytes))
            return SimpleNamespace(getResponse=lambda: b"HTTP/1.1 200 OK\r\n\r\npong")

    ext = ext_mod.BurpExtender()
    # Prevent real daemon threads from racing with deterministic single-step test
    monkeypatch.setattr(ext, "_start_background_workers", lambda: None)
    monkeypatch.setenv("HUNTER_BURP_GATEWAY_TOKEN", "ext-secret-token-42")
    ext.registerExtenderCallbacks(FakeCallbacks())

    msg = SimpleNamespace(
        getHttpService=lambda: SimpleNamespace(getHost=lambda: "app.example.com", getPort=lambda: 443, getProtocol=lambda: "https"),
        getRequest=lambda: b"GET /profile HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
        getResponse=lambda: b"HTTP/1.1 200 OK\r\n\r\nhello",
    )

    # 1. Proxy thread must NOT execute urllib2.urlopen synchronously
    ext.processHttpMessage(FakeCallbacks.TOOL_PROXY, False, msg)
    assert sent_requests == []
    assert ext._outbound_queue.qsize() == 1

    # 2. Background worker drains item with X-Hunter-Token attached
    assert ext.process_one_outbound(timeout=0.1) is True
    assert len(sent_requests) == 1
    assert sent_requests[0]["url"].endswith("/api/traffic")
    assert sent_requests[0]["headers"]["x-hunter-token"] == "ext-secret-token-42"
    assert sent_requests[0]["headers"]["authorization"] == "Bearer ext-secret-token-42"

    # 3. Inbound task poller dispatches Repeater + Active Check and posts completion
    outcomes = ext.poll_tasks_once()
    assert len(outcomes) == 2
    assert len(repeater_calls) == 1
    assert repeater_calls[0][3] == "OrderProbe"
    assert len(http_exec_calls) == 1
    completion_urls = [r["url"] for r in sent_requests if "/complete" in r["url"]]
    assert any("task_rep_1/complete" in u for u in completion_urls)
    assert any("task_probe_2/complete" in u for u in completion_urls)
    # Re-polling the same task IDs must be idempotent (no duplicate dispatch)
    assert ext.poll_tasks_once() == []


# ---------------------------------------------------------------------------
# 2. Browser & Code Intelligence Triad Repair
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_browser_brain_loop_shares_triad_state_and_runs_code_intel(tmp_path: Path):
    pages = {
        "https://app.example.com/": (
            "<html><head><title>Portal Login</title>"
            "<script src='/static/bundle.js'></script></head>"
            "<body>"
            "<form action='/api/auth/login' method='POST'>"
            "<input name='username' type='text'/><input name='password' type='password'/>"
            "</form>"
            "<a href='/dashboard'>Dashboard</a>"
            "</body></html>"
        ),
        "https://app.example.com/dashboard": (
            "<html><head><title>Dashboard</title></head>"
            "<body><script>"
            "var rawQ = location.search; document.getElementById('out').innerHTML = rawQ;"
            "</script></body></html>"
        ),
    }
    scripts = {
        "https://app.example.com/static/bundle.js": (
            "const awsKey = 'AKIAI44QH8DHB7XYZ912';\n"
            "fetch('/api/v1/users?role=admin');\n"
        )
    }

    class FakeSession:
        def __init__(self, target_url: str, output_dir: Path):
            self.target_url = target_url
            self.output_dir = output_dir
            self.output_dir.mkdir(parents=True, exist_ok=True)
            self.current_url = target_url
            self.cookies: List[Dict[str, Any]] = []
            self.local_storage: Dict[str, str] = {}
            self.network_history: List[Any] = []
            self.discovered_forms: List[Dict[str, Any]] = []
            self.event_bus = None

        async def start(self) -> bool:
            return True

        async def navigate(self, url: str):
            self.current_url = url
            html = pages.get(url, pages.get(url.rstrip("/"), ""))
            return html, 200, {"Content-Type": "text/html"}

        async def interact(self, selector: str, action: str = "click") -> bool:
            return False

        async def get_dom(self) -> str:
            return pages.get(self.current_url, "")

        def save_artifacts(self) -> None:
            pass

    session = FakeSession("https://app.example.com/", tmp_path / "browser")
    loop = BrowserBrainLoop(
        target_url="https://app.example.com/",
        session=session,
        max_pages=5,
        max_depth=2,
        script_fetcher=lambda url: scripts.get(url),
    )

    report = await loop.run_loop()

    # Exact shared instance identity between BrowserBrainLoop and HumanLikeExplorationEngine
    assert loop.explorer is not None
    assert loop.explorer.state_graph is loop.state_graph
    assert loop.explorer.coverage is loop.coverage
    assert loop.explorer.discovered_forms is loop.discovered_forms

    # Truthful telemetry: states, forms, secrets, and flows are all non-zero and accurate
    assert report.states_mapped >= 2
    assert report.states_mapped == len(loop.state_graph.states)
    assert report.forms_discovered >= 1
    assert report.forms_discovered == len(loop.discovered_forms)
    assert report.secrets_discovered >= 1
    assert report.source_sink_flows_discovered >= 1


@pytest.mark.asyncio
async def test_code_intel_sourcemap_and_autonomous_brain_candidate_court_routing():
    # Source Map v3 containing original unobfuscated source with a secret and a DOM XSS flow
    orig_source = (
        "const backupAwsKey = 'AKIAI44QH8DHB7XYZ912';\n"
        "const userParam = location.hash;\n"
        "document.getElementById('preview').innerHTML = userParam;\n"
        "fetch('/api/internal/export?format=csv');\n"
    )
    sourcemap_json = json.dumps({
        "version": 3,
        "file": "app.min.js",
        "sources": ["src/internal_admin.ts"],
        "sourcesContent": [orig_source],
    })
    inline_b64 = base64.b64encode(sourcemap_json.encode("utf-8")).decode("ascii")

    fetched_scripts = {
        "https://app.example.com/static/app.min.js": (
            "function a(){return 1;}\n"
            "//# sourceMappingURL=app.min.js.map\n"
        ),
        "https://app.example.com/static/inline_mapped.js": (
            "function b(){return 2;}\n"
            f"//# sourceMappingURL=data:application/json;base64,{inline_b64}\n"
        ),
    }

    async def fake_map_fetcher(map_url: str) -> Optional[str]:
        if map_url == "https://app.example.com/static/app.min.js.map":
            return sourcemap_json
        return None

    agent = CodeIntelligenceAgent()
    ci_res = await agent.analyze_page(
        target_url="https://app.example.com/",
        raw_html="<html><script src='/static/app.min.js'></script></html>",
        fetched_scripts=fetched_scripts,
        source_map_fetcher=fake_map_fetcher,
    )

    assert len(ci_res["source_maps_resolved"]) == 2
    assert any("/api/internal/export" in ep["url_or_path"] for ep in ci_res["endpoints"])
    assert len(ci_res["secrets"]) >= 1
    assert len(ci_res["source_sink_flows"]) >= 1

    # Route CodeIntelligenceAgent outputs through AutonomousBrain -> EvidenceCourt as CANDIDATE
    brain = AutonomousBrain.__new__(AutonomousBrain)
    brain.security_state = None
    brain.attack_surface_graph = None

    hyps = brain._ingest_code_intel_hypotheses("https://app.example.com/", ci_res)
    kinds = {h["kind"] for h in hyps}
    assert "code_intel_secret" in kinds
    assert "code_intel_source_sink" in kinds
    for h in hyps:
        # Phase 3 Evidence Court invariant: static JS clues are CANDIDATE, never auto-CONFIRMED
        assert h["verdict"] == CourtVerdict.CANDIDATE.value
        assert h["epistemic_state"] == "CANDIDATE"
        assert h["reportable"] is False
        assert "AKIAI44QH8DHB7XYZ912" not in json.dumps(h)


# ---------------------------------------------------------------------------
# 3. Vulnerability Intelligence (`core/vuln_intel/`) Production Wiring
# ---------------------------------------------------------------------------


def test_cve_scan_truthful_unavailable_and_real_sqlite_triage(tmp_path: Path):
    empty_db = tmp_path / "empty_vuln.sqlite3"
    empty_res = scan_cves("app.example.com", technologies=["symfony/http-kernel:5.4.0"], db_path=empty_db)
    assert empty_res["status"] == "UNAVAILABLE"
    assert empty_res["total"] == 0
    assert empty_res["cves"] == []
    # Must NEVER fabricate legacy Log4j / Outlook CVEs
    assert "CVE-2021-44228" not in json.dumps(empty_res)
    assert "CVE-2023-23397" not in json.dumps(empty_res)
    assert empty_res["provenance"]["db_records_total"] == 0

    populated_db = tmp_path / "vuln.sqlite3"
    _seed_vuln_store(populated_db)

    vuln_res = scan_cves(
        "app.example.com",
        technologies=["symfony/http-kernel:5.4.0"],
        db_path=populated_db,
        authorized=True,
        max_risk="high",
    )
    assert vuln_res["status"] == "OK"
    assert vuln_res["total"] == 1
    cve_entry = vuln_res["cves"][0]
    assert cve_entry["cve"] == "CVE-2024-50001"
    assert cve_entry["applicability"] == "CONFIRMED_APPLICABLE"
    assert "xss" in cve_entry["tool_selection"]["vuln_classes"]
    assert "dalfox" in cve_entry["tool_selection"]["selected_tools"]

    patched_res = scan_cves(
        "app.example.com",
        technologies=["symfony/http-kernel:5.4.25"],
        db_path=populated_db,
    )
    assert patched_res["cves"][0]["applicability"] == "NOT_APPLICABLE"


@pytest.mark.asyncio
async def test_runtime_tool_registry_policy_gate_scope_and_vuln_intel(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("HUNTER_UNRESTRICTED", raising=False)
    monkeypatch.delenv("HUNTER_FULL_POWER", raising=False)
    db_path = tmp_path / "runtime_vuln.sqlite3"
    _seed_vuln_store(db_path)

    registry = build_default_tool_registry(
        allowed_targets=["example.com", "*.example.com"],
        authorized=False,
        vuln_db_path=db_path,
    )
    assert registry.policy_gate is not None
    assert registry.scope_engine is not None

    # Out-of-scope & cloud metadata SSRF must be blocked before any network call
    blocked_ssrf = await registry.execute(
        "http_probe",
        {"url": "http://169.254.169.254/latest/meta-data/"},
    )
    assert blocked_ssrf["success"] is False
    assert blocked_ssrf.get("blocked") is True

    blocked_oos = await registry.execute(
        "differential_analyze",
        {"baseline_url": "https://evil.invalid/a", "probe_url": "https://evil.invalid/b"},
    )
    assert blocked_oos["success"] is False
    assert blocked_oos.get("blocked") is True

    # cve_lookup must query core/vuln_intel/ SQLite store
    lookup = await registry.execute(
        "cve_lookup",
        {"product": "symfony/http-kernel", "version": "5.4.0"},
    )
    assert lookup["success"] is True
    out = lookup["output"]
    assert out["provenance"] == "core.vuln_intel"
    assert out["status"] == "OK"
    assert len(out["results"]) == 1
    assert out["results"][0]["canonical_id"] == "CVE-2024-50001"
    assert out["results"][0]["applicability"] == "CONFIRMED_APPLICABLE"


def test_pipeline_orchestrator_offline_vuln_intel_triage_and_tool_selection(tmp_path: Path, monkeypatch):
    # Keep EvidenceStore isolated inside tmp_path so tests never dirty tracked data/ files
    import core.evidence_store as ev_mod

    orig_es = ev_mod.EvidenceStore
    monkeypatch.setattr(ev_mod, "EvidenceStore", lambda *a, **k: orig_es(db_path=str(tmp_path / "evidence.sqlite3")))

    orch = HunterPipelineOrchestrator(
        target="https://app.example.com",
        authorized=True,
        dry_run=True,
        allow_no_ai=True,
        skip_ai_probe=True,
    )
    orch.live_assets = [
        LiveAssetRecord(
            url="https://app.example.com",
            host="app.example.com",
            status_code=200,
            technologies=["symfony/http-kernel:5.4.0"],
        )
    ]

    # Empty DB -> clean hermetic UNAVAILABLE
    empty_summary = orch.run_vuln_intel_triage(db_path=tmp_path / "empty.sqlite3")
    assert empty_summary["status"] == "UNAVAILABLE"
    assert empty_summary["candidate_hypotheses"] == []

    # Populated DB -> triage + select_tools + CANDIDATE hypothesis
    db_path = tmp_path / "pipe_vuln.sqlite3"
    _seed_vuln_store(db_path)
    summary = orch.run_vuln_intel_triage(db_path=db_path)
    assert summary["status"] == "OK"
    assert summary["matched_advisories"] == 1
    assert len(summary["triage_results"]) == 1
    assert summary["triage_results"][0]["classification"] == "CONFIRMED_APPLICABLE"
    assert len(summary["tool_plans"]) == 1
    assert len(summary["candidate_hypotheses"]) == 1
    hyp = summary["candidate_hypotheses"][0]
    assert hyp["source"] == "vuln_intel"
    assert hyp["status"] == "CANDIDATE"
    assert "dalfox" in hyp["recommended_tools"]


def test_intelligence_api_vuln_intel_views_kb_and_truthful_opencode_execute(tmp_path: Path, monkeypatch):
    db_path = tmp_path / "api_vuln.sqlite3"
    _seed_vuln_store(db_path)
    monkeypatch.setenv("HUNTER_VULN_INTEL_DB", str(db_path))

    factory = APIRequestFactory()

    # 1. Direct DRF APIViews ready for urls.py mounting
    search_req = factory.get("/api/vuln-intel/search", {"q": "symfony", "cwe": "CWE-79"})
    search_resp = VulnIntelSearchView.as_view()(search_req)
    assert search_resp.status_code == 200
    assert search_resp.data["count"] == 1
    assert search_resp.data["results"][0]["canonical_id"] == "CVE-2024-50001"

    cov_req = factory.get("/api/vuln-intel/coverage", {"source": "nvd", "start": "2024-06-01", "end": "2024-06-30"})
    cov_resp = VulnIntelCoverageView.as_view()(cov_req)
    assert cov_resp.status_code == 200
    assert cov_resp.data["records_total"] == 1
    assert cov_resp.data["months_covered"] == 1

    triage_req = factory.post(
        "/api/vuln-intel/triage",
        data=json.dumps({
            "project": {
                "project_id": "demo-app",
                "ecosystem": "composer",
                "packages": [{"name": "symfony/http-kernel", "version": "5.4.0", "ecosystem": "composer"}],
            },
            "vuln_ids": ["CVE-2024-50001"],
            "include_tool_selection": True,
            "authorized": True,
            "max_risk": "high",
        }),
        content_type="application/json",
    )
    triage_resp = VulnIntelTriageView.as_view()(triage_req)
    assert triage_resp.status_code == 200
    assert triage_resp.data["count"] == 1
    assert triage_resp.data["results"][0]["classification"] == "CONFIRMED_APPLICABLE"
    assert len(triage_resp.data["tool_selections"]) == 1

    sync_get_resp = VulnIntelSyncView.as_view()(factory.get("/api/vuln-intel/sync"))
    assert sync_get_resp.status_code == 200
    assert sync_get_resp.data["stats"]["vulnerabilities"] == 1

    sync_dry_req = factory.post(
        "/api/vuln-intel/sync",
        data=json.dumps({"source": "nvd", "start": "2024-06-01", "end": "2024-06-02", "dry_run": True}),
        content_type="application/json",
    )
    sync_dry_resp = VulnIntelSyncView.as_view()(sync_dry_req)
    assert sync_dry_resp.status_code == 200
    assert sync_dry_resp.data["status"] == "dry_run"

    # 2. Mounted /api/cve/*, /api/brain/kb/*, and truthful /api/opencode/execute via ASGI client
    with ASGISyncClient() as client:
        r_latest = client.get("/api/cve/latest")
        assert r_latest.status_code == 200
        assert r_latest.json()["count"] == 1
        assert r_latest.json()["cves"][0]["canonical_id"] == "CVE-2024-50001"

        r_search = client.get("/api/cve/search", params={"q": "symfony"})
        assert r_search.status_code == 200
        assert r_search.json()["count"] == 1

        r_kb_cve = client.get("/api/brain/kb/cve/CVE-2024-50001")
        assert r_kb_cve.status_code == 200
        assert r_kb_cve.json()["found"] is True
        assert r_kb_cve.json()["source"] == "core.vuln_intel"

        r_kb_retrieve = client.post("/api/brain/retrieve", json={"query": "authorization idor", "signals": ["numeric_id"]})
        assert r_kb_retrieve.status_code == 200
        assert r_kb_retrieve.json()["count"] >= 1

        r_kb_payloads = client.get("/api/brain/kb/payloads/authorization")
        assert r_kb_payloads.status_code == 200
        assert len(r_kb_payloads.json()["knowledge_items"]) >= 1

        # Truthful opencode_execute_view: markdown prompt skill returns UNAVAILABLE, NEVER "CORS Scan finished"
        r_exec = client.post(
            "/api/opencode/execute",
            json={"skill_name": "hunterai-redteam", "task": "cors audit", "target": "https://example.com"},
        )
        assert r_exec.status_code == 200
        exec_data = r_exec.json()
        assert exec_data["status"] == "UNAVAILABLE"
        assert exec_data["ok"] is False
        assert exec_data["executed"] is False
        assert "CORS Scan finished" not in str(exec_data)

    # 3. OpenCodeSkillFileSaveView validates frontmatter & triggers sync
    bad_save_req = factory.post(
        "/api/opencode/skills/file",
        data=json.dumps({"name": "hunterai-redteam", "content": "# Missing frontmatter"}),
        content_type="application/json",
    )
    bad_save_resp = OpenCodeSkillFileSaveView.as_view()(bad_save_req)
    assert bad_save_resp.status_code == 400

    import hunter_backend.apps.intelligence_api as intel_mod

    sync_called: List[bool] = []
    monkeypatch.setattr(
        intel_mod,
        "_trigger_opencode_skills_sync",
        lambda: (sync_called.append(True) or {"synced": True, "count": 1, "skills": ["phase5-demo-skill"]}),
    )
    monkeypatch.setattr(intel_mod, "BASE_DIR", tmp_path)
    (tmp_path / "skills").mkdir(parents=True, exist_ok=True)

    good_md = "---\nname: phase5-demo-skill\ndescription: Valid test skill\n---\n# Body\n"
    good_save_req = factory.post(
        "/api/opencode/skills/file",
        data=json.dumps({"name": "phase5-demo-skill", "content": good_md}),
        content_type="application/json",
    )
    good_save_resp = OpenCodeSkillFileSaveView.as_view()(good_save_req)
    assert good_save_resp.status_code == 200
    assert good_save_resp.data["synced"] is True
    assert sync_called == [True]
    assert (tmp_path / "skills" / "phase5-demo-skill" / "SKILL.md").read_text(encoding="utf-8") == good_md


@pytest.mark.asyncio
async def test_opencode_execute_view_dispatches_real_skill_registry_handler(monkeypatch):
    import core.skill_registry as sr_mod

    executed_targets: List[str] = []

    class FakeSkillInstance:
        async def run(self, ctx):
            executed_targets.append(ctx.target)
            return SimpleNamespace(
                success=True,
                tool_used="demo_exec_skill",
                findings=[{"title": "Real Skill Signal", "target": ctx.target}],
                output_files=["report.json"],
                error="",
            )

    class FakeMeta:
        def instantiate(self):
            return FakeSkillInstance()

    class FakeRegistry:
        def get_skill(self, name: str):
            return FakeMeta() if name == "demo_exec_skill" else None

    monkeypatch.setattr(sr_mod, "SkillRegistry", FakeRegistry)

    with ASGISyncClient() as client:
        # 1. Valid in-scope target executes the real skill handler
        resp = client.post(
            "/api/opencode/execute",
            json={
                "skill_name": "demo_exec_skill",
                "target": "https://example.com",
                "scope": ["example.com"],
                "task": "audit",
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is True
        assert body["executed"] is True
        assert body["tool_used"] == "demo_exec_skill"
        assert executed_targets == ["https://example.com"]
        assert len(body["findings"]) == 1

        # 2. Non-overridable SSRF / metadata / scheme / metacharacter targets MUST be blocked
        #    with HTTP 403 EVEN when HUNTER_WEB_UNRESTRICTED=1!
        monkeypatch.setenv("HUNTER_WEB_UNRESTRICTED", "1")
        for forbidden_target in (
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd",
            "gopher://127.0.0.1:6379/_INFO",
            "example.com;id",
        ):
            r_blk = client.post(
                "/api/opencode/execute",
                json={
                    "skill_name": "demo_exec_skill",
                    "target": forbidden_target,
                    "task": "audit",
                },
            )
            assert r_blk.status_code == 403, f"Expected 403 for {forbidden_target}, got {r_blk.status_code}: {r_blk.text}"
        # Ensure handler was NOT called for any blocked target
        assert executed_targets == ["https://example.com"]


@pytest.mark.asyncio
async def test_runtime_tool_registry_blocks_invariants_under_unrestricted_and_bare_registry_fails_closed(
    tmp_path: Path,
    monkeypatch,
):
    from hunter_ai.runtime.tool_registry import ToolRegistry, ToolRiskLevel

    # 1. Bare ToolRegistry() defaults to fail-closed PolicyGate + StrictScopeEngine in governed mode
    monkeypatch.delenv("HUNTER_UNRESTRICTED", raising=False)
    monkeypatch.delenv("HUNTER_FULL_POWER", raising=False)
    bare = ToolRegistry()
    assert bare.policy_gate is not None
    assert bare.scope_engine is not None

    handler_invoked: List[str] = []

    async def _probe_stub(url: str) -> Dict[str, Any]:
        handler_invoked.append(url)
        return {"ok": True}

    bare.register(
        name="stub_probe",
        description="Stub probe",
        input_schema={"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
        handler=_probe_stub,
        risk_level=ToolRiskLevel.SAFE,
    )
    denied_bare = await bare.execute("stub_probe", {"url": "https://example.com/health"})
    assert denied_bare["success"] is False
    assert denied_bare.get("blocked") is True
    assert handler_invoked == []

    # 2. Under HUNTER_UNRESTRICTED=1, non-overridable SSRF / metadata / unsafe schemes remain BLOCKED
    monkeypatch.setenv("HUNTER_UNRESTRICTED", "1")
    reg = build_default_tool_registry(
        allowed_targets=["example.com"],
        authorized=True,
        vuln_db_path=tmp_path / "unrestricted_vuln.sqlite3",
    )
    for bad_url in (
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_INFO",
    ):
        res_probe = await reg.execute("http_probe", {"url": bad_url})
        assert res_probe["success"] is False, f"Expected block for {bad_url}"
        assert res_probe.get("blocked") is True
        res_diff = await reg.execute(
            "differential_analyze",
            {"baseline_url": "https://example.com/", "probe_url": bad_url},
        )
        assert res_diff["success"] is False
        assert res_diff.get("blocked") is True


@pytest.mark.asyncio
async def test_autonomous_brain_js_and_sourcemap_rejects_file_and_metadata_urls():
    brain = AutonomousBrain.__new__(AutonomousBrain)
    fetched_calls: List[str] = []

    async def _spy_fetch_js(url: str, proxy: Optional[str] = None) -> str:
        fetched_calls.append(url)
        return "console.log('ok');"

    brain._fetch_js = _spy_fetch_js

    assert brain._is_in_scope("file:///etc/passwd", "https://app.example.com/") is False
    assert brain._is_in_scope("gopher://127.0.0.1:6379/", "https://app.example.com/") is False
    assert brain._is_safe_fetchable_url("file:///etc/passwd", "https://app.example.com/") is False
    assert brain._is_safe_fetchable_url("http://169.254.169.254/latest/meta-data/app.js", "https://app.example.com/") is False
    assert brain._is_safe_fetchable_url("https://app.example.com/static/app.js", "https://app.example.com/") is True

    fetched = await brain._fetch_code_intel_scripts(
        [
            "file:///etc/passwd",
            "gopher://127.0.0.1:6379/app.js",
            "http://169.254.169.254/latest/meta-data/app.js",
            "https://app.example.com/static/app.js",
        ],
        target="https://app.example.com/",
    )
    assert list(fetched.keys()) == ["https://app.example.com/static/app.js"]
    assert fetched_calls == ["https://app.example.com/static/app.js"]
