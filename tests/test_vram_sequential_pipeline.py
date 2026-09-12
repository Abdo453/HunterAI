"""
Unit and Integration Tests for VRAMSequentialPipeline and 5-Stage Architecture
"""
import os
import json
import pytest
import sqlite3
import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock

import httpx

from core.scope_guard import ScopeGuard
from core.pipeline.vram_sequential_pipeline import (
    VRAMManager,
    ResponseNormalizer,
    ReconStateStore,
    QwenDecompilerExtractor,
    WhiteRabbitHypothesisEngine,
    ControlledExecutionController,
    TriageAndReportEngine,
    VRAMSequentialPipeline,
    ExtractedSurface,
    ProbePlan,
    ExecutionTelemetry,
    VerifiedFinding,
    PipelineResult,
)


# ─────────────────────────────────────────────────────────────────────────────
# 1. ResponseNormalizer Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_response_normalizer_sanitizes_dynamic_tokens():
    raw_body_1 = """
    <html>
      <input type="hidden" name="csrf_token" value="abc123randomXYZ" />
      <div>Welcome User</div>
      <!-- Session Timestamp: 2026-09-09T16:00:00Z -->
      <span nonce="nonce-99887766">Active</span>
    </html>
    """
    raw_body_2 = """
    <html>
      <input type="hidden" name="csrf_token" value="diffNonceToken777" />
      <div>Welcome User</div>
      <!-- Session Timestamp: 2026-09-09T16:05:00Z -->
      <span nonce="nonce-11223344">Active</span>
    </html>
    """
    hash1 = ResponseNormalizer.compute_hash(raw_body_1)
    hash2 = ResponseNormalizer.compute_hash(raw_body_2)

    assert hash1 == hash2, "Dynamic CSRF tokens/timestamps should produce identical structural hash"


def test_response_normalizer_detects_actual_structural_change():
    body_base = "<html><body><h1>Dashboard</h1></body></html>"
    body_changed = "<html><body><h1>Admin Console</h1><p>Secret Data</p></body></html>"

    hash_base = ResponseNormalizer.compute_hash(body_base)
    hash_changed = ResponseNormalizer.compute_hash(body_changed)

    assert hash_base != hash_changed, "Structural changes must result in distinct hashes"


# ─────────────────────────────────────────────────────────────────────────────
# 2. ReconStateStore Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_recon_state_store_cache(tmp_path):
    db_file = tmp_path / "test_recon.db"
    store = ReconStateStore(db_file)

    url = "https://target.local/profile"
    method = "GET"
    h1 = "hash_alpha_1"

    # Initially not unchanged
    assert not store.is_unchanged(url, method, h1)

    # Update state
    store.update_endpoint(url, method, h1, 200, "id=1")

    # Now it should be detected as unchanged
    assert store.is_unchanged(url, method, h1, "id=1")

    # Different hash should be detected as changed
    assert not store.is_unchanged(url, method, "hash_beta_2", "id=1")


# ─────────────────────────────────────────────────────────────────────────────
# 3. VRAMManager & Unload Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_vram_manager_unloads_model_with_keep_alive_zero():
    async def _run():
        vram = VRAMManager(ollama_host="http://192.168.1.3:11434")

        mock_resp = MagicMock()
        mock_resp.status_code = 200

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_resp
            success = await vram.unload_model("WhiteRabbitNeo")

            assert success is True
            mock_post.assert_called_once()
            call_args = mock_post.call_args
            assert call_args[1]["json"] == {"model": "WhiteRabbitNeo", "keep_alive": 0}

    asyncio.run(_run())


def test_vram_manager_generate_json_calls_keep_alive():
    async def _run():
        vram = VRAMManager(ollama_host="http://192.168.1.3:11434")

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "response": json.dumps({"endpoints": ["/api/v1/auth"], "sensitive_parameters": [{"name": "token"}]})
        }

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_resp
            data = await vram.generate_json(
                model_name="qwen2.5-coder:14b",
                prompt="Find parameters",
                system_prompt="Extract JSON"
            )

            assert "endpoints" in data
            assert data["endpoints"] == ["/api/v1/auth"]
            first_call_payload = mock_post.call_args_list[0][1]["json"]
            assert first_call_payload["keep_alive"] == 0

    asyncio.run(_run())


# ─────────────────────────────────────────────────────────────────────────────
# 4. Stage 2: QwenDecompilerExtractor Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_qwen_decompiler_extractor():
    async def _run():
        vram = VRAMManager()
        extractor = QwenDecompilerExtractor(vram)

        mock_output = {
            "endpoints": ["/api/v2/users", "/internal/admin/secret"],
            "sensitive_parameters": [{"name": "user_id", "location": "query", "risk": "IDOR"}],
            "leaked_secrets": [{"type": "api_key", "value": "sk_test_12345"}],
            "internal_routes": ["staging.internal.net"],
            "tech_stack": ["Node.js", "Express"]
        }

        with patch.object(vram, "generate_json", new_callable=AsyncMock) as mock_gen:
            mock_gen.return_value = mock_output
            surface = await extractor.analyze_surface(
                target_url="https://app.target.com",
                js_snippets=["fetch('/api/v2/users?user_id=10')"],
                discovered_urls=["https://app.target.com/login"]
            )

            assert surface.target_url == "https://app.target.com"
            assert len(surface.endpoints) == 2
            assert surface.sensitive_parameters[0]["name"] == "user_id"
            assert surface.leaked_secrets[0]["value"] == "sk_test_12345"

    asyncio.run(_run())


# ─────────────────────────────────────────────────────────────────────────────
# 5. Stage 3: WhiteRabbitHypothesisEngine Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_whiterabbit_hypothesis_engine():
    async def _run():
        vram = VRAMManager()
        engine = WhiteRabbitHypothesisEngine(vram)

        surface = ExtractedSurface(
            target_url="https://app.target.com",
            endpoints=["/api/users"],
            sensitive_parameters=[{"name": "user_id", "location": "query"}],
            tech_stack=["PostgreSQL", "FastAPI"]
        )

        mock_probes = {
            "probes": [
                {
                    "probe_id": "probe_idor_1",
                    "target_url": "https://app.target.com/api/users",
                    "method": "GET",
                    "param_name": "user_id",
                    "param_location": "query",
                    "vulnerability_category": "idor",
                    "payload": "1002",
                    "baseline_payload": "1001",
                    "expected_differential": "status_change",
                    "canary_token": "canary_user_1002",
                    "rationale": "Cross-user IDOR access check",
                    "risk_level": "safe"
                }
            ]
        }

        with patch.object(vram, "generate_json", new_callable=AsyncMock) as mock_gen:
            mock_gen.return_value = mock_probes
            plans = await engine.generate_probe_plans("https://app.target.com", surface)

            assert len(plans) == 1
            assert plans[0].probe_id == "probe_idor_1"
            assert plans[0].vulnerability_category == "idor"
            assert plans[0].payload == "1002"

    asyncio.run(_run())


# ─────────────────────────────────────────────────────────────────────────────
# 6. Stage 4: ControlledExecutionController Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_controlled_execution_controller_scope_enforcement():
    async def _run():
        scope = ScopeGuard(in_scope=["https://app.target.com/*"])
        controller = ControlledExecutionController(scope, rate_limit_rps=10.0)

        probes = [
            ProbePlan(
                probe_id="p1",
                target_url="https://app.target.com/api/item",
                method="GET",
                param_name="id",
                param_location="query",
                vulnerability_category="sqli",
                payload="1'",
                baseline_payload="1",
                expected_differential="status_change"
            ),
            ProbePlan(
                probe_id="p2",
                target_url="https://evil-unauthorized-target.com/api",
                method="GET",
                param_name="id",
                param_location="query",
                vulnerability_category="sqli",
                payload="1'",
                baseline_payload="1",
                expected_differential="status_change"
            )
        ]

        mock_handler = httpx.MockTransport(lambda req: httpx.Response(200, text="OK response"))
        async with httpx.AsyncClient(transport=mock_handler) as client:
            telemetry = await controller.execute_probes(probes, client=client)

        assert len(telemetry) == 1
        assert telemetry[0].probe_id == "p1"

    asyncio.run(_run())


# ─────────────────────────────────────────────────────────────────────────────
# 7. Stage 5: TriageAndReportEngine Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_triage_and_report_engine():
    async def _run():
        vram = VRAMManager()
        triager = TriageAndReportEngine(vram)

        telemetry = [
            ExecutionTelemetry(
                probe_id="p1",
                probe_plan=ProbePlan(
                    probe_id="p1",
                    target_url="https://app.target.com/search",
                    method="GET",
                    param_name="q",
                    param_location="query",
                    vulnerability_category="sqli",
                    payload="1' AND 1=1 --",
                    baseline_payload="1",
                    expected_differential="body_diff"
                ),
                target_url="https://app.target.com/search",
                timestamp=1000.0,
                request_headers={},
                request_body="1' AND 1=1 --",
                response_status=200,
                response_time_ms=50.0,
                response_length=5400,
                response_body_snippet="Search results found",
                baseline_status=200,
                baseline_time_ms=45.0,
                baseline_length=2200,
                is_differential_detected=True,
                canary_reflected=False
            )
        ]

        mock_triage_output = {
            "findings": [
                {
                    "title": "SQL Injection in Search Query Parameter",
                    "vulnerability_type": "SQL Injection",
                    "severity": "High",
                    "cvss_score": 8.1,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "cwe_id": "CWE-89",
                    "param_name": "q",
                    "summary": "Boolean differential query confirmed SQL injection on 'q'",
                    "steps_to_reproduce": ["Send GET with q=1' AND 1=1 --"],
                    "proof_of_concept": "curl -i 'https://app.target.com/search?q=1%27+AND+1%3D1+--'",
                    "business_impact": "Unauthorized extraction of application records",
                    "root_cause": "Dynamic string concatenation in SQL query",
                    "remediation": "Use prepared statements with parameterized inputs."
                }
            ]
        }

        with patch.object(vram, "generate_json", new_callable=AsyncMock) as mock_gen:
            mock_gen.return_value = mock_triage_output
            findings = await triager.triage_findings("https://app.target.com/search", telemetry)

            assert len(findings) == 1
            assert findings[0].cwe_id == "CWE-89"
            assert findings[0].severity == "High"
            assert findings[0].cvss_score == 8.1

    asyncio.run(_run())


# ─────────────────────────────────────────────────────────────────────────────
# 8. End-to-End VRAMSequentialPipeline Integration Test
# ─────────────────────────────────────────────────────────────────────────────

def test_vram_sequential_pipeline_e2e(tmp_path):
    async def _run():
        pipeline = VRAMSequentialPipeline(workspace_dir=str(tmp_path / "test_run"))

        mock_surface = {
            "endpoints": ["/api/v1/data"],
            "sensitive_parameters": [{"name": "account_id", "location": "query"}],
            "leaked_secrets": [],
            "internal_routes": [],
            "tech_stack": ["Python", "FastAPI"]
        }

        mock_probes = {
            "probes": [
                {
                    "probe_id": "probe_bola_1",
                    "target_url": "https://testapp.local/api/v1/data",
                    "method": "GET",
                    "param_name": "account_id",
                    "param_location": "query",
                    "vulnerability_category": "idor",
                    "payload": "9999",
                    "baseline_payload": "1001",
                    "expected_differential": "status_change",
                    "canary_token": "",
                    "rationale": "BOLA cross-account check",
                    "risk_level": "safe"
                }
            ]
        }

        mock_findings = {
            "findings": [
                {
                    "title": "Broken Object Level Authorization (BOLA)",
                    "vulnerability_type": "BOLA / IDOR",
                    "severity": "High",
                    "cvss_score": 8.5,
                    "cwe_id": "CWE-639",
                    "param_name": "account_id",
                    "summary": "Access granted to foreign account_id 9999",
                    "steps_to_reproduce": ["GET /api/v1/data?account_id=9999"],
                    "proof_of_concept": "curl https://testapp.local/api/v1/data?account_id=9999",
                    "business_impact": "Cross-tenant data exposure",
                    "root_cause": "Missing tenant ownership verification",
                    "remediation": "Verify authenticated user matches object owner."
                }
            ]
        }

        def custom_responder(req: httpx.Request):
            if "account_id=9999" in str(req.url):
                return httpx.Response(200, text="Secret Account 9999 Data")
            return httpx.Response(200, text="<html><body>App Home <a href='/api/v1/data'>API</a></body></html>")

        mock_client = httpx.AsyncClient(transport=httpx.MockTransport(custom_responder))

        with patch.object(pipeline.vram_mgr, "generate_json") as mock_gen:
            mock_gen.side_effect = [mock_surface, mock_probes, mock_findings]

            res: PipelineResult = await pipeline.execute_pipeline(
                target_url="https://testapp.local",
                in_scope=["https://testapp.local/*"],
                mock_client=mock_client
            )

            assert res.target == "https://testapp.local"
            assert res.findings_count == 1
            assert res.findings[0].cwe_id == "CWE-639"
            assert res.vram_unloaded_successfully is True
            assert Path(res.report_json_path).exists()
            assert Path(res.report_html_path).exists()

    asyncio.run(_run())


def test_fastapi_vram_pipeline_status_endpoint():
    async def _run():
        from ui.web.app import app
        from httpx import ASGITransport, AsyncClient

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            r = await ac.get("/api/pipeline/vram/status")
            assert r.status_code == 200
            data = r.json()
            assert "active_model_in_vram" in data
            assert "pipeline_stages" in data
            assert len(data["pipeline_stages"]) == 5

    asyncio.run(_run())


def test_fastapi_vram_pipeline_execute_endpoint():
    async def _run():
        from ui.web.app import app
        from httpx import ASGITransport, AsyncClient

        mock_res = PipelineResult(
            target="https://target.local",
            scan_id="scan_mock_123",
            total_endpoints_crawled=5,
            new_or_modified_endpoints=3,
            skipped_unchanged_endpoints=2,
            extracted_sensitive_params=2,
            probes_executed=4,
            findings_count=1,
            findings=[
                VerifiedFinding(
                    finding_id="VND-1",
                    title="Test SQLi",
                    vulnerability_type="SQL Injection",
                    severity="High",
                    cvss_score=8.5,
                    cvss_vector="CVSS:3.1/AV:N",
                    cwe_id="CWE-89",
                    target_url="https://target.local",
                    param_name="id",
                    summary="SQLi detected",
                    steps_to_reproduce=["id=1'"],
                    proof_of_concept="poc",
                    business_impact="impact",
                    root_cause="cause",
                    remediation="fix"
                )
            ],
            report_json_path="/tmp/report.json",
            report_html_path="/tmp/report.html",
            duration_seconds=1.2,
            vram_unloaded_successfully=True
        )

        with patch("core.pipeline.vram_sequential_pipeline.vram_pipeline.execute_pipeline", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = mock_res
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                r = await ac.post("/api/pipeline/vram/execute", json={"target_url": "https://target.local"})
                assert r.status_code == 200
                data = r.json()
                assert data["status"] == "completed"
                assert data["findings_count"] == 1
                assert data["findings"][0]["cwe"] == "CWE-89"

    asyncio.run(_run())
