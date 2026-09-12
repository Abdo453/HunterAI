"""
Tests for HunterAI Master Pipeline:
- MasterToolRegistry Tool Specifications & Fallbacks (subfinder -> crtsh, gobuster -> python_dir_fuzz, nmap -> python_socket_scan)
- CorrelationEngine (Linking attack surfaces, endpoints, parameters, and exposed secrets)
- DeduplicationEngine (Bayesian confidence combining, evidence merging, deduplication)
- PriorityEngine (P0 to P5 bug bounty classification and sorting)
- HunterPipelineOrchestrator end-to-end execution (authorized=True vs authorized=False)
"""
import os
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from hunter_ai.pipeline.tool_specs import MasterToolRegistry, ToolSpec
from hunter_ai.pipeline.correlation import CorrelationEngine, DeduplicationEngine, PriorityEngine
from hunter_ai.pipeline.schemas import (
    EndpointRecord,
    ParameterRecord,
    SecretFindingRecord,
    LiveAssetRecord,
    HunterFinding,
    FindingStatus,
    VerificationEvidence,
    ReproductionArtifact,
    AssetCategory,
)
from hunter_ai.pipeline.pipeline_orchestrator import HunterPipelineOrchestrator
from tools.tool_manager import ToolManager, ToolResult


# =====================================================================
# 1. MasterToolRegistry & Tool Specifications Tests
# =====================================================================

def test_master_tool_registry_spec_coverage():
    registry = MasterToolRegistry()
    expected_tools = ["subfinder", "assetfinder", "crtsh", "httpx", "nmap", "gobuster", "katana", "nuclei"]
    for t in expected_tools:
        assert t in registry.specs
        spec = registry.specs[t]
        assert isinstance(spec, ToolSpec)
        assert spec.purpose
        assert spec.timeout > 0
        assert 0.0 < spec.confidence <= 1.0
        assert spec.risk_level in ("SAFE", "AUDIT", "ACTIVE")


@pytest.mark.asyncio
async def test_master_tool_fallback_subfinder_to_crtsh(tmp_path):
    tm = ToolManager()
    registry = MasterToolRegistry(tm)

    # Force subfinder as unavailable so fallback triggers
    with patch.object(registry, "is_available", return_value=False):
        with patch("core.playbooks.bug_bounty_methodology.BugBountyMethodology.fetch_crtsh_subdomains", new_callable=AsyncMock) as mock_crt:
            mock_crt.return_value = ["api.example.com", "dev.example.com"]
            results, log_file = await registry.execute("subfinder", {"domain": "example.com"})

            assert results == ["api.example.com", "dev.example.com"]
            assert log_file is not None
            assert os.path.exists(log_file)


@pytest.mark.asyncio
async def test_master_tool_fallback_gobuster_to_python_dir_fuzz():
    tm = ToolManager()
    registry = MasterToolRegistry(tm)

    fake_result = ToolResult(
        tool="python_dir_fuzz",
        command="fuzz https://example.com",
        stdout="[+] (Status: 200) /admin [Size: 1234]\n[+] (Status: 200) /login [Size: 567]",
        stderr="",
        returncode=0,
        duration=0.4,
        output_file="data/tool_outputs/fake_fuzz.txt"
    )

    with patch.object(registry, "is_available", return_value=False):
        with patch("tools.web_tools.WebTools.python_dir_fuzz", new_callable=AsyncMock) as mock_fuzz:
            mock_fuzz.return_value = fake_result
            results, log_file = await registry.execute("gobuster", {"url": "https://example.com", "wordlist": "dummy.txt"})

            assert len(results) == 2
            assert any("/admin" in r for r in results)
            assert any("/login" in r for r in results)
            assert log_file == "data/tool_outputs/fake_fuzz.txt"


@pytest.mark.asyncio
async def test_master_tool_fallback_nmap_to_python_socket_scan():
    tm = ToolManager()
    registry = MasterToolRegistry(tm)

    with patch.object(registry, "is_available", return_value=False):
        # Mock socket to report port 80 and 443 open
        with patch("socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            def fake_connect(addr):
                port = addr[1]
                return 0 if port in (80, 443) else 1
            mock_sock.connect_ex.side_effect = fake_connect
            mock_sock_cls.return_value = mock_sock

            results, log_file = await registry.execute("nmap", {"host": "127.0.0.1"})
            assert len(results) == 2
            assert any("80/tcp" in r for r in results)
            assert any("443/tcp" in r for r in results)
            assert log_file is not None


# =====================================================================
# 2. Correlation Engine Tests
# =====================================================================

def test_correlation_engine_attack_surface():
    endpoints = [
        EndpointRecord(url="https://api.example.com/v1/users", path="/v1/users", method="GET", source="crawler"),
        EndpointRecord(url="https://example.com/about", path="/about", method="GET", source="crawler"),
    ]
    parameters = [
        ParameterRecord(parameter="user_id", endpoint="https://api.example.com/v1/users", potential_classes=["IDOR", "SQLi"]),
        ParameterRecord(parameter="lang", endpoint="https://example.com/about", potential_classes=["LFI"]),
    ]
    secrets = [
        SecretFindingRecord(
            file_url="https://api.example.com/main.js",
            secret_type="stripe_api_key",
            matched_string="sk_live_123",
            line_number=12
        )
    ]
    live_assets = [
        LiveAssetRecord(url="https://api.example.com", host="api.example.com", status_code=200, asset_class=AssetCategory.API),
        LiveAssetRecord(url="https://example.com", host="example.com", status_code=200, asset_class=AssetCategory.WEB),
    ]

    correlated = CorrelationEngine.correlate_attack_surface(endpoints, parameters, secrets, live_assets)
    assert len(correlated) == 2

    # The API endpoint with IDOR+SQLi and exposed secrets should have highest score
    top_target = correlated[0]
    assert top_target["parameter"] == "user_id"
    assert "https://api.example.com" in top_target["endpoint"]
    assert top_target["relevance_score"] > correlated[1]["relevance_score"]
    assert top_target["is_live"] is True
    assert any("Associated with exposed client secrets" in r for r in top_target["reasons"])


# =====================================================================
# 3. Deduplication & Bayesian Confidence Engine Tests
# =====================================================================

def test_deduplication_engine_bayesian_confidence():
    f1 = HunterFinding(
        finding="SQL Injection via id",
        asset="api.example.com",
        endpoint="https://api.example.com/items",
        parameter="id",
        vuln_type="SQLi",
        status=FindingStatus.CONFIRMED,
        severity="High",
        confidence=0.80,
        cvss_score=8.5,
        tool="sqli_skill",
        evidence=[VerificationEvidence(type="time_based", description="5s delay confirmed", proof_snippet="5000ms delay", verified=True)]
    )

    f2 = HunterFinding(
        finding="SQLi UNION in items endpoint",
        asset="api.example.com",
        endpoint="https://api.example.com/items?filter=all",
        parameter="id",
        vuln_type="SQL_Injection",
        status=FindingStatus.CONFIRMED,
        severity="Critical",
        confidence=0.80,
        cvss_score=9.8,
        tool="nuclei",
        evidence=[VerificationEvidence(type="controlled_execution", description="Version string extracted", proof_snippet="14.2-Debian", verified=True)]
    )

    findings = [f1, f2]
    deduped = DeduplicationEngine.deduplicate(findings)

    # Both refer to https://api.example.com/items with param id and SQLi -> merged into 1
    assert len(deduped) == 1
    merged = deduped[0]

    # Bayesian confidence: 1 - (1 - 0.8) * (1 - 0.8) = 1 - 0.04 = 0.96
    assert merged.confidence == 0.96
    # CVSS score is the maximum of the two (9.8)
    assert merged.cvss_score == 9.8
    # Merged evidence has both proofs
    assert len(merged.evidence) == 2
    # Both tools mentioned
    assert "sqli_skill" in merged.tool
    assert "nuclei" in merged.tool


# =====================================================================
# 4. Priority Engine Tests (P0 to P5)
# =====================================================================

def test_priority_engine_tiers():
    findings = [
        HunterFinding(
            finding="Unverified Hypothesis",
            asset="example.com",
            endpoint="https://example.com/test",
            vuln_type="XSS",
            status=FindingStatus.UNVERIFIED,
            severity="Medium",
            cvss_score=6.0
        ),
        HunterFinding(
            finding="Info / Port open",
            asset="example.com",
            endpoint="https://example.com",
            vuln_type="info",
            status=FindingStatus.CONFIRMED,
            severity="Informational",
            cvss_score=0.0
        ),
        HunterFinding(
            finding="Missing Security Header",
            asset="example.com",
            endpoint="https://example.com",
            vuln_type="headers",
            status=FindingStatus.CONFIRMED,
            severity="Low",
            cvss_score=3.5
        ),
        HunterFinding(
            finding="Reflected XSS",
            asset="example.com",
            endpoint="https://example.com/search",
            vuln_type="XSS",
            status=FindingStatus.CONFIRMED,
            severity="Medium",
            cvss_score=6.1
        ),
        HunterFinding(
            finding="Blind SSRF to AWS Metadata",
            asset="example.com",
            endpoint="https://example.com/webhook",
            vuln_type="SSRF",
            status=FindingStatus.CONFIRMED,
            severity="High",
            cvss_score=8.6
        ),
        HunterFinding(
            finding="Pre-Auth Remote Code Execution",
            asset="example.com",
            endpoint="https://example.com/cmd",
            vuln_type="Command Injection",
            status=FindingStatus.CONFIRMED,
            severity="Critical",
            cvss_score=9.8
        ),
    ]

    # Verify individual priority assignments
    assert PriorityEngine.assign_priority(findings[0]) == "P5"  # UNVERIFIED -> P5
    assert PriorityEngine.assign_priority(findings[1]) == "P4"  # 0.0 -> P4
    assert PriorityEngine.assign_priority(findings[2]) == "P3"  # 3.5 -> P3
    assert PriorityEngine.assign_priority(findings[3]) == "P2"  # 6.1 -> P2
    assert PriorityEngine.assign_priority(findings[4]) == "P1"  # 8.6 -> P1
    assert PriorityEngine.assign_priority(findings[5]) == "P0"  # 9.8 -> P0

    # Verify ranked ordering (P0 first, then P1, P2, P3, P4, P5)
    ranked = PriorityEngine.rank_findings(findings)
    assert len(ranked) == 6
    priorities = [tier for tier, _ in ranked]
    assert priorities == ["P0", "P1", "P2", "P3", "P4", "P5"]


# =====================================================================
# 5. HunterPipelineOrchestrator Execution: Authorized vs Restricted
# =====================================================================

@pytest.mark.asyncio
async def test_orchestrator_safe_mode_restricted(tmp_path):
    orch = HunterPipelineOrchestrator(
        target="http://example.com",
        session_id="test_safe_sess",
        in_scope=["example.com"],
        authorized=False,
        workflow="full"
    )
    orch.artifact_root = str(tmp_path)

    # Mock tool executions and external network
    with patch.object(orch.master_tools, "execute", new_callable=AsyncMock) as mock_exec:
        mock_exec.return_value = ([], None)
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_http_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = "<html><body>Hello World</body></html>"
            mock_resp.content = b"<html><body>Hello World</body></html>"
            mock_resp.headers = {"server": "nginx"}
            mock_resp.url = "http://example.com"
            mock_http_get.return_value = mock_resp

            res = await orch.run()
            assert res["status"] == "completed"
            assert orch.authorized is False

            # Verify reports generated
            rep_dir = os.path.join(orch.artifact_root, "09_reports")
            assert os.path.exists(os.path.join(rep_dir, "bug_bounty_report.md"))
            assert os.path.exists(os.path.join(rep_dir, "final_findings.json"))

            with open(os.path.join(rep_dir, "bug_bounty_report.md"), "r", encoding="utf-8") as f:
                content = f.read()
                assert "RESTRICTED (Safe)" in content


@pytest.mark.asyncio
async def test_orchestrator_authorized_mode(tmp_path):
    orch = HunterPipelineOrchestrator(
        target="https://target.com",
        session_id="test_auth_sess",
        in_scope=["target.com"],
        authorized=True,
        workflow="full"
    )
    orch.artifact_root = str(tmp_path)

    with patch.object(orch.master_tools, "execute", new_callable=AsyncMock) as mock_exec:
        mock_exec.return_value = ([], None)
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_http_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = "<html><body>Target Active</body></html>"
            mock_resp.content = b"<html><body>Target Active</body></html>"
            mock_resp.headers = {"server": "apache"}
            mock_resp.url = "https://target.com"
            mock_http_get.return_value = mock_resp

            res = await orch.run()
            assert res["status"] == "completed"
            assert orch.authorized is True

            rep_dir = os.path.join(orch.artifact_root, "09_reports")
            assert os.path.exists(os.path.join(rep_dir, "bug_bounty_report.md"))
            with open(os.path.join(rep_dir, "bug_bounty_report.md"), "r", encoding="utf-8") as f:
                content = f.read()
                assert "AUTHORIZED" in content
