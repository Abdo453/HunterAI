"""
HunterAI Advanced Capabilities Test Suite
=========================================
Hermetic unit tests validating:
  1. RealToolAdapter (Sandboxed tool execution + graceful native fallback)
  2. DualIdentityMatrix (3-way differential IDOR/BOLA authorization testing)
  3. OOBEngine (Out-of-band blind SSRF/RCE canary generation and verification)
  4. PoCBundleGenerator (Automated Python repro, W3C HAR 1.2, and HackerOne report)
  5. End-to-end OmniHunterEngine integration with advanced flags
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.auth.identity_matrix import (
    DifferentialEvidence,
    DualIdentityMatrix,
    IDORVerdict,
    IdentityContext,
)
from core.engine.omni_hunter_engine import (
    AssessmentConfig,
    AssessmentResult,
    OmniHunterEngine,
)
from core.engine.poc_bundle_generator import (
    FindingContext,
    PoCBundleGenerator,
)
from core.engine.real_tool_adapter import (
    RealToolAdapter,
    ToolExecutionResult,
)
from core.oob.oob_engine import (
    OOBEngine,
    OOBVerdictReport,
)


# ── 1. Real Tool Adapter Tests ─────────────────────────────────────────────────

def test_tool_adapter_detects_availability():
    adapter = RealToolAdapter()
    # python should always be available in the test environment
    assert adapter.is_tool_available("python") or adapter.is_tool_available("python3")
    # non-existent tool must report False
    assert not adapter.is_tool_available("non_existent_fake_tool_xyz_999")


def test_subfinder_fallback_generates_valid_subdomains():
    adapter = RealToolAdapter(force_fallback=True)
    res = adapter.execute_subfinder("example.corp")
    assert res.success
    assert "discovered_subdomains" in res.structured_data
    subdomains = res.structured_data["discovered_subdomains"]
    assert any("api.example.corp" in s for s in subdomains)


def test_nmap_fallback_generates_standard_ports():
    adapter = RealToolAdapter(force_fallback=True)
    res = adapter.execute_nmap_ports("192.168.1.100")
    assert res.success
    assert "open_ports" in res.structured_data
    assert "80" in res.structured_data["open_ports"]
    assert "443" in res.structured_data["open_ports"]


def test_httpx_fallback_generates_endpoint_records():
    adapter = RealToolAdapter(force_fallback=True)
    urls = ["https://example.corp", "https://api.example.corp"]
    res = adapter.execute_httpx_endpoints(urls)
    assert res.success
    assert "alive_endpoints" in res.structured_data
    assert len(res.structured_data["alive_endpoints"]) == 2


# ── 2. Dual-Identity Matrix Tests ──────────────────────────────────────────────

def test_identity_matrix_detects_confirmed_idor():
    victim = IdentityContext(
        user_id="user_1002",
        username="alice",
        canary_data=["CONFIDENTIAL_ALICE_SSN_9988", "alice@secret.corp"],
    )
    attacker = IdentityContext(
        user_id="user_1001",
        username="bob",
    )
    matrix = DualIdentityMatrix(user_attacker=attacker, user_victim=victim)

    evidence = matrix.evaluate_differential(
        endpoint="https://api.corp.local/v1/users/1002/profile",
        victim_object_id="1002",
        victim_response_code=200,
        victim_response_body='{"id": 1002, "name": "alice", "ssn": "CONFIDENTIAL_ALICE_SSN_9988"}',
        attacker_response_code=200,
        attacker_response_body='{"id": 1002, "name": "alice", "ssn": "CONFIDENTIAL_ALICE_SSN_9988"}',
        unauth_response_code=401,
        unauth_response_body='{"error": "Unauthorized"}',
    )

    assert evidence.verdict == IDORVerdict.CONFIRMED_IDOR
    assert evidence.confidence >= 0.95
    assert "CONFIDENTIAL_ALICE_SSN_9988" in evidence.token_leakage_detected


def test_identity_matrix_detects_enforced_access():
    victim = IdentityContext(user_id="user_1002")
    attacker = IdentityContext(user_id="user_1001")
    matrix = DualIdentityMatrix(user_attacker=attacker, user_victim=victim)

    evidence = matrix.evaluate_differential(
        endpoint="https://api.corp.local/v1/users/1002/profile",
        victim_object_id="1002",
        victim_response_code=200,
        victim_response_body='{"id": 1002, "name": "alice"}',
        attacker_response_code=403,
        attacker_response_body='{"error": "Forbidden: Not object owner"}',
        unauth_response_code=401,
    )

    assert evidence.verdict == IDORVerdict.ENFORCED_ACCESS
    assert evidence.confidence >= 0.95


def test_identity_matrix_detects_public_resource():
    matrix = DualIdentityMatrix()
    evidence = matrix.evaluate_differential(
        endpoint="https://corp.local/public/catalog",
        victim_object_id="catalog",
        victim_response_code=200,
        victim_response_body='{"catalog": [1, 2, 3]}',
        attacker_response_code=200,
        attacker_response_body='{"catalog": [1, 2, 3]}',
        unauth_response_code=200,
        unauth_response_body='{"catalog": [1, 2, 3]}',
    )

    assert evidence.verdict == IDORVerdict.PUBLIC_ENDPOINT


# ── 3. Out-Of-Band (OOB) Engine Tests ──────────────────────────────────────────

def test_oob_engine_probe_generation():
    engine = OOBEngine(callback_domain="test.oob.corp")
    ctx, payloads = engine.create_probe("https://target.corp/api/fetch", "url", vuln_type="blind_ssrf")

    assert ctx.token in ctx.canary_domain
    assert "test.oob.corp" in ctx.canary_domain
    assert "dns_lookup" in payloads
    assert "http_url" in payloads
    assert ctx.canary_domain in payloads["dns_lookup"]


def test_oob_engine_verifies_callback():
    engine = OOBEngine(callback_domain="test.oob.corp")
    ctx, _ = engine.create_probe("https://target.corp/api/proxy", "dest_url", vuln_type="blind_ssrf")

    # Before interaction -> unconfirmed
    pre_report = engine.verify_interaction(ctx.token)
    assert not pre_report.is_confirmed

    # Simulate callback
    engine.simulate_mock_callback(ctx.token, protocol="DNS", origin_ip="198.51.100.99")

    # After interaction -> CONFIRMED with evidence artifact
    post_report = engine.verify_interaction(ctx.token)
    assert post_report.is_confirmed
    assert post_report.interaction_protocol == "DNS"
    assert post_report.origin_ip == "198.51.100.99"
    assert post_report.evidence_artifact is not None
    assert post_report.evidence_artifact.significance.value == "PROOF"


# ── 4. PoC Bundle Generator Tests ──────────────────────────────────────────────

def test_poc_bundle_generation(tmp_path):
    generator = PoCBundleGenerator(output_base_dir=tmp_path)
    finding = FindingContext(
        finding_id="FINDING-TEST-001",
        target_url="https://app.target.corp/api/v1/users/55",
        vuln_class="IDOR",
        parameter="id",
        http_method="GET",
        request_headers={"Authorization": "Bearer attacker_token"},
        response_status=200,
        response_body='{"id": 55, "email": "victim@target.corp"}',
        cvss_score=8.5,
    )

    bundle_dir = generator.generate_bundle(finding)
    assert bundle_dir.exists()

    # Verify 4 expected files
    assert (bundle_dir / "reproduce.py").exists()
    assert (bundle_dir / "evidence.har").exists()
    assert (bundle_dir / "report_hackerone.md").exists()
    assert (bundle_dir / "bundle_metadata.json").exists()

    # Validate HAR JSON structure
    with open(bundle_dir / "evidence.har", "r", encoding="utf-8") as f:
        har = json.load(f)
    assert "log" in har
    assert len(har["log"]["entries"]) == 1
    assert har["log"]["entries"][0]["request"]["url"] == finding.target_url

    # Validate Metadata checksums
    with open(bundle_dir / "bundle_metadata.json", "r", encoding="utf-8") as f:
        meta = json.load(f)
    assert meta["finding_id"] == "FINDING-TEST-001"
    assert len(meta["files"]) == 3


# ── 5. End-to-End Advanced Engine Loop ─────────────────────────────────────────

def test_omni_hunter_with_advanced_capabilities(tmp_path):
    user_a = IdentityContext(user_id="user_a", username="attacker")
    user_b = IdentityContext(user_id="user_b", username="victim", canary_data=["CANARY_SECRET"])

    config = AssessmentConfig(
        target_url="https://corp.example.com",
        scope_domains=["corp.example.com", "api.corp.example.com"],
        auth_user_a=user_a,
        auth_user_b=user_b,
        enable_oob=True,
        generate_poc_bundles=True,
        force_tool_fallback=True,
        coverage_threshold=0.01,
        max_cycles=2,
        snapshot_dir=str(tmp_path / "snapshots"),
        engagement_id="ENG-ADV-TEST",
    )

    engine = OmniHunterEngine(config)
    result = engine.run()

    assert result.engagement_id == "ENG-ADV-TEST"
    assert result.phase_reached.value == "REPORT"
    assert result.total_tasks > 0
    assert engine.tool_adapter is not None
    assert engine.identity_matrix is not None
    assert engine.oob_engine is not None
    assert engine.poc_generator is not None
