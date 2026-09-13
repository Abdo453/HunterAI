"""
HunterAI V9.0 Swarm Intelligence & Remediation Test Suite
=========================================================
Verifies:
1. Multi-Agent Swarm Intelligence & Blackboard (Scout, Logic, Protocol, Defender Shadow)
2. Adaptive Session Self-Healing & MFA Injection Engine
3. AST-Level Code Auto-Remediation & Regression Patching
4. Attack Path Chaining & Compound Risk Modeling
"""
import pytest
import time
import base64
import json
from core.swarm.swarm_coordinator import (
    SwarmCoordinator,
    SwarmBlackboard,
    SwarmObservation,
    SwarmAgentRole,
    DefenderShadowAgent,
)
from core.session_auth.session_healer import (
    SessionHealer,
    SessionCredentials,
    SessionLivenessStatus,
)
from core.remediation.ast_patch_engine import (
    ASTPatchEngine,
    VulnerabilityPatchRequest,
    PatchResult,
)
from core.chains.attack_path_chain import (
    AttackPathChainingEngine,
    CompoundImpactTier,
)


# ─── 1. SWARM INTELLIGENCE TESTS ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_swarm_coordinator_full_mission():
    coordinator = SwarmCoordinator(target_host="api.test.local", max_requests_budget=2000)
    res = await coordinator.run_swarm_mission()

    assert res["target"] == "api.test.local"
    assert res["status"] == "SWARM_MISSION_COMPLETE"
    assert res["endpoints_discovered"] >= 4
    assert res["total_requests"] >= 10
    assert res["stealth_score"] >= 80.0
    assert res["alert_ceiling_exceeded"] is False


def test_swarm_blackboard_and_defender_shadow():
    board = SwarmBlackboard()
    board.post_observation(SwarmObservation(
        observation_id="OBS-01",
        source_agent=SwarmAgentRole.SCOUT,
        endpoint="https://api.test.local/users",
        category="ASSET",
        data={"endpoint": "https://api.test.local/users"}
    ))
    assert len(board.discovered_endpoints) == 1

    # Simulate 2 WAF blocks and 1 High alert
    board.record_telemetry_signal("WAF_BLOCK", "MEDIUM", "Parameter payload blocked by WAF")
    board.record_telemetry_signal("WAF_BLOCK", "MEDIUM", "Second block")
    board.record_telemetry_signal("SIEM_ALERT", "HIGH", "Repeated 403 status spike")

    shadow = DefenderShadowAgent("shadow-test", board, max_alert_threshold=3)
    metrics = shadow.calculate_stealth_metrics(total_agent_requests=50)

    # 2*15 (WAF) + 1*20 (SIEM) = 50 penalty -> 50.0 stealth
    assert metrics.stealth_score == 50.0
    assert metrics.waf_triggers == 2
    assert metrics.simulated_siem_alerts == 1
    assert metrics.alert_ceiling_exceeded is False


# ─── 2. SESSION SELF-HEALING & MFA TESTS ─────────────────────────────────────

def test_session_healer_liveness_detection():
    creds = SessionCredentials(access_token="tok_initial_123")
    healer = SessionHealer(creds)

    # 1. Active response
    assert healer.inspect_response_liveness(200, '{"status": "ok"}') == SessionLivenessStatus.ACTIVE

    # 2. HTTP 401 Expiration
    assert healer.inspect_response_liveness(401, '{"error": "Unauthorized"}') == SessionLivenessStatus.EXPIRED

    # 3. Login redirect
    headers = {"Location": "/auth/login?expired=true"}
    assert healer.inspect_response_liveness(302, "", headers) == SessionLivenessStatus.EXPIRED

    # 4. Keyword in body
    assert healer.inspect_response_liveness(200, '{"msg": "Your session expired. Please log in"}') == SessionLivenessStatus.EXPIRED

    # 5. MFA challenge
    assert healer.inspect_response_liveness(403, '{"mfa": true, "error": "TOTP required"}') == SessionLivenessStatus.MFA_REQUIRED


@pytest.mark.asyncio
async def test_session_healer_token_refresh_and_rehydrate():
    creds = SessionCredentials(access_token="tok_expired", refresh_token="ref_valid_999")

    async def fake_refresh(refresh_tok: str) -> SessionCredentials:
        return SessionCredentials(access_token="tok_fresh_001", refresh_token=refresh_tok)

    healer = SessionHealer(creds, refresh_callback=fake_refresh)
    result = await healer.heal_session(SessionLivenessStatus.EXPIRED)

    assert result.was_healed is True
    assert result.new_status == SessionLivenessStatus.ACTIVE
    assert healer.credentials.access_token == "tok_fresh_001"

    # Re-hydrate request headers
    headers = {"Content-Type": "application/json"}
    rehydrated = healer.rehydrate_request_headers(headers)
    assert rehydrated["Authorization"] == "Bearer tok_fresh_001"


@pytest.mark.asyncio
async def test_session_healer_mfa_hook_resolution():
    creds = SessionCredentials(access_token="tok_user")

    async def prompt_mfa(challenge_msg: str) -> str:
        return "123456"

    healer = SessionHealer(creds, mfa_callback=prompt_mfa)
    result = await healer.heal_session(SessionLivenessStatus.MFA_REQUIRED)

    assert result.was_healed is True
    assert "123456" in healer.credentials.access_token


# ─── 3. AST AUTO-REMEDIATION TESTS ───────────────────────────────────────────

def test_ast_patch_engine_sqli():
    req = VulnerabilityPatchRequest(
        cwe_id="CWE-89",
        file_path="backend/users.py",
        target_parameter="username"
    )
    patch = ASTPatchEngine.generate_patch(req)

    assert patch.cwe_id == "CWE-89"
    assert "--- a/backend/users.py" in patch.git_diff
    assert "%s" in patch.patched_snippet
    assert "test_get_record_parameterized" in patch.regression_test_code


def test_ast_patch_engine_bola():
    req = VulnerabilityPatchRequest(
        cwe_id="CWE-639",
        file_path="backend/documents.py",
        target_parameter="doc_id"
    )
    patch = ASTPatchEngine.generate_patch(req)

    assert patch.cwe_id == "CWE-639"
    assert "PermissionDenied" in patch.patched_snippet
    assert "test_resource_owner_isolation" in patch.regression_test_code


def test_ast_patch_engine_xss_and_ssrf():
    # XSS
    patch_xss = ASTPatchEngine.generate_patch(VulnerabilityPatchRequest("CWE-79", "views/page.py", "comment"))
    assert "escape" in patch_xss.patched_snippet

    # SSRF
    patch_ssrf = ASTPatchEngine.generate_patch(VulnerabilityPatchRequest("CWE-918", "services/fetch.py", "url"))
    assert "169.254." in patch_ssrf.patched_snippet


# ─── 4. ATTACK PATH CHAINING TESTS ───────────────────────────────────────────

def test_attack_path_chaining_compound_risk():
    sample_findings = [
        {
            "finding_id": "F-LEAK-01",
            "cwe": "CWE-200",
            "title": "UUID Info Disclosure",
            "endpoint": "/api/v1/users/export",
            "severity": "LOW"
        },
        {
            "finding_id": "F-BOLA-02",
            "cwe": "CWE-639",
            "title": "Cross-Tenant BOLA Access",
            "endpoint": "/api/v1/invoices/102",
            "severity": "MEDIUM"
        }
    ]
    chains = AttackPathChainingEngine.analyze_compound_paths(sample_findings)

    assert len(chains) >= 1
    chain = chains[0]
    assert chain.compound_impact in (CompoundImpactTier.HIGH, CompoundImpactTier.CRITICAL)
    assert chain.composite_cvss >= 8.5
    assert len(chain.stages) == 2

    # Verify ASCII topology representation renders properly
    topo = chain.format_topology_ascii()
    assert "COMPOUND ATTACK PATH" in topo
    assert "Business Impact" in topo
    assert "Mitigation Priority" in topo
