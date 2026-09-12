"""
Unit and Integration Tests for:
1. EvidenceGraph & DeterministicEvidenceValidator (Hypothesis -> Differential Evidence -> Decision Gate)
2. ContextCompressor (Knowledge Handoff Contract: JS to WhiteRabbitNeo)
3. ScopePolicy Private Lab Mode (RFC1918 allowed when lab_mode=True, Cloud metadata still blocked)
"""
import pytest
from core.evidence_graph import (
    EvidenceGraph,
    DeterministicEvidenceValidator,
    NodeStatus,
)
from hunter_ai.protocol.context_compressor import (
    ContextCompressor,
    CompressedKnowledgePackage,
)
from core.scope_engine import StrictScopeEngine, ScopePolicy


# ── 1. EVIDENCE GRAPH & DETERMINISTIC VALIDATOR TESTS ────────────────────────

def test_evidence_graph_hierarchy_and_serialization():
    """Verify hierarchical linking: Target -> Subdomain -> Endpoint -> Parameter -> Evidence"""
    graph = EvidenceGraph("target.com")

    # Add observation
    graph.record_observation("api.target.com", "https://api.target.com/users", "/users", "id", "Reflection of user id in response")

    # Propose hypothesis by WhiteRabbitNeo
    hyp = graph.propose_hypothesis(
        sub="api.target.com",
        url="https://api.target.com/users",
        path="/users",
        param_name="id",
        vuln_class="IDOR",
        proposed_by="WhiteRabbitNeo",
        rationale="Numeric ID parameter exposed without tenant authorization header",
        test_plan="Compare response when swapping session cookie between user_a and user_b"
    )
    assert hyp.vuln_class == "IDOR"
    assert hyp.proposed_by_model == "WhiteRabbitNeo"

    # Record differential evidence
    ev = graph.record_differential_evidence(
        sub="api.target.com",
        url="https://api.target.com/users",
        path="/users",
        param_name="id",
        req="GET /users?id=123 HTTP/1.1\r\nHost: api.target.com",
        resp="HTTP/1.1 200 OK\r\n\r\n{\"email\": \"admin@target.com\"}",
        evidence_type="behavioral_diff",
        diff_analysis="User B session retrieved User A private profile data"
    )
    assert ev.request_hash != ""
    assert ev.response_hash != ""

    # Verify JSON tree serialization
    tree = graph.to_dict()
    assert tree["root_target"] == "target.com"
    assert "api.target.com" in tree["subdomains"]
    assert "GET:https://api.target.com/users" in tree["subdomains"]["api.target.com"]["endpoints"]
    p_node = tree["subdomains"]["api.target.com"]["endpoints"]["GET:https://api.target.com/users"]["parameters"]["id"]
    assert p_node["status"] == "evidence_gathered"
    assert len(p_node["hypotheses"]) == 1
    assert len(p_node["evidence"]) == 1


def test_deterministic_evidence_validator_arithmetic_nonce():
    """Verify deterministic validator proves command execution via arithmetic nonce (41+1=42)"""
    # Success case
    ok, score, msg = DeterministicEvidenceValidator.evaluate_arithmetic_proof("uid=1000(app) gid=1000 Result: 42", expected_nonce=42)
    assert ok is True
    assert score >= 0.95
    assert "Arithmetic nonce 42 evaluated" in msg

    # Failure case (e.g. false positive in-band HTML reflection)
    bad, score, _ = DeterministicEvidenceValidator.evaluate_arithmetic_proof("Error: $((41+1)) is not supported", expected_nonce=42)
    assert bad is False
    assert score == 0.0


def test_deterministic_evidence_validator_decision_gate():
    """Verify finding is created ONLY when evidence and confidence threshold pass"""
    graph = EvidenceGraph("target.com")
    p = graph.get_or_create_parameter("api.target.com", "https://api.target.com/user", "/user", "id")

    # Before evidence: decision must reject
    finding = DeterministicEvidenceValidator.decide_finding(p, "https://api.target.com/user", "IDOR")
    assert finding is None
    assert p.status == NodeStatus.REJECTED

    # Attach evidence with high confidence
    graph.record_differential_evidence(
        sub="api.target.com",
        url="https://api.target.com/user",
        path="/user",
        param_name="id",
        req="GET /user?id=2",
        resp="{\"data\": 2}",
        evidence_type="behavioral_diff",
        diff_analysis="Bypass confirmed"
    )
    p.confidence_score = 0.95  # Above 0.85 threshold

    finding = DeterministicEvidenceValidator.decide_finding(p, "https://api.target.com/user", "IDOR")
    assert finding is not None
    assert finding["status"] == "CONFIRMED"
    assert p.status == NodeStatus.VERIFIED


# ── 2. CONTEXT COMPRESSION & MODEL HANDOFF CONTRACT TESTS ────────────────────

def test_context_compression_schema():
    """Verify JS crawling outputs compress into the standardized handoff package"""
    pkg = ContextCompressor.compress_js_recon(
        asset="app.target.com",
        raw_endpoints=["/api/v1/auth", "/api/v1/users", "/api/v1/export", "/api/v1/users"],
        discovered_params=["id", "token", "query", "id"],
        detected_secrets=[{"type": "StripeKey", "matched": "sk_live_••••••••1234"}],
        technologies=["React", "Webpack", "Nginx"],
        raw_artifacts_path="data/engagements/app_target_com/2026/09_javascript/raw.json"
    )
    assert pkg.asset == "app.target.com"
    # Deduplicated endpoints
    assert len(pkg.interesting_endpoints) == 3
    assert len(pkg.parameters) == 3
    assert len(pkg.secrets) == 1
    assert "data/engagements/app_target_com/2026/09_javascript/raw.json" in pkg.evidence_refs

    # Dense prompt for WhiteRabbitNeo
    prompt = ContextCompressor.prepare_white_rabbit_prompt(pkg)
    assert "TACTICAL TARGET INTELLIGENCE:" in prompt
    assert "High-Value Endpoints" in prompt
    assert "TASK FOR WHITERABBITNEO:" in prompt


# ── 3. PRIVATE LAB MODE TESTS ────────────────────────────────────────────────

def test_scope_lab_mode_permits_private_ip():
    """Verify allow_private_ips_override permits RFC1918 subnets while keeping cloud metadata blocked"""
    lab_policy = ScopePolicy(
        allowed_targets=["192.168.1.0/24", "10.10.10.5", "169.254.169.254"],
        allow_private_ips_override=True  # Lab mode enabled
    )
    engine = StrictScopeEngine(lab_policy)

    # 1. Private RFC1918 permitted under lab mode
    assert engine.validate_target("192.168.1.50")[0] is True
    assert engine.validate_target("10.10.10.5")[0] is True

    # 2. Cloud metadata & loopback STILL blocked even under lab mode!
    assert engine.validate_target("169.254.169.254")[0] is False
    assert engine.validate_target("metadata.google.internal")[0] is False
