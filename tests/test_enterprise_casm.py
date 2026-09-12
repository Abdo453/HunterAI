"""
Unit and Integration Tests for HunterAI Enterprise CASM Architecture:
1. StrictScopeEngine: Invariant non-overridability (RFC1918, loopback, metadata, excluded paths/ports)
2. AdaptiveRateLimiter: Per-domain token bucket spacing, dynamic backoff, Retry-After, circuit breaker
3. SecretSanitizer: Token masking (AWS, Stripe, GitHub, JWT, DB URIs) across text and nested JSON
4. EngagementDiffEngine: Temporal diff calculation, asset growth, closed/opened ports, vulnerability drift
5. HunterPipelineOrchestrator: Integration with safe profile, passive profile, and invariant abort
"""
import asyncio
import json
import os
import shutil
import tempfile
import time
import pytest
from datetime import datetime

from core.scope_engine import StrictScopeEngine, ScopePolicy
from core.rate_limiter import AdaptiveRateLimiter, CircuitState
from core.secret_sanitizer import SecretSanitizer
from hunter_ai.pipeline.diff_engine import EngagementDiffEngine
from hunter_ai.pipeline.schemas import FindingTier, ProfileMode, HunterFinding, FindingStatus
from hunter_ai.pipeline.pipeline_orchestrator import HunterPipelineOrchestrator


# ── 1. STRICT SCOPE ENGINE & INVARIANTS ───────────────────────────────────────

def test_scope_invariants_hard_blocked():
    """Verify that inviolable safety invariants cannot be bypassed under any circumstances"""
    policy = ScopePolicy(
        allowed_targets=["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "localhost"],
        allow_internal_scanning=True  # Engine must ignore this override
    )
    engine = StrictScopeEngine(policy)

    # 1. Loopback
    allowed, reason = engine.validate_target("127.0.0.1")
    assert allowed is False
    assert "SECURITY INVARIANT" in reason or "internal" in reason

    allowed, reason = engine.validate_target("localhost")
    assert allowed is False

    # 2. RFC1918 Private Subnets
    assert engine.validate_target("10.1.2.3")[0] is False
    assert engine.validate_target("172.16.0.1")[0] is False
    assert engine.validate_target("192.168.1.254")[0] is False

    # 3. Cloud Metadata Services
    assert engine.validate_target("169.254.169.254")[0] is False
    assert engine.validate_target("metadata.google.internal")[0] is False


def test_scope_allowed_targets_and_wildcards():
    """Verify domain allowlisting and wildcard matching for valid public assets"""
    policy = ScopePolicy(
        allowed_targets=["target.com", "*.target.com", "203.0.113.0/24"],
        excluded_targets=["admin.target.com"]
    )
    engine = StrictScopeEngine(policy)

    # Root and subdomains
    assert engine.validate_target("target.com")[0] is True
    assert engine.validate_target("api.target.com")[0] is True
    assert engine.validate_target("deep.sub.target.com")[0] is True

    # Explicit exclusion
    allowed, reason = engine.validate_target("admin.target.com")
    assert allowed is False
    assert "out-of-scope" in reason.lower() or "excluded" in reason.lower()

    # Out of scope domain
    allowed, _ = engine.validate_target("evil.com")
    assert allowed is False

    # Public CIDR
    assert engine.validate_target("203.0.113.42")[0] is True
    assert engine.validate_target("203.0.114.1")[0] is False


def test_scope_excluded_paths_and_ports():
    """Verify safety exclusion of sensitive destruction paths and mail relay ports"""
    policy = ScopePolicy(allowed_targets=["target.com", "*.target.com"])
    engine = StrictScopeEngine(policy)

    # Path exclusions
    assert engine.validate_url("https://target.com/dashboard")[0] is True
    assert engine.validate_url("https://target.com/logout")[0] is False
    assert engine.validate_url("https://target.com/auth/signout")[0] is False
    assert engine.validate_url("https://target.com/api/v1/delete_account")[0] is False

    # Port exclusions
    assert engine.is_port_allowed(80) is True
    assert engine.is_port_allowed(443) is True
    assert engine.is_port_allowed(25) is False
    assert engine.is_port_allowed(465) is False
    assert engine.is_port_allowed(587) is False


# ── 2. ADAPTIVE RATE LIMITER & CIRCUIT BREAKER ───────────────────────────────

@pytest.mark.asyncio
async def test_adaptive_rate_limiter_spacing():
    """Verify that requests are spaced according to the configured rate limit"""
    limiter = AdaptiveRateLimiter(default_rate_limit_rps=10.0)  # min delay = 0.1s
    t0 = time.time()

    await limiter.acquire("api.example.com")
    await limiter.acquire("api.example.com")
    elapsed = time.time() - t0

    assert elapsed >= 0.08  # At least spaced out by min_delay


@pytest.mark.asyncio
async def test_rate_limiter_circuit_breaker():
    """Verify circuit trips OPEN after consecutive 429/503 errors and cools down"""
    limiter = AdaptiveRateLimiter(default_rate_limit_rps=20.0, failure_threshold=3, cooldown_seconds=0.2)
    host = "fragile.example.com"

    for _ in range(3):
        limiter.record_response(host, 429)

    state = limiter.get_state(host)
    assert state.circuit_state == CircuitState.OPEN

    # Trying to acquire while OPEN raises or pauses
    t0 = time.time()
    await limiter.acquire(host)  # Waits until cooldown expires
    assert time.time() - t0 >= 0.15


# ── 3. SECRET SANITIZER & CREDENTIAL MASKING ──────────────────────────────────

def test_secret_sanitizer_masking():
    """Verify regex scrubbing of sensitive keys in text and JSON structures"""
    raw_text = (
        "Found AWS key AKIAIOSFODNN7EXAMPLE and Stripe sk_live_51Abcdef1234567890XYZ "
        "and GitHub token ghp_1234567890abcdef1234567890abcdef1234"
    )
    sanitized = SecretSanitizer.sanitize_text(raw_text)

    # AWS
    assert "AKIA" in sanitized
    assert "••••••••" in sanitized
    assert "AKIAIOSFODNN7EXAMPLE" not in sanitized

    # Stripe
    assert "sk_live_" in sanitized
    assert "sk_live_51Abcdef1234567890XYZ" not in sanitized

    # GitHub
    assert "ghp_" in sanitized
    assert "ghp_1234567890abcdef1234567890abcdef1234" not in sanitized

    # Nested data structure
    nested = {
        "finding": "Leaked Credential",
        "evidence": ["Key: AKIAIOSFODNN7EXAMPLE"],
        "meta": {"token": "ghp_1234567890abcdef1234567890abcdef1234"}
    }
    cleaned = SecretSanitizer.sanitize_data(nested)
    assert "AKIAIOSFODNN7EXAMPLE" not in str(cleaned)
    assert "ghp_1234567890abcdef1234567890abcdef1234" not in str(cleaned)
    assert "••••••••" in cleaned["meta"]["token"]


# ── 4. ENGAGEMENT DIFF ENGINE ────────────────────────────────────────────────

def test_engagement_diff_engine_temporal_delta():
    """Verify temporal diff detects new subdomains, closed/opened ports, and resolved vulns"""
    temp_dir = tempfile.mkdtemp(prefix="test_diff_")
    try:
        run1_dir = os.path.join(temp_dir, "2026-09-01_100000")
        run2_dir = os.path.join(temp_dir, "2026-09-02_100000")
        os.makedirs(os.path.join(run1_dir, "02_subdomains"), exist_ok=True)
        os.makedirs(os.path.join(run2_dir, "02_subdomains"), exist_ok=True)
        os.makedirs(os.path.join(run1_dir, "05_ports"), exist_ok=True)
        os.makedirs(os.path.join(run2_dir, "05_ports"), exist_ok=True)
        os.makedirs(os.path.join(run1_dir, "14_reports"), exist_ok=True)
        os.makedirs(os.path.join(run2_dir, "14_reports"), exist_ok=True)

        # Run 1 data
        with open(os.path.join(run1_dir, "02_subdomains", "all_subdomains.txt"), "w") as f:
            f.write("sub1.target.com\nsub2.target.com\n")
        with open(os.path.join(run1_dir, "05_ports", "open_ports.txt"), "w") as f:
            f.write("target.com:80\ntarget.com:443\n")
        with open(os.path.join(run1_dir, "14_reports", "final_findings.json"), "w") as f:
            json.dump([{"vuln_type": "SQLi", "endpoint": "https://target.com/search", "parameter": "q", "finding": "SQL Injection on q"}], f)

        # Run 2 data (sub1 removed, sub3 added, port 8080 opened, SQLi resolved)
        with open(os.path.join(run2_dir, "02_subdomains", "all_subdomains.txt"), "w") as f:
            f.write("sub2.target.com\nsub3.target.com\n")
        with open(os.path.join(run2_dir, "05_ports", "open_ports.txt"), "w") as f:
            f.write("target.com:443\ntarget.com:8080\n")
        with open(os.path.join(run2_dir, "14_reports", "final_findings.json"), "w") as f:
            json.dump([{"vuln_type": "XSS", "endpoint": "https://target.com/profile", "parameter": "name", "finding": "Reflected XSS on name"}], f)

        diff_engine = EngagementDiffEngine(current_run_dir=run2_dir, previous_run_dir=run1_dir)
        diff = diff_engine.compute_diff()

        assert diff["is_baseline"] is False
        assert "sub3.target.com" in diff["subdomains"]["added"]
        assert "sub1.target.com" in diff["subdomains"]["removed"]
        assert "target.com:8080" in diff["ports"]["added"]
        assert "target.com:80" in diff["ports"]["closed"]
        assert len(diff["findings"]["new"]) == 1
        assert diff["findings"]["new"][0]["vuln_type"] == "XSS"
        assert len(diff["findings"]["resolved"]) == 1
        assert diff["findings"]["resolved"][0]["vuln_type"] == "SQLi"

        # Generate markdown report
        md = diff_engine.generate_markdown_report(diff, "target.com")
        assert "Attack Surface Drift" in md
        assert "sub3.target.com" in md
        assert "Newly Opened Ports" in md
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


# ── 5. ORCHESTRATOR INTEGRATION & GOVERNANCE PROFILES ─────────────────────────

@pytest.mark.asyncio
async def test_orchestrator_invariant_abort_on_loopback():
    """Verify orchestrator immediately aborts without scanning if target is loopback/private"""
    orch = HunterPipelineOrchestrator(
        target="127.0.0.1",
        profile="safe",
        authorized=False
    )
    result = await orch.run()
    assert result["status"] == "aborted"
    assert result["reason"] == "out_of_scope"


@pytest.mark.asyncio
async def test_orchestrator_passive_profile_and_diff():
    """Verify orchestrator runs cleanly under passive profile and generates artifacts and baseline diff"""
    orch = HunterPipelineOrchestrator(
        target="scanme.nmap.org",
        profile="passive",
        authorized=False,
        workflow="recon"
    )
    res = await orch.run()
    assert res["status"] == "completed"
    assert orch.profile == "passive"

    # Verify manifest stored profile
    manifest_path = orch.engagement_mgr.manifest_path
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest_data = json.load(f)
    assert manifest_data.get("profile") == "passive"

    # Verify diff report exists
    diff_md = os.path.join(orch.artifact_root, "14_reports", "diff_report.md")
    assert os.path.exists(diff_md)
    with open(diff_md, "r", encoding="utf-8") as f:
        diff_text = f.read()
    assert "HunterAI Temporal Diff" in diff_text
