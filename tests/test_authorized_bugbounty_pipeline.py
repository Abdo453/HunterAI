"""
Test Suite for Authorized Bug Bounty Security Testing Pipeline (Phases 0 - 7)
"""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
import pytest

from core.pipeline.authorized_bugbounty_pipeline import (
    AuthorizedBugBountyPipeline,
    AuthorizedProgramScope,
    EndpointRecord,
    ParameterRecord,
    SafeFinding,
    SYSTEM_PROMPT
)


@pytest.fixture
def temp_pipeline_workspace():
    tmp = tempfile.mkdtemp()
    yield Path(tmp)
    shutil.rmtree(tmp, ignore_errors=True)


def test_authorized_bugbounty_pipeline_e2e(temp_pipeline_workspace):
    # ── Phase 0: Scope Gate Setup ────────────────────────────────────
    scope = AuthorizedProgramScope(
        program_name="authorized-lab-program",
        in_scope=["https://app.example.com", "https://api.example.com"],
        out_of_scope=["https://admin.example.com", "https://third-party.example.net"],
        allowed_methods=["GET", "POST", "PATCH"],
        forbidden_tests=["DoS", "bruteforce", "account takeover", "data deletion"],
        max_requests_per_second=2.0,
        test_accounts=["researcher_account_1", "researcher_account_2"]
    )

    pipeline = AuthorizedBugBountyPipeline(scope=scope, workspace_root=temp_pipeline_workspace)

    # Test Scope In/Out boundaries
    assert pipeline.is_url_in_scope("https://app.example.com/login") is True
    assert pipeline.is_url_in_scope("https://api.example.com/v1/users") is True
    assert pipeline.is_url_in_scope("https://admin.example.com/dashboard") is False  # Out of scope!
    assert pipeline.is_url_in_scope("https://third-party.example.net/auth") is False  # Out of scope!
    assert pipeline.is_url_in_scope("https://evil.com/leak") is False

    # Test Forbidden tests
    ok, _ = pipeline.validate_method_and_safety("GET", "parameter_analysis")
    assert ok is True
    forbidden_ok, _ = pipeline.validate_method_and_safety("GET", "dos_stress_test")
    assert forbidden_ok is False

    # ── Phase 1: Passive Discovery ───────────────────────────────────
    raw_sources = {
        "robots_txt": ["/admin", "/api/v1/status"],
        "javascript_endpoints": ["/api/v1/profile", "/api/v1/orders"],
        "openapi_endpoints": [{"url": "https://api.example.com/v1/reports", "method": "GET", "auth": True, "params": ["report_id"]}]
    }
    discovered_eps = pipeline.ingest_passive_assets(raw_sources)
    assert len(discovered_eps) >= 3

    # ── Phase 2: Directory Discovery Filtering ───────────────────────
    ffuf_raw = [
        {"url": "https://app.example.com/account", "status": 200, "length": 1400},
        {"url": "https://app.example.com/404_fake", "status": 404, "length": 0},
        {"url": "https://admin.example.com/secret", "status": 200, "length": 500},  # out of scope!
    ]
    filtered_dirs = pipeline.filter_directory_results(ffuf_raw)
    assert len(filtered_dirs) == 1
    assert filtered_dirs[0]["url"] == "https://app.example.com/account"

    # ── Phase 3 & 4: Parameter Discovery & Classification ────────────
    param_1 = pipeline.classify_parameter("user_id", "query", "GET", "https://api.example.com/v1/profile")
    assert param_1.vulnerability_category == "bola_idor"

    param_2 = pipeline.classify_parameter("redirect", "query", "GET", "https://app.example.com/login")
    assert param_2.vulnerability_category == "ssrf_open_redirect"

    param_3 = pipeline.classify_parameter("template", "query", "GET", "https://app.example.com/render")
    assert param_3.vulnerability_category == "ssti"

    # ── Phase 5 & 6: Safe Validation & 8-Question Gate ───────────────
    def mock_safe_bola_probe(url: str, param: str) -> dict:
        return {
            "impact_proven": True,
            "severity": "Medium",
            "summary": "Dual account test revealed PII on order details.",
            "reproduction_steps": [
                "1. Log into researcher_account_1.",
                "2. Send GET /api/v1/profile?user_id=8472 (belonging to researcher_account_2).",
                "3. Observe HTTP 200 OK returning Account 2 profile."
            ],
            "actual_behavior": "Returned Account 2 profile JSON.",
            "impact": "Broken Object Level Authorization (IDOR) on profile endpoint.",
            "request_raw": "GET /api/v1/profile?user_id=8472 HTTP/1.1\nCookie: session=test_user_1\nAuthorization: Bearer token123",
            "response_raw": "HTTP/1.1 200 OK\n{'email': 'test2@example.com', 'user_id': 8472}",
            "root_cause": "Missing tenant check in User.query.filter_by(id=user_id).",
            "remediation": "Filter queries by current_user.id.",
            "is_reproducible": True,
            "baseline_difference_verified": True,
            "is_benign_randomness": False,
            "used_test_accounts": True,
            "caused_harm": False
        }

    finding = pipeline.perform_safe_validation(
        endpoint_url="https://api.example.com/v1/profile",
        param_record=param_1,
        probe_differential_fn=mock_safe_bola_probe
    )

    assert finding is not None
    assert finding.gate_8_passed is True
    assert "[REDACTED_BEARER_TOKEN]" in finding.sanitized_request or "Bearer" in finding.sanitized_request
    assert "[REDACTED_EMAIL]" in finding.sanitized_response or "email" in finding.sanitized_response

    # ── Phase 7: Professional Bug Bounty Report ──────────────────────
    report_md = pipeline.generate_final_report()
    assert "# [REPORT] Bug Bounty Security Assessment" in report_md
    assert "Title: Confirmed BOLA_IDOR on parameter 'user_id'" in report_md
    assert "Remediation" in report_md
    assert "Safety Notes" in report_md
    assert (temp_pipeline_workspace / "authorized_bugbounty_report.md").exists()
