"""
Test Suite for WAF-Aware Architecture & Rate-Limit Governor
Verifies defensive, non-evasive handling of WAFs and API Gateways.
"""
from __future__ import annotations

import pytest
from core.waf.waf_aware_governor import (
    WAFAwareGovernor,
    GatewayClassification,
    ResultClassification,
    WAF_SAFETY_POLICY
)


def test_gateway_response_classification():
    governor = WAFAwareGovernor(requests_per_second=2.0)

    # 1. Rate Limited (429)
    res_429 = governor.classify_gateway_response(
        status_code=429,
        response_headers={"Retry-After": "30"},
        response_body="Too Many Requests"
    )
    assert res_429 == GatewayClassification.RATE_LIMITED

    # 2. Blocked or Filtered (403 WAF block)
    res_403 = governor.classify_gateway_response(
        status_code=403,
        response_headers={"Server": "cloudflare"},
        response_body="Access Denied by WAF policy"
    )
    assert res_403 == GatewayClassification.BLOCKED_OR_FILTERED

    # 3. Upstream Error (502/503)
    res_502 = governor.classify_gateway_response(
        status_code=502,
        response_headers={"Server": "nginx"},
        response_body="Bad Gateway"
    )
    assert res_502 == GatewayClassification.UPSTREAM_OR_GATEWAY_ERROR

    # 4. Challenge Page
    res_chal = governor.classify_gateway_response(
        status_code=403,
        response_headers={},
        response_body="<html><title>Just a moment...</title>Cloudflare Turnstile challenge</html>"
    )
    assert res_chal == GatewayClassification.CHALLENGE

    # 5. Normal Application Response
    res_200 = governor.classify_gateway_response(
        status_code=200,
        response_headers={"Content-Type": "application/json"},
        response_body='{"items": [1, 2, 3]}'
    )
    assert res_200 == GatewayClassification.APPLICATION_RESPONSE


def test_rate_limit_governor_stopping_on_repeated_blocks():
    governor = WAFAwareGovernor(requests_per_second=5.0, max_consecutive_blocks=3)

    # First block
    cont, msg = governor.handle_rate_limit_feedback(403)
    assert cont is True
    assert governor.consecutive_blocks == 1

    # Second block
    cont, msg = governor.handle_rate_limit_feedback(403)
    assert cont is True
    assert governor.consecutive_blocks == 2

    # Third block -> triggers STOP_TEST_PATH without attempting evasion
    cont, msg = governor.handle_rate_limit_feedback(403)
    assert cont is False
    assert "STOP_TEST_PATH" in msg
    assert governor.consecutive_blocks == 3


def test_baseline_recording_and_comparison():
    governor = WAFAwareGovernor()

    # Record baseline for /search
    base = governor.record_baseline(
        endpoint_url="https://target.local/search?q=normal-test",
        method="GET",
        status_code=200,
        response_body="<html><head><title>Search Results</title></head><body>Found 10 items</body></html>",
        response_headers={"Content-Type": "text/html"},
        response_time_ms=45.0
    )
    assert base.status_code == 200
    assert base.title == "Search Results"

    # Compare with a probe result that gets blocked by WAF
    diff_block = governor.compare_with_baseline(
        endpoint_url="https://target.local/search?q=probe",
        method="GET",
        probe_status=403,
        probe_body="<html><head><title>403 Forbidden</title></head><body>Blocked by WAF</body></html>",
        probe_headers={"Content-Type": "text/html"},
        probe_time_ms=15.0
    )
    assert diff_block["status_changed"] is True
    assert diff_block["baseline_status"] == 200
    assert diff_block["probe_status"] == 403
    assert diff_block["title_changed"] is True


def test_strict_result_classification():
    governor = WAFAwareGovernor()

    # 1. WAF Block is NOT classified as a vulnerability!
    triage_waf = governor.classify_test_result(
        target_url="https://target.local/search",
        parameter_name="q",
        probe_status=403,
        probe_headers={"Server": "cloudflare"},
        probe_body="Blocked by firewall"
    )
    assert triage_waf.classification == ResultClassification.WAF_BLOCK
    assert triage_waf.vulnerability_confirmed is False
    assert triage_waf.next_action == "stop_and_request_manual_review"

    # 2. Confirmed safe differential with benign canary
    triage_vuln = governor.classify_test_result(
        target_url="https://target.local/search",
        parameter_name="q",
        probe_status=200,
        probe_headers={"Content-Type": "text/html"},
        probe_body="Found results: <b>hnt_canary</b>",
        benign_canary_reflected=True,
        proven_differential=True
    )
    assert triage_vuln.classification == ResultClassification.CONFIRMED_VULNERABILITY
    assert triage_vuln.vulnerability_confirmed is True
    assert triage_vuln.next_action == "report"


def test_defensive_waf_audit_heuristics():
    audit = WAFAwareGovernor.audit_waf_defensive_coverage(
        domain="example.com",
        subdomains=["app.example.com", "api.example.com", "legacy-origin.example.com"],
        waf_detected_per_sub={
            "app.example.com": True,
            "api.example.com": True,
            "legacy-origin.example.com": False
        },
        origin_ip_exposed=True
    )

    assert audit["total_subdomains"] == 3
    assert audit["protected_subdomains"] == 2
    assert "legacy-origin.example.com" in audit["unprotected_subdomains"]
    assert audit["origin_ip_exposed"] is True
    assert len(audit["hardening_recommendations"]) == 2
