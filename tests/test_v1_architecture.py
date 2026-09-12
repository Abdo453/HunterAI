"""
Unit Test Suite for HunterAI V1.0 Architecture & Core Components
================================================================
Verifies:
- Unified Finding Model serialization & reproduction guides
- Evidence State Machine invariant transitions
- Attack Surface Catalog & Endpoint Input Model
- Network Scope Guard protocol & redirect enforcement
- Execution Modes (Passive by default) & Human Approval Gates
- Targeted XSS & SQLi Detectors with false positive rejection
- Benchmark Engine ground truth catalog & run recorder
- Security Sanitizer masking & Session Data Purge
"""
import pytest
from core.finding_model import Finding, HttpExchangeRecord, VerificationRecord, ReproducibilityRecord
from core.evidence_state_machine import EvidenceStateMachine, FindingState, InvalidStateTransitionError
from core.models.endpoint_input_model import AttackSurfaceCatalog, EndpointModel, ParameterLocation
from core.network_scope_guard import NetworkScopeGuard, ScopeViolationError
from core.scope_engine import ScopePolicy
from core.execution_modes import (
    ExecutionMode,
    HighRiskActionType,
    HumanApprovalDeniedError,
    HumanApprovalGate,
    ModeManager,
    ModeViolationError
)
from core.detectors.xss_detector import XSSDetector
from core.detectors.sqli_detector import SQLiDetector
from benchmarks.benchmark_engine import BenchmarkEngine, BenchmarkRunResult
from core.dashboard.assessment_dashboard import DashboardMetrics
from core.security_sanitizer import SecuritySanitizer, SessionDataPurge


def test_unified_finding_model_and_reproducibility():
    exchange = HttpExchangeRecord(
        method="GET",
        url="https://shop.lab.local/search?q=%22%3E%3Chunter_xss%3E",
        headers={"User-Agent": "HunterAI/1.0"},
        status_code=200,
        response_body_snippet='<div>Results for: "><hunter_xss></div>'
    )
    finding = Finding(
        vulnerability_type="xss",
        title="Reflected XSS in query 'q'",
        severity="HIGH",
        confidence=0.98,
        target="shop.lab.local",
        endpoint="/search",
        parameter="q",
        tested_request=exchange,
        test_response=exchange,
        evidence="Unencoded breakout in response",
        reproducibility=ReproducibilityRecord(
            is_reproducible=True,
            reproduction_steps=["Navigate to /search", "Supply payload", "Verify tag breakout"],
            reproduction_curl=exchange.to_curl()
        ),
        cwe="CWE-79",
        owasp="A03:2021-Injection"
    )

    d = finding.to_dict()
    assert d["vulnerability_type"] == "xss"
    assert d["severity"] == "HIGH"
    assert "curl" in finding.to_reproduction_guide()
    assert "# [HIGH]" in finding.to_hackerone_markdown()


def test_evidence_state_machine_transitions():
    fsm = EvidenceStateMachine("FINDING-001")
    assert fsm.current_state == FindingState.DISCOVERED

    # Valid transitions
    fsm.transition_to(FindingState.OBSERVED, reason="Traffic analyzed")
    fsm.transition_to(FindingState.HYPOTHESIS, reason="Hypothesis generated")
    fsm.transition_to(FindingState.TESTED, reason="Probe dispatched")
    fsm.transition_to(FindingState.EVIDENCE_COLLECTED, reason="Proof received")
    fsm.transition_to(FindingState.VERIFIED, reason="Court verification")
    fsm.transition_to(FindingState.CONFIRMED, reason="Finding adjudicated")
    assert fsm.is_confirmed() is True

    # Attempt illegal transition from terminal state
    with pytest.raises(InvalidStateTransitionError):
        fsm.transition_to(FindingState.HYPOTHESIS)


def test_network_scope_guard_protocols_and_redirects():
    policy = ScopePolicy(allowed_targets=["target.com"], allow_private_ips_override=False)
    guard = NetworkScopeGuard(policy)

    # Allow valid in-scope
    allowed, _ = guard.check_url("https://target.com/api")
    assert allowed is True

    # Block disallowed protocols
    allowed, reason = guard.check_url("file:///etc/passwd")
    assert allowed is False
    assert "Disallowed protocol scheme" in reason

    allowed, reason = guard.check_url("ftp://target.com/file")
    assert allowed is False
    assert "Disallowed protocol scheme" in reason

    # Redirect validation: In-scope relative redirect allowed
    allowed, _ = guard.check_redirect("https://target.com/login", "/dashboard")
    assert allowed is True

    # Redirect validation: Out-of-scope redirect blocked
    allowed, reason = guard.check_redirect("https://target.com/login", "https://evil.com/steal")
    assert allowed is False
    assert "out-of-scope" in reason

    # Out of scope domain assertion raises ScopeViolationError
    with pytest.raises(ScopeViolationError):
        guard.assert_allowed("https://evil.com/probe")


def test_execution_modes_and_human_approval_gate():
    manager = ModeManager()
    assert manager.is_passive is True

    # In PASSIVE mode, attempting active payload raises ModeViolationError
    with pytest.raises(ModeViolationError):
        manager.assert_active_allowed("SQL Injection Probe")

    # Switch to ACTIVE mode
    manager.switch_mode(ExecutionMode.ACTIVE, reason="Authorized test scope")
    assert manager.is_active is True
    manager.assert_active_allowed("SQL Injection Probe")  # Should not raise

    # Human Approval Gate: Non-interactive without whitelist raises
    gate = HumanApprovalGate(interactive=False)
    with pytest.raises(HumanApprovalDeniedError):
        gate.request_approval(HighRiskActionType.ACTIVE_SQLI, "target.com", {"payload": "1' OR 1=1"})

    # Whitelisted action succeeds
    gate_whitelisted = HumanApprovalGate(interactive=False, auto_approved_categories=[HighRiskActionType.ACTIVE_SQLI])
    assert gate_whitelisted.request_approval(HighRiskActionType.ACTIVE_SQLI, "target.com", {}) is True


def test_targeted_xss_detector_and_fp_rejection():
    ep = EndpointModel(target="test.lab", path="/search", method="GET")

    # 1. Vulnerable mock dispatcher
    def mock_vuln_http(method, url, headers, body):
        if "hunter_xss" in url:
            import urllib.parse
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            q_val = params.get("q", [""])[0]
            return 200, {"Content-Type": "text/html"}, f'<html><body><input value="{q_val}"/></body></html>'
        return 200, {"Content-Type": "text/html"}, "<html><body>Search</body></html>"

    finding = XSSDetector.test_parameter(ep, "q", mock_vuln_http)
    assert finding is not None
    assert finding.vulnerability_type == "xss"
    assert finding.confidence >= 0.95

    # 2. Hardened False Positive Trap dispatcher (HTML encoded)
    def mock_safe_http(method, url, headers, body):
        return 200, {"Content-Type": "text/html"}, "<html><body>&lt;hunter_xss&gt;</body></html>"

    finding_safe = XSSDetector.test_parameter(ep, "q", mock_safe_http)
    assert finding_safe is None  # Suppressed by evidence court


def test_targeted_sqli_detector_and_fp_rejection():
    ep = EndpointModel(target="test.lab", path="/products", method="GET")

    # 1. Vulnerable mock dispatcher (arithmetic boolean differential)
    def mock_vuln_sqli(method, url, headers, body):
        if "1%2B%2853-52%29" in url or "1+(53-52)" in url:
            return 200, {"Content-Type": "application/json"}, '{"id": 2, "name": "Premium Gadget"}'
        return 200, {"Content-Type": "application/json"}, '{"id": 1, "name": "Standard"}'

    finding = SQLiDetector.test_parameter(ep, "cat", mock_vuln_sqli)
    assert finding is not None
    assert finding.vulnerability_type == "sqli"
    assert finding.confidence >= 0.95

    # 2. Hardened False Positive Trap (Generic 500 error on quote without SQL differential)
    def mock_safe_sqli(method, url, headers, body):
        if "1%2B%2853-52%29" in url or "1+(53-52)" in url:
            # Generic 500 app exception
            return 500, {"Content-Type": "text/html"}, "<html><body>500 Internal Server Error: Invalid Format</body></html>"
        return 200, {"Content-Type": "text/html"}, "OK"

    finding_safe = SQLiDetector.test_parameter(ep, "cat", mock_safe_sqli)
    assert finding_safe is None  # Suppressed by evidence court


def test_benchmark_engine_ground_truth_and_runs(tmp_path):
    engine = BenchmarkEngine(benchmark_dir=tmp_path)
    engine.load_ground_truth("xss")  # should not crash if empty

    result = BenchmarkRunResult(
        run_id="001",
        target_app="OWASP Juice Shop",
        total_cases=10,
        detected=9,
        missed=1,
        false_positives=0,
        precision_pct=100.0,
        recall_pct=90.0,
        total_requests=42,
        runtime_sec=1.5
    )
    engine.record_run(result)
    assert (tmp_path / "runs" / "run_001.json").exists()
    assert (tmp_path / "reports" / "report_001.md").exists()
    assert "**Precision:** 100.0%" in (tmp_path / "reports" / "report_001.md").read_text()


def test_security_sanitizer_and_session_purge(tmp_path):
    raw_text = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret.sig connect.sid=s%3A1234567890"
    masked = SecuritySanitizer.mask_text(raw_text)
    assert "secret.sig" not in masked
    assert "MASKED" in masked

    headers = {
        "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9",
        "Cookie": "sessionid=xyz987654",
        "Content-Type": "application/json"
    }
    masked_headers = SecuritySanitizer.mask_headers(headers)
    assert "xyz987654" not in str(masked_headers)
    assert masked_headers["Content-Type"] == "application/json"

    # Test Session purge
    session_dir = tmp_path / "test_session"
    session_dir.mkdir()
    (session_dir / "cache.bin").write_text("data")
    assert (session_dir / "cache.bin").exists()

    res = SessionDataPurge.wipe_session("test_session", data_dir=session_dir)
    assert res["status"] == "PURGED"
    assert not (session_dir / "cache.bin").exists()