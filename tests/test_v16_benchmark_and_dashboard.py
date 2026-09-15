"""
HunterAI V16.0 Test Suite — Evidence-Driven Architecture & Operational Benchmarks
=================================================================================
Certifies:
1. Standardized BenchmarkEngine execution & run reporting (runs/ and reports/)
2. Executive Assessment Dashboard metrics & rendering
3. Unified Finding object contract with reproducible curl extraction
4. EvidenceStateMachine strict lifecycle transitions (positive and negative terminal states)
5. Ground-truth case coverage across Juice Shop, DVWA, WebGoat, and PortSwigger
"""
import json
import pytest
from pathlib import Path

from benchmarks.benchmark_engine import BenchmarkEngine, BenchmarkCase, BenchmarkRunResult
from core.dashboard.assessment_dashboard import DashboardMetrics
from core.finding_model import Finding, HttpExchangeRecord, VerificationRecord, ReproducibilityRecord
from core.evidence_state_machine import EvidenceStateMachine, FindingState, InvalidStateTransitionError
from core.request_fingerprinter import RequestFingerprinter
from core.replay_lab.replay_lab import ReplayLab, ReplayDriftResult


class TestBenchmarkEngine:
    """Test Case 1 & 2: Benchmark suite execution, ground truth parsing, and run artifacts"""

    def test_benchmark_engine_load_cases(self):
        engine = BenchmarkEngine()
        cases = engine.load_all_cases()
        assert len(cases) >= 4
        # Verify cases have necessary fields
        for c in cases:
            assert isinstance(c, BenchmarkCase)
            assert c.case_id.startswith("TC-")
            assert c.vulnerability_type in ("sqli", "xss", "jwt", "auth")

    def test_benchmark_engine_run_suite(self, tmp_path):
        engine = BenchmarkEngine(benchmark_dir=tmp_path)
        # Create a mock ground_truth file in temp dir
        gt_dir = tmp_path / "ground_truth"
        gt_dir.mkdir(parents=True, exist_ok=True)
        with open(gt_dir / "sqli.json", "w", encoding="utf-8") as f:
            json.dump([
                {"case_id": "TC-01", "target_app": "DVWA", "vulnerability_type": "sqli", "endpoint": "/sqli", "parameter": "id", "expected_vulnerable": True},
                {"case_id": "TC-02", "target_app": "DVWA", "vulnerability_type": "sqli", "endpoint": "/safe", "parameter": "id", "expected_vulnerable": False}
            ], f)

        res = engine.execute_suite(target_app="DVWA")
        assert res.total_cases == 2
        assert res.detected == 1
        assert res.false_positives == 0
        assert res.precision_pct == 100.0
        assert res.recall_pct == 100.0

        # Check run files created
        assert (tmp_path / "runs" / f"run_{res.run_id}.json").exists()
        assert (tmp_path / "reports" / f"report_{res.run_id}.md").exists()


class TestDashboardMetrics:
    """Test Case 3: Executive Assessment Dashboard"""

    def test_dashboard_metrics_render(self):
        metrics = DashboardMetrics(
            scope_domain="juice-shop.local",
            mode="Active",
            endpoints_count=42,
            parameters_count=18,
            confirmed_findings=3,
            rejected_findings=7,
            out_of_scope_violations=0
        )
        report = metrics.render_terminal_dashboard()
        assert "juice-shop.local" in report
        assert "Active" in report
        assert "42" in report
        assert "Confirmed:             3" in report
        assert "Out-of-scope:          0" in report


class TestFindingModelAndReproducibility:
    """Test Case 4: Unified Finding schema and curl generation"""

    def test_finding_schema_and_curl_generation(self):
        req = HttpExchangeRecord(
            method="POST",
            url="https://target.local/api/orders",
            headers={"Authorization": "Bearer test_token", "Content-Type": "application/json"},
            body='{"id": 42}'
        )
        curl_cmd = req.to_curl()
        assert "curl -i -s -X POST" in curl_cmd
        assert "-H 'Authorization: Bearer test_token'" in curl_cmd
        assert "https://target.local/api/orders" in curl_cmd

        finding = Finding(
            id="FND-TEST-001",
            vulnerability_type="sqli",
            title="SQL Injection on Orders API",
            severity="CRITICAL",
            confidence=0.98,
            target="https://target.local",
            endpoint="/api/orders",
            parameter="id",
            tested_request=req,
            reproducibility=ReproducibilityRecord(
                is_reproducible=True,
                reproduction_steps=["Inject arithmetic payload 1+(53-52)", "Observe status 200"],
                reproduction_curl=curl_cmd
            )
        )
        h1_md = finding.to_hackerone_markdown()
        assert "SQL Injection on Orders API" in h1_md
        assert "CRITICAL" in h1_md
        assert "curl" in h1_md


class TestEvidenceStateMachine:
    """Test Case 5: Evidence state machine transitions and invalid leap rejection"""

    def test_evidence_state_machine_lifecycle(self):
        sm = EvidenceStateMachine(finding_id="FND-STATE-01")
        assert sm.current_state == FindingState.DISCOVERED

        # Transition: DISCOVERED -> OBSERVED -> HYPOTHESIS -> TESTED -> EVIDENCE_COLLECTED -> VERIFIED -> CONFIRMED
        sm.transition_to(FindingState.OBSERVED, reason="Telemetry parsed")
        sm.transition_to(FindingState.HYPOTHESIS, reason="Proposed by model")
        sm.transition_to(FindingState.TESTED, reason="Probe dispatched")
        sm.transition_to(FindingState.EVIDENCE_COLLECTED, reason="Nonce reflected")
        sm.transition_to(FindingState.VERIFIED, reason="Court proof matched")
        sm.transition_to(FindingState.CONFIRMED, reason="Adjudicated final")

        assert sm.current_state == FindingState.CONFIRMED

    def test_evidence_state_machine_rejects_invalid_leap(self):
        sm = EvidenceStateMachine(finding_id="FND-STATE-02")
        # Attempting to jump from DISCOVERED directly to CONFIRMED must raise InvalidStateTransitionError
        with pytest.raises(InvalidStateTransitionError):
            sm.transition_to(FindingState.CONFIRMED, reason="Hallucinated leap without evidence")


class TestRequestFingerprinter:
    """Test Case 6: Request fingerprinting, canonicalization, and deduplication"""

    def test_request_fingerprinter_deduplication(self):
        rf = RequestFingerprinter()
        url1 = "https://target.local/api/search?q=1&t=12345"
        url2 = "https://target.local/api/search?t=99999&q=1"

        sig1 = rf.calculate_hash("GET", url1, parameter="q", mutation_payload="' OR 1=1--")
        sig2 = rf.calculate_hash("GET", url2, parameter="q", mutation_payload="' OR 1=1--")
        assert sig1 == sig2  # Noise timestamps ignored and query keys sorted

        assert rf.should_skip("GET", url1, parameter="q", mutation_payload="' OR 1=1--") is False
        rf.record_execution("GET", url1, parameter="q", mutation_payload="' OR 1=1--")
        assert rf.should_skip("GET", url2, parameter="q", mutation_payload="' OR 1=1--") is True


class TestReplayLab:
    """Test Case 7: Replay lab freeze, replay execution, and evidence drift detection"""

    def test_replay_lab_drift_detection(self, tmp_path):
        lab = ReplayLab(base_dir=tmp_path)
        bundle_dir = lab.freeze_finding(
            finding_id="FND-REPLAY-01",
            target_url="https://target.local/profile?id=42",
            method="GET",
            parameter="id",
            payload="<script>alert(1)</script>",
            raw_request="GET /profile?id=42 HTTP/1.1",
            raw_response="HTTP/1.1 200 OK\r\n\r\n<script>alert(1)</script>",
            raw_baseline="HTTP/1.1 200 OK\r\n\r\nSafe profile"
        )
        assert (bundle_dir / "replay.py").exists()
        assert (bundle_dir / "metadata.json").exists()

        # Case A: Replay reproduces payload -> Drift: NONE
        result_ok = lab.evaluate_replay(
            finding_id="FND-REPLAY-01",
            re_executed_response_body="Profile: <script>alert(1)</script>",
            expected_indicator="<script>alert(1)</script>"
        )
        assert result_ok.evidence_drift_detected is False
        assert result_ok.is_reproducible is True
        assert result_ok.replay_verdict == "CONFIRMED"

        # Case B: Replay fails (e.g. patched) -> Drift: DETECTED
        result_drift = lab.evaluate_replay(
            finding_id="FND-REPLAY-01",
            re_executed_response_body="Profile: &lt;script&gt;alert(1)&lt;/script&gt;",
            expected_indicator="<script>alert(1)</script>"
        )
        assert result_drift.evidence_drift_detected is True
        assert result_drift.is_reproducible is False
        assert result_drift.replay_verdict == "REJECTED"
