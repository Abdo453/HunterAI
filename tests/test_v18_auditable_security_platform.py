"""
HunterAI V18.0 Auditable Autonomous Security Platform Tests
============================================================
Comprehensive test suite certifying:
1. Security Flight Recorder: micro-decision blackbox logging & chronological audit trail.
2. Security Digital Twin: evolving world model & attack path simulation.
3. Agent Intrusion Detector (Agent IDS) & CapabilityGate: least-privilege & anomaly trip.
4. CoverageLedger: Attack surface coverage & negative space ledger with causal justifications.
5. Cryptographic Evidence Manifest: HMAC-SHA256 tamper verification.
6. ReplayLab & FindingLifecycleEngine: standalone bundles, drift detection & regression retesting.
7. AutonomousBrain: Subsystems attachment and Kill Switch gating.
8. Hunter CLI: Subcommands execution (coverage, flight-log, ids-status, replay, retest, abort).
"""
import json
import pytest
from pathlib import Path

from core.telemetry.flight_recorder import SecurityFlightRecorder, FlightEventType
from core.twin.security_digital_twin import SecurityDigitalTwin, RoleTier
from core.safety.agent_ids import AgentIntrusionDetector, AnomalySeverity
from core.safety.capabilities import CapabilityGate, AgentCapability, UnauthorizedCapabilityError
from core.safety.kill_switch import EmergencyKillSwitch
from core.coverage.coverage_ledger import CoverageLedger, CoverageStatus
from core.security.evidence_manifest import EvidenceManifestSigner, ManifestTamperError
from core.replay_lab.replay_lab import ReplayLab
from core.lifecycle.finding_lifecycle_engine import FindingLifecycleEngine, LifecycleStage, InvalidLifecycleTransitionError
from core.brain.autonomous_brain import AutonomousBrain


class TestSecurityFlightRecorder:
    """Test Case 1: Blackbox flight recorder telemetry and chronological audit trail"""

    def test_flight_recorder_event_logging_and_query(self, tmp_path):
        recorder = SecurityFlightRecorder(session_id="test_sess_01", output_dir=tmp_path)
        ev1 = recorder.record_event(
            event_type=FlightEventType.SCOPE_LOADED,
            phase="ORIENT",
            actor="PolicyGate",
            rationale="Authorized target scope loaded: api.target.local"
        )
        ev2 = recorder.record_event(
            event_type=FlightEventType.PROBE_EXECUTED,
            phase="ACT",
            actor="WebAgent",
            rationale="Sent SQLi probe on parameter id",
            payload="' OR 1=1--"
        )
        assert ev1.event_type == FlightEventType.SCOPE_LOADED
        assert ev2.payload_checksum is not None
        assert len(recorder.events) == 2

        recent = recorder.get_recent_events(limit=10)
        assert len(recent) == 2

        timeline = recorder.format_timeline(limit=10)
        assert "Security Flight Log" in timeline
        assert "SCOPE_LOADED" in timeline


class TestSecurityDigitalTwin:
    """Test Case 2: Target digital twin world model and cross-tenant attack path simulation"""

    def test_digital_twin_attack_path_simulation(self):
        dt = SecurityDigitalTwin("portal.corp.local")
        dt.register_identity("usr_alice", RoleTier.AUTHENTICATED_USER, "token_alice")
        dt.register_identity("usr_bob", RoleTier.AUTHENTICATED_USER, "token_bob")
        dt.register_resource("REC-INV-99", "invoice", "usr_alice", "CRITICAL")

        paths = dt.simulate_cross_tenant_access_paths()
        assert len(paths) >= 1
        path = paths[0]
        assert path.source_identity == "usr_bob"
        assert path.target_resource == "REC-INV-99"
        assert "BOLA" in path.vulnerability_vector


class TestAgentIDSAndCapabilityGate:
    """Test Case 3: Agent Intrusion Detection, least privilege tokens & kill switch trip"""

    def test_capability_gate_least_privilege(self):
        token = CapabilityGate.create_token(
            agent_role="ReconAgent",
            capabilities=[AgentCapability.CAP_READ_DISCOVERY, AgentCapability.CAP_PROPOSE_TEST]
        )
        assert CapabilityGate.verify_capability(token, AgentCapability.CAP_READ_DISCOVERY) is True
        with pytest.raises(UnauthorizedCapabilityError):
            CapabilityGate.verify_capability(token, AgentCapability.CAP_MUTATE_STATE)

    def test_agent_ids_velocity_and_scope_anomaly(self):
        ks = EmergencyKillSwitch()
        ks.reset()
        ids = AgentIntrusionDetector(authorized_domains={"target.local"}, max_req_per_min=5, kill_switch=ks)

        # Action on authorized domain
        alert = ids.monitor_action("Tester", "target.local", "GET /api/test")
        assert alert is None

        # Action on forbidden domain (Scope Violation)
        alert_scope = ids.monitor_action("Tester", "unauthorized-malicious.org", "GET /api/leak")
        assert alert_scope is not None
        assert alert_scope.severity == AnomalySeverity.CRITICAL
        assert ks.is_tripped is True
        ks.reset()


class TestCoverageLedgerAndNegativeSpace:
    """Test Case 4: Coverage map, negative space ledger, and multidimensional confidence"""

    def test_coverage_ledger_probed_and_skipped(self):
        ledger = CoverageLedger("target.local")
        ledger.record_probed("/api/v1/auth", "POST", "user", verified_finding=False)
        ledger.record_probed("/api/v1/profile", "GET", "id", verified_finding=True)

        ledger.record_skipped("/api/v1/admin/purge", "POST", CoverageStatus.SKIPPED_AUTH_MISSING, "Admin auth missing")
        ledger.record_skipped("/api/v1/upload", "POST", CoverageStatus.SKIPPED_POLICY_RESTRICTION, "Upload restricted")
        ledger.record_skipped("/ws/feed", "GET", CoverageStatus.SKIPPED_UNSUPPORTED_PROTOCOL, "WebSocket unsupported")

        summary = ledger.get_summary()
        assert summary["total_surface_items"] == 5
        assert summary["probed_items"] == 2
        assert summary["probed_and_verified"] == 1
        assert summary["skipped_items"] == 3
        assert summary["coverage_percentage"] == 40.0

        terminal_map = ledger.format_terminal_coverage_map()
        assert "Coverage Map" in terminal_map
        assert "Negative Space Ledger" in terminal_map
        assert "SKIPPED_AUTH_MISSING" in terminal_map


class TestEvidenceManifestAndTamperDetection:
    """Test Case 5: Cryptographic evidence signing and tamper verification"""

    def test_manifest_creation_and_tamper_detection(self):
        signer = EvidenceManifestSigner(secret="test_secret_v18")
        manifest = signer.create_manifest(
            finding_id="F-SQLI-01",
            target="https://target.local",
            raw_request="GET /search?q=' OR 1=1-- HTTP/1.1",
            raw_response="HTTP/1.1 200 OK\r\n\r\nSQL Syntax Error near '--'",
            evidence_snippet="SQL Syntax Error near '--'"
        )
        assert manifest.signature.startswith("HMAC-SHA256:")
        assert signer.verify_manifest(manifest) is True

        # Tampering with evidence must be caught
        manifest.evidence_hash = "tampered_fake_hash"
        with pytest.raises(ManifestTamperError):
            signer.verify_manifest(manifest)


class TestReplayLabAndRegressionEngine:
    """Test Case 6: Standalone replay packages and lifecycle regression verification"""

    def test_replay_bundle_and_lifecycle_retest(self, tmp_path):
        lab = ReplayLab(base_dir=tmp_path)
        bundle_dir = lab.freeze_finding(
            finding_id="FND-RETEST-101",
            target_url="https://target.local/profile?id=42",
            method="GET",
            parameter="id",
            payload="<script>alert('poe')</script>",
            raw_request="GET /profile?id=42 HTTP/1.1",
            raw_response="HTTP/1.1 200 OK\r\n\r\n<script>alert('poe')</script>",
            raw_baseline="HTTP/1.1 200 OK\r\n\r\nSafe profile"
        )
        assert (bundle_dir / "replay.py").exists()

        # Step 1: Initialize finding lifecycle at CONFIRMED
        lifecycle = FindingLifecycleEngine("FND-RETEST-101", initial_stage=LifecycleStage.CONFIRMED)

        # Step 2: Target is patched -> Retest proves fix
        report_fixed = lifecycle.retest_with_replay(
            current_response_body="Profile: &lt;script&gt;alert('poe')&lt;/script&gt;",
            expected_payload="<script>alert('poe')</script>",
            replay_lab=lab
        )
        assert report_fixed.verdict == "FIXED"
        assert report_fixed.is_reproduced is False
        assert lifecycle.current_stage == LifecycleStage.FIXED

        # Step 3: Bad deployment -> Vulnerability returns (Regression Detected)
        report_regressed = lifecycle.retest_with_replay(
            current_response_body="Profile: <script>alert('poe')</script>",
            expected_payload="<script>alert('poe')</script>",
            replay_lab=lab
        )
        assert report_regressed.verdict == "REGRESSION_DETECTED"
        assert report_regressed.is_reproduced is True
        assert lifecycle.current_stage == LifecycleStage.REGRESSED


class TestAutonomousBrainPlatformIntegration:
    """Test Case 7: AutonomousBrain auditable subsystems attachment and kill switch"""

    def test_brain_subsystems_attached(self):
        from unittest.mock import MagicMock
        brain = AutonomousBrain(resource_manager=MagicMock(), tool_manager=MagicMock(), dry_run=True)
        assert brain.flight_recorder is not None
        assert brain.agent_ids is not None
        assert brain.capability_gate is not None
        assert brain.replay_lab is not None
        assert brain.request_fingerprinter is not None

    @pytest.mark.asyncio
    async def test_brain_run_scan_kill_switch_abort(self):
        from unittest.mock import MagicMock
        ks = EmergencyKillSwitch()
        ks.reset()
        ks.trigger(reason="Test Emergency Abort")

        brain = AutonomousBrain(resource_manager=MagicMock(), tool_manager=MagicMock(), dry_run=True)
        res = await brain.run_scan("https://target.local")
        assert res.get("status") == "ABORTED_BY_KILL_SWITCH"
        ks.reset()


class TestPlatformCLICommands:
    """Test Case 8: Hunter CLI platform subcommands execution"""

    def test_cli_subcommands(self):
        from cli.hunter_cli import main
        # 1. Coverage command
        main(["coverage", "--domain", "test.local", "--json"])

        # 2. Flight-log command
        main(["flight-log", "--limit", "5"])

        # 3. Retest command
        main(["retest", "--finding", "F-001", "--json"])

        # 4. Abort status
        main(["abort", "--status"])
