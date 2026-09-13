"""
HunterAI V3.0 Provenance Platform Test Suite
============================================
Comprehensive automated testing of the 8 enterprise pillars:
1. Security Flight Recorder
2. Cryptographic Provenance Chain (Core Axiom)
3. Target Digital Twin & Attack Path Simulator
4. Capability-Based Access Control
5. Agent Intrusion Detection System (Agent IDS)
6. Scientific Experiment Engine (Tripartite Control)
7. Evidence Quality Score (EQS) & Expiration Engine
8. HunterAI Research Mode & Finding Economics
"""

import tempfile
import pytest
from pathlib import Path

from core.telemetry.flight_recorder import SecurityFlightRecorder, FlightEventType
from core.provenance.provenance_chain import ProvenanceChain, ProvenanceStage
from core.graph.digital_twin import TargetDigitalTwin, DataClassification, NodeLifecycleState
from core.safety.capabilities import CapabilityGate, AgentCapability, UnauthorizedCapabilityError
from core.safety.agent_ids import AgentIntrusionDetector, AnomalySeverity
from core.safety.kill_switch import EmergencyKillSwitch
from core.experiment.scientific_experiment import ScientificExperimentEngine, TripartiteObservation
from core.scoring.evidence_quality import EvidenceQualityEngine, EvidenceQualityMetrics, EvidenceFreshnessStatus
from core.research.research_mode import ResearchModeEngine, MissingEvidenceType
from core.economics.finding_economics import FindingEconomicsTracker


class TestSecurityFlightRecorder:
    def test_record_and_query_trail(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            recorder = SecurityFlightRecorder(session_id="test_sess_01", output_dir=Path(tmpdir))
            e1 = recorder.record_event(
                event_type=FlightEventType.SCOPE_LOADED,
                phase="ORIENT",
                actor="scope_engine",
                rationale="Initialized authorized scope",
                details={"scope": "target.local"}
            )
            assert e1.event_id.startswith("FLT-")

            e2 = recorder.record_event(
                event_type=FlightEventType.ACTION_PROPOSED,
                phase="PLAN",
                actor="planner",
                rationale="Proposing BOLA test on order endpoint",
                payload="id=101",
                finding_id="FIND-BOLA-01",
                action_id="ACT-001"
            )
            assert e2.payload_checksum is not None

            # Query causal decision trail
            trail = recorder.query_decision_trail(finding_id="FIND-BOLA-01")
            assert len(trail) == 1
            assert trail[0].action_id == "ACT-001"

            # Timeline rendering
            timeline = recorder.format_timeline()
            assert "Security Flight Log" in timeline
            assert "ACTION_PROPOSED" in timeline


class TestProvenanceChain:
    def test_eight_stage_chain_and_integrity(self):
        chain = ProvenanceChain(finding_id="FIND-SQLI-77", target="api.target.local")
        chain.add_step(ProvenanceStage.OBSERVATION, "recon", "Discovered /search endpoint", "GET /search")
        chain.add_step(ProvenanceStage.BASELINE, "http_engine", "Baseline response established", "HTTP 200 OK")
        chain.add_step(ProvenanceStage.HARMLESS_CONTROL, "control_engine", "Harmless control 1=1 probe", "q=1=1")
        chain.add_step(ProvenanceStage.ACTIVE_REQUEST, "active_probe", "Adversarial payload sent", "q=' OR 1=1--")
        chain.add_step(ProvenanceStage.ACTIVE_RESPONSE, "http_engine", "SQL error returned", "Syntax error near syntax")
        chain.add_step(ProvenanceStage.DIFFERENTIAL, "diff_engine", "Divergence verified", "Status change 200 -> 500")
        chain.add_step(ProvenanceStage.COURT_VERDICT, "evidence_court", "Deterministic PoE confirmed", "PoE verified")
        chain.add_step(ProvenanceStage.FINDING, "reporter", "Finding generated", "CWE-89 SQL Injection")

        assert len(chain.steps) == 8
        assert chain.verify_integrity() is True

        # Tampering with any step breaks chain integrity
        chain.steps[3].data_hash = "bad_hash_tampered_bytes"
        assert chain.verify_integrity() is False

    def test_render_ascii_trace(self):
        chain = ProvenanceChain(finding_id="FIND-01", target="example.com")
        chain.add_step(ProvenanceStage.OBSERVATION, "recon", "Endpoint found", "GET /")
        trace = chain.render_trace_ascii()
        assert "Finding Provenance Chain" in trace
        assert "[OBSERVATION]" in trace


class TestTargetDigitalTwin:
    def test_digital_twin_and_path_simulation(self):
        twin = TargetDigitalTwin("api.target.local")
        ep_user = twin.register_endpoint("/api/v1/users/profile", "GET")
        assert ep_user.classification == DataClassification.SENSITIVE

        ep_admin = twin.register_endpoint("/api/v1/admin/secrets", "POST")
        assert ep_admin.classification == DataClassification.SECRET

        twin.add_parameter("/api/v1/users/profile", "GET", "user_id", "query")

        # Simulate attack path
        sim = twin.simulate_attack_path("/api/v1/users/profile", "GET")
        assert sim["recommended_priority"] == 1
        assert sim["has_object_id"] is True
        assert sim["simulated_risk"] == "CRITICAL"

        # Update node lifecycle state
        twin.update_node_state("/api/v1/users/profile", "GET", NodeLifecycleState.VERIFIED, finding_id="FIND-001")
        assert twin.endpoints["GET:/api/v1/users/profile"].state == NodeLifecycleState.VERIFIED

        topology = twin.export_topology()
        assert topology["total_endpoints"] == 2
        assert "VERIFIED" in topology["state_distribution"]


class TestCapabilityGate:
    def test_capability_enforcement(self):
        token_read_only = CapabilityGate.create_token(
            agent_role="recon_agent",
            capabilities=[AgentCapability.CAP_READ_DISCOVERY]
        )
        # Allowed capability
        CapabilityGate.enforce(token_read_only, AgentCapability.CAP_READ_DISCOVERY)

        # Prohibited capability raises UnauthorizedCapabilityError
        with pytest.raises(UnauthorizedCapabilityError):
            CapabilityGate.enforce(token_read_only, AgentCapability.CAP_MUTATE_STATE)


class TestAgentIntrusionDetector:
    def test_forbidden_subnet_egress(self):
        kill_switch = EmergencyKillSwitch()
        kill_switch.reset()
        ids = AgentIntrusionDetector(kill_switch=kill_switch)

        # Probing 169.254.169.254 (AWS/Cloud metadata)
        alert = ids.monitor_action(
            agent_role="compromised_agent",
            target_host="169.254.169.254",
            action_signature="GET /latest/meta-data"
        )
        assert alert is not None
        assert alert.anomaly_type == "FORBIDDEN_SUBNET_EGRESS"
        assert kill_switch.is_tripped is True

        kill_switch.reset()

    def test_scope_expansion_anomaly(self):
        kill_switch = EmergencyKillSwitch()
        kill_switch.reset()
        ids = AgentIntrusionDetector(authorized_domains={"target.local"}, kill_switch=kill_switch)

        # Probing foreign unauthorized domain
        alert = ids.monitor_action(
            agent_role="planner",
            target_host="unauthorized-evil.com",
            action_signature="POST /login"
        )
        assert alert is not None
        assert alert.anomaly_type == "SCOPE_EXPANSION_ANOMALY"
        assert kill_switch.is_tripped is True

        kill_switch.reset()

    def test_repetitive_loop_anomaly(self):
        kill_switch = EmergencyKillSwitch()
        kill_switch.reset()
        ids = AgentIntrusionDetector(authorized_domains={"target.local"}, kill_switch=kill_switch)

        # Send same failed action 5 times
        for _ in range(4):
            ids.monitor_action("tester", "target.local", "GET /retry")
        alert = ids.monitor_action("tester", "target.local", "GET /retry")
        assert alert is not None
        assert alert.anomaly_type == "ACTION_LOOP_ANOMALY"


class TestScientificExperimentEngine:
    def test_tripartite_control_verification(self):
        # Case 1: Baseline stable, canary verified exclusively in active test
        obs_valid = TripartiteObservation(
            baseline_status=200,
            baseline_length=500,
            baseline_body="Standard user dashboard",
            control_status=200,
            control_length=505,
            control_body="Standard user dashboard 1=1",
            active_status=200,
            active_length=560,
            active_body="Standard user dashboard CANARY_POE_TOKEN_99",
            expected_canary="CANARY_POE_TOKEN_99"
        )
        res_valid = ScientificExperimentEngine.evaluate_tripartite_experiment(obs_valid)
        assert res_valid.is_conclusive is True
        assert res_valid.is_causal_vulnerability is True
        assert res_valid.confidence == 0.99

        # Case 2: Target environment unstable (harmless control causes massive diff)
        obs_unstable = TripartiteObservation(
            baseline_status=200,
            baseline_length=500,
            baseline_body="Dashboard",
            control_status=503,
            control_length=150,
            control_body="Backend timeout",
            active_status=500,
            active_length=200,
            active_body="Internal error"
        )
        res_unstable = ScientificExperimentEngine.evaluate_tripartite_experiment(obs_unstable)
        assert res_unstable.is_conclusive is False
        assert res_unstable.is_causal_vulnerability is False
        assert "non-deterministic" in res_unstable.rationale


class TestEvidenceQualityEngine:
    def test_quality_score_and_freshness(self):
        # Audit-grade fresh finding
        metrics_fresh = EvidenceQualityMetrics(
            completeness=1.0,
            reproducibility=1.0,  # 3/3
            integrity_verified=True,
            differential_signal=1.0,
            age_days=1.0,
            ttl_days=7.0
        )
        report_fresh = EvidenceQualityEngine.evaluate(metrics_fresh)
        assert report_fresh.overall_score >= 95.0
        assert report_fresh.grade in ("A+", "A")
        assert report_fresh.is_audit_grade is True
        assert report_fresh.freshness_status == EvidenceFreshnessStatus.FRESH

        # Stale evidence (older than TTL)
        metrics_stale = EvidenceQualityMetrics(
            completeness=1.0,
            reproducibility=1.0,
            integrity_verified=True,
            differential_signal=1.0,
            age_days=10.0,
            ttl_days=7.0
        )
        report_stale = EvidenceQualityEngine.evaluate(metrics_stale)
        assert report_stale.freshness_status == EvidenceFreshnessStatus.STALE_REQUIRES_RETEST
        assert report_stale.is_audit_grade is False

        # Compromised integrity
        metrics_tampered = EvidenceQualityMetrics(
            completeness=1.0,
            reproducibility=1.0,
            integrity_verified=False
        )
        report_tampered = EvidenceQualityEngine.evaluate(metrics_tampered)
        assert report_tampered.overall_score <= 25.0
        assert report_tampered.grade == "F"


class TestResearchModeAndEconomics:
    def test_research_case_lifecycle(self):
        case = ResearchModeEngine.open_research_case(
            finding_id="F-99",
            endpoint="/api/v1/orders",
            parameter="id",
            uncertainty_reason="Missing benign control and unconfirmed DOM execution"
        )
        assert case.status == "OPEN"
        assert len(case.missing_elements) == 2
        assert MissingEvidenceType.MISSING_BENIGN_CONTROL in case.missing_elements
        assert len(case.experiments) == 2

        # Resolve case
        resolved = ResearchModeEngine.resolve_case(case, {"exp1": True, "exp2": True})
        assert resolved.status == "RESOLVED_CONFIRMED"
        assert resolved.final_verdict == "CONFIRMED"

    def test_finding_economics_tracking(self):
        tracker = FindingEconomicsTracker()
        tracker.record_cost(
            finding_id="F-99",
            target="api.target.local",
            vulnerability_type="IDOR",
            requests=22,
            socket_sec=3.45,
            tokens=2400
        )
        summary = tracker.get_summary("F-99")
        assert summary["requests_count"] == 22
        assert summary["socket_seconds"] == 3.45
        assert summary["llm_tokens"] == 2400

        agg = tracker.get_aggregate_economics()
        assert agg["total_findings_tracked"] == 1
        assert agg["total_requests"] == 22
