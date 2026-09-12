"""
Unit tests for HunterAI Theory-Driven Research Engine:
- Latent Architecture Inference
- Trust Boundary Mapping
- Object Lifecycle Modeling
- Semantic Diff Analysis
- Curiosity Engine
- Decision Replay Ledger
"""
import pytest

from hunter_ai.runtime import (
    InferredArchitecture, ArchitectureTier, LatentArchitectureInferrer,
    TrustLevel, TrustTransition, TrustBoundaryMapper,
    LifecycleStage, LifecycleViolation, ObjectLifecycleTracker,
    SemanticFieldChange, SemanticDiffAnalyzer,
    CuriousEvent, CuriosityEngine,
    DecisionReplayStep, DecisionReplayLedger
)


# ─── 1. Latent Architecture Inference Tests ──────────────────────────────────
class TestLatentArchitectureInferrer:
    def test_infer_microservices_gateway_topology(self):
        headers = {
            "cf-ray": "8934abcdf123-AMS",
            "x-kong-proxy-latency": "12",
            "Server": "nginx/1.24",
            "X-Powered-By": "Express"
        }

        arch = LatentArchitectureInferrer.infer_from_headers(headers)
        assert isinstance(arch, InferredArchitecture)
        assert ArchitectureTier.CDN_EDGE in arch.detected_tiers
        assert ArchitectureTier.API_GATEWAY in arch.detected_tiers
        assert ArchitectureTier.APPLICATION_SERVICE in arch.detected_tiers
        assert arch.topology_type == "MICROSERVICES_GATEWAY"
        assert len(arch.evidence_footprints) >= 2


# ─── 2. Trust Boundary Mapping Tests ─────────────────────────────────────────
class TestTrustBoundaryMapper:
    def test_dangerous_trust_boundary_crossing(self):
        transition = TrustBoundaryMapper.analyze_parameter_boundary(
            endpoint="/api/orders/update",
            parameter_name="tenant_id",
            is_client_supplied=True,
            affects_authorization=True
        )

        assert transition.is_dangerous_boundary is True
        assert transition.source_level == TrustLevel.UNTRUSTED_USER
        assert transition.target_level == TrustLevel.INTERNAL_TRUSTED
        assert "tenant_id" in transition.rationale

    def test_normal_validated_boundary(self):
        transition = TrustBoundaryMapper.analyze_parameter_boundary(
            endpoint="/api/catalog/search",
            parameter_name="query",
            is_client_supplied=True,
            affects_authorization=False
        )

        assert transition.is_dangerous_boundary is False
        assert transition.target_level == TrustLevel.GATEWAY_VALIDATED


# ─── 3. Object Lifecycle Model Tests ─────────────────────────────────────────
class TestObjectLifecycleTracker:
    def test_lifecycle_breach_detection(self):
        tracker = ObjectLifecycleTracker()
        tracker.set_stage("invoice_999", LifecycleStage.APPROVED_FINAL)

        # Attempting modification on finalized invoice accepted by server (200 OK)
        breach = tracker.audit_lifecycle_action(
            object_id="invoice_999",
            action="update_amount",
            server_status=200
        )

        assert breach is not None
        assert breach.object_id == "invoice_999"
        assert breach.current_stage == LifecycleStage.APPROVED_FINAL
        assert breach.was_accepted_by_server is True
        assert "LIFECYCLE_BREACH" in breach.description

    def test_legitimate_lifecycle_action(self):
        tracker = ObjectLifecycleTracker()
        tracker.set_stage("invoice_100", LifecycleStage.DRAFT)

        # Modifying draft is legitimate
        breach = tracker.audit_lifecycle_action(
            object_id="invoice_100",
            action="update_amount",
            server_status=200
        )
        assert breach is None


# ─── 4. Semantic Diff Analysis Tests ─────────────────────────────────────────
class TestSemanticDiffAnalyzer:
    def test_critical_security_field_detection(self):
        base = {"user_id": 10, "username": "alice", "role": "viewer", "last_login": "10:00"}
        obs = {"user_id": 10, "username": "alice", "role": "admin", "last_login": "10:05"}

        changes = SemanticDiffAnalyzer.compare_semantic_structures(base, obs)
        assert len(changes) == 2

        role_change = next(c for c in changes if c.field_name == "role")
        assert role_change.security_significance == "CRITICAL_AUTHORIZATION_FIELD"
        assert role_change.baseline_value == "viewer"
        assert role_change.observed_value == "admin"

        login_change = next(c for c in changes if c.field_name == "last_login")
        assert login_change.security_significance == "INFORMATIONAL_DATA"


# ─── 5. Curiosity Engine Tests ───────────────────────────────────────────────
class TestCuriosityEngine:
    def test_curiosity_scoring_novel_security_anomaly(self):
        event = CuriosityEngine.evaluate_anomaly(
            endpoint="/api/internal/debug",
            is_novel=True,
            confidence_gap=0.8,  # high uncertainty
            affects_security_boundary=True,
            description="Unexpected endpoint exposed with verbose diagnostics"
        )

        assert isinstance(event, CuriousEvent)
        assert event.interestingness_score >= 0.7
        assert "debug" in event.endpoint
        assert "Proactively design" in event.recommended_inquiry


# ─── 6. Decision Replay Ledger Tests ─────────────────────────────────────────
class TestDecisionReplayLedger:
    def test_timeline_recording_and_replay(self):
        ledger = DecisionReplayLedger()

        s1 = ledger.record_step(
            observation_id="OBS_01",
            hypothesis_id="HYP_01",
            action_taken="http_probe",
            evidence_gathered="Status 200 with admin cookies",
            resulting_belief_update="Elevated hypothesis confidence to 0.85"
        )

        s2 = ledger.record_step(
            observation_id="OBS_02",
            hypothesis_id="HYP_01",
            action_taken="independent_verify",
            evidence_gathered="Verified differential between roles",
            resulting_belief_update="Finding confirmed beyond doubt"
        )

        timeline = ledger.get_timeline()
        assert len(timeline) == 2
        assert timeline[0]["step_number"] == 1
        assert timeline[1]["step_number"] == 2
        assert timeline[0]["observation_id"] == "OBS_01"
        assert timeline[1]["action_taken"] == "independent_verify"
