"""
HunterAI V7.0 Enterprise Cognitive Assurance Test Suite
======================================================
Comprehensive tests for:
- AgentDecisionTrace (structured non-CoT decision auditing)
- EpistemicTrustPipeline (6-stage linear trust graduation & violation errors)
- SecretLifecycleManager (fingerprinting, masked preview, rotation, zero raw leak)
- ModelAgnosticAdapter (deterministic No-LLM mode & graceful degradation)
- PeerReviewWorkflow (packet review, approval, rejection, evidence request)
- CapabilityNegotiationEngine (token-based agent assignment & mutation gating)
- ComplianceMapper (post-proof mapping to OWASP, CAPEC, NIST, CIS)
- UnknownsMatrix (5-sector visibility breakdown & transparency scoring)
- PostureTimelineTracker (longitudinal trend analysis & regression tracking)
"""
import pytest

from core.trace.agent_decision_trace import AgentDecisionTrace, DecisionTraceLogger
from core.trust.trust_pipeline import TrustBoundaryPipeline, TrustState, TrustViolationError
from core.secrets.secret_lifecycle import SecretLifecycleManager, SecretState
from core.ai_bridge.model_agnostic_adapter import ModelAgnosticAdapter, ModelBackendType
from core.review.peer_review_workflow import PeerReviewWorkflow, ReviewStatus
from core.safety.capability_negotiation import CapabilityNegotiationEngine
from core.compliance.compliance_mapper import ComplianceMapper
from core.visibility.unknowns_matrix import UnknownsMatrix, SurfaceSector
from core.timeline.posture_timeline import PostureTimelineTracker, PostureTrend


class TestAgentDecisionTrace:
    def test_structured_decision_trace(self):
        trace = AgentDecisionTrace("TRC-001", "api.target.local")
        step = trace.record_step(
            observation="Discovered order ID parameter",
            evidence=["Baseline 200 OK"],
            decision="Select BOLA test",
            policy_result="ALLOW",
            policy_receipt="POL-v14-01",
            action="GET /api/v1/orders/2",
            result="200 OK",
            mutated=False
        )
        assert step.step_id.startswith("TRC-TRC-001-")
        assert step.policy_check_result == "ALLOW"
        assert len(trace.steps) == 1
        
        timeline = trace.format_timeline_ascii()
        assert "TRC-001" in timeline
        assert "POL-v14-01" in timeline


class TestEpistemicTrustPipeline:
    def test_linear_trust_graduation(self):
        data = TrustBoundaryPipeline.ingest_untrusted("DAT-100", "<html>target content</html>", "spider")
        assert data.current_state == TrustState.UNTRUSTED
        
        # Ingest -> Observed
        TrustBoundaryPipeline.graduate(data, TrustState.OBSERVED, "Payload recorded by proxy")
        assert data.current_state == TrustState.OBSERVED
        
        # Observed -> Normalized
        TrustBoundaryPipeline.graduate(data, TrustState.NORMALIZED, "DOM sanitized by PromptInjectionFirewall")
        assert data.current_state == TrustState.NORMALIZED
        
        # Normalized -> Analyzed
        TrustBoundaryPipeline.graduate(data, TrustState.ANALYZED, "Endpoints extracted by DeepJSAnalyzer")
        assert data.current_state == TrustState.ANALYZED
        
        # Analyzed -> Verified
        TrustBoundaryPipeline.graduate(data, TrustState.VERIFIED, "Tripartite equation satisfied")
        assert data.current_state == TrustState.VERIFIED
        
        # Verified -> Trusted Evidence
        TrustBoundaryPipeline.graduate(data, TrustState.TRUSTED_EVIDENCE, "Contract confirmed by Evidence Court")
        assert data.current_state == TrustState.TRUSTED_EVIDENCE

    def test_illegal_trust_jump_rejected(self):
        data = TrustBoundaryPipeline.ingest_untrusted("DAT-200", "malicious_payload")
        # Attempting to jump from UNTRUSTED directly to TRUSTED_EVIDENCE must fail
        with pytest.raises(TrustViolationError):
            TrustBoundaryPipeline.graduate(data, TrustState.TRUSTED_EVIDENCE, "Bypassing pipeline")


class TestSecretLifecycleManager:
    def test_secret_registration_and_redaction(self):
        sm = SecretLifecycleManager()
        raw_key = "AKIAIOSFODNN7EXAMPLE"
        rec = sm.register_secret_candidate(raw_key, "AWS_ACCESS_KEY", "/bundle.js")
        
        assert raw_key not in rec.masked_preview
        assert rec.masked_preview.startswith("AKIA")
        assert rec.masked_preview.endswith("MPLE")
        assert len(rec.sha256_fingerprint) == 64
        assert rec.state == SecretState.REDACTED_STORAGE
        
        # Retest secret revocation
        assert sm.retest_secret(rec.secret_id, is_still_functional=False) is True
        assert rec.state == SecretState.RETESTED_REVOKED


class TestModelAgnosticAdapter:
    def test_deterministic_no_llm_mode(self):
        adapter = ModelAgnosticAdapter(backend_type=ModelBackendType.NO_LLM_DETERMINISTIC)
        choice = adapter.plan_next_step(
            endpoint="/api/v1/auth/login",
            method="POST",
            discovered_params=["username", "password"],
            prioritized_checks=["RATE_LIMIT_BRUTEFORCE", "SESSION_SECURITY"]
        )
        assert choice.action_type == "PROBE_RATE_LIMIT_BRUTEFORCE"
        assert choice.model_provider == "NO_LLM_DETERMINISTIC_ENGINE"
        assert choice.confidence >= 0.85


class TestPeerReviewWorkflow:
    def test_peer_review_lifecycle(self):
        pw = PeerReviewWorkflow()
        packet = pw.submit_finding("F-SQLI-01", "shop.target.local", "SQL Injection", "CWE-89")
        assert packet.current_status == ReviewStatus.AWAITING_REVIEW
        assert len(pw.get_pending()) == 1
        
        # Approve finding
        pw.approve_finding("F-SQLI-01", "Security Lead", "All nonces verified")
        assert packet.current_status == ReviewStatus.APPROVED
        assert len(pw.get_pending()) == 0


class TestCapabilityNegotiationEngine:
    def test_capability_matching(self):
        engine = CapabilityNegotiationEngine()
        engine.register_agent("recon_worker", "Reconnaissance Worker", ["HTTP_PROBE", "JS_ANALYSIS"], max_budget=100, mutation_permitted=False)
        engine.register_agent("browser_worker", "DOM Browser Agent", ["BROWSER_DOM", "HTTP_PROBE"], max_budget=50, mutation_permitted=True)
        
        # Task requiring JS_ANALYSIS without mutation
        matched = engine.negotiate_agent_for_task(["JS_ANALYSIS"], requires_mutation=False)
        assert matched is not None
        assert matched.agent_id == "recon_worker"
        
        # Task requiring mutation cannot be assigned to recon_worker
        matched_mut = engine.negotiate_agent_for_task(["HTTP_PROBE"], requires_mutation=True)
        assert matched_mut is not None
        assert matched_mut.agent_id == "browser_worker"


class TestComplianceMapper:
    def test_sqli_and_bola_mapping(self):
        sqli_map = ComplianceMapper.map_cwe("CWE-89")
        assert "A03:2021" in sqli_map.owasp_top10
        assert "CAPEC-66" in sqli_map.capec_id
        assert "SI-10" in sqli_map.nist_sp800_53
        
        bola_map = ComplianceMapper.map_cwe("CWE-639")
        assert "A01:2021" in bola_map.owasp_top10
        assert "AC-3" in bola_map.nist_sp800_53


class TestUnknownsMatrix:
    def test_epistemic_visibility_breakdown(self):
        um = UnknownsMatrix("portal.target.local")
        um.record_asset("/api/login", "POST", SurfaceSector.KNOWN_TESTED, "Tested rate limits")
        um.record_asset("/api/search", "GET", SurfaceSector.KNOWN_TESTED, "Tested SQLi")
        um.record_asset("/api/docs", "GET", SurfaceSector.KNOWN_UNTESTED, "Pending in queue")
        um.record_asset("/ws/live", "WS", SurfaceSector.UNSUPPORTED, "WebSocket unsupported")
        
        summary = um.get_summary()
        assert summary["total_surface_points"] == 4
        assert summary["visibility_percentage"] == 50.0  # 2 of 4 tested
        assert summary["sectors"]["UNSUPPORTED"] == 1
        assert "Epistemic Warning" in summary["warning"]


class TestPostureTimelineTracker:
    def test_posture_trend_calculation(self):
        tracker = PostureTimelineTracker("target.corp.local")
        tracker.record_snapshot("SCN-1", "Jan", open_findings=10, fixed_findings=0, regressions=0, coverage_pct=60.0)
        tracker.record_snapshot("SCN-2", "Feb", open_findings=6, fixed_findings=4, regressions=0, coverage_pct=75.0)
        assert tracker.compute_trend() == PostureTrend.IMPROVING
        
        # Month 3 with a regression
        tracker.record_snapshot("SCN-3", "Mar", open_findings=7, fixed_findings=4, regressions=1, coverage_pct=80.0)
        assert tracker.compute_trend() == PostureTrend.DEGRADING
