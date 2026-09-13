"""
HunterAI V4.0 Evidence OS & Unified Cognitive Architecture Test Suite
====================================================================
Comprehensive automated verification of:
1. Evidence OS Unified Epistemic Model & Lineage
2. Security Memory Graph & Attack Surface Differ (Delta)
3. Goal-Driven Mission System & Evidence-Based Stopping
4. Risk Budgeting & Approval Queue (Human-in-the-Loop)
5. Epistemic Agent Blackboard (Strict Category Isolation)
6. Scan Health Score & Wait Diagnostics
7. Finding Fingerprints & Permanent Test Case Generation
"""

import tempfile
import pytest
from pathlib import Path

from core.evidence_os.unified_model import (
    EvidenceOS,
    ObservationType,
    RelationType
)
from core.memory.security_memory_graph import SecurityMemoryGraph, AttackSurfaceDiffer
from core.mission.mission_system import MissionSystem, MissionType, EvidenceStoppingEngine
from core.governance.risk_budget_queue import (
    RiskBudgetManager,
    ApprovalQueue,
    RiskTier,
    RiskBudgetExceededError
)
from core.blackboard.agent_blackboard import (
    AgentBlackboard,
    BlackboardSlot,
    EpistemicCategoryViolation
)
from core.observability.scan_health import (
    ScanHealthScoreEngine,
    AgentStateObserver,
    AgentWaitState
)
from core.testing.test_case_generator import FindingFingerprinter, TestCaseGenerator


class TestEvidenceOS:
    def test_canonical_lineage_and_verdict(self):
        eos = EvidenceOS()

        # 1. Ingest Observation
        obs = eos.ingest_observation(
            obs_type=ObservationType.HTTP_RESPONSE,
            source_tool="http_engine",
            target_url="https://api.target.local/v1/orders/42",
            snippet='{"order_id": 42, "user": "alice", "total": 100.0}',
            status_code=200
        )
        assert obs.obs_id.startswith("OBS-")

        # 2. Formulate Hypothesis
        hyp = eos.formulate_hypothesis(
            vulnerability_class="BOLA",
            target_endpoint="/v1/orders/42",
            parameter="order_id",
            predicted_behavior="Bob token accesses Alice order object",
            origin_obs_id=obs.obs_id
        )
        assert hyp.hypo_id.startswith("HYP-")

        # 3. Record Experiment
        exp = eos.record_experiment(
            hypothesis_id=hyp.hypo_id,
            baseline_obs_id=obs.obs_id,
            control_obs_id=obs.obs_id,
            active_obs_id=obs.obs_id,
            mutation_description="Replay request with Bob Authorization header"
        )

        # 4. Commit Evidence
        evi = eos.commit_evidence(
            experiment_id=exp.exp_id,
            has_execution_proof=True,
            poe_token="BOB_TOKEN_ACCESS_PROOF",
            differential_score=1.0,
            is_reproducible=True
        )

        # 5. Issue Claim
        clm = eos.issue_claim(
            evidence_id=evi.evidence_id,
            vulnerability_class="BOLA",
            confidence_score=0.99,
            rationale="Cross-tenant access confirmed via differential execution"
        )
        assert clm.provenance_hash_chain is not None

        # 6. Rule Verdict
        vrd = eos.rule_verdict(clm.claim_id, decision="CONFIRMED")
        assert vrd.decision == "CONFIRMED"

        # 7. Lineage verification
        assert eos.verify_claim_lineage(clm.claim_id) is True

    def test_broken_lineage_rejected(self):
        eos = EvidenceOS()
        with pytest.raises(ValueError):
            eos.formulate_hypothesis("SQLI", "/search", "q", "Error in query", "NON_EXISTENT_OBS")


class TestSecurityMemoryGraphAndDiffer:
    def test_attack_surface_delta(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mem = SecurityMemoryGraph(storage_dir=Path(tmpdir))
            mem.save_target_memory(
                domain="api.example.com",
                endpoints=["/api/v1/login", "/api/v1/users"],
                parameters={"/api/v1/users": ["id", "page"]},
                technologies=["Express", "Node.js"]
            )

            historical = mem.load_target_memory("api.example.com")
            assert historical is not None
            assert len(historical["endpoints"]) == 2

            # Compute Delta on subsequent scan with new surface
            delta = AttackSurfaceDiffer.compute_delta(
                domain="api.example.com",
                historical_data=historical,
                current_endpoints=["/api/v1/login", "/api/v1/users", "/api/v1/admin/export"],
                current_parameters={"/api/v1/users": ["id", "page", "filter"]},
                current_technologies=["Express", "Node.js", "Redis"]
            )
            assert delta.has_changes is True
            assert "/api/v1/admin/export" in delta.new_endpoints
            assert "filter" in delta.new_parameters["/api/v1/users"]
            assert "Redis" in delta.new_technologies


class TestMissionSystem:
    def test_mission_lifecycle_and_evidence_stopping(self):
        ms = MissionSystem(MissionType.AUTHENTICATION_AUDIT, "auth.target.local")
        assert not ms.is_mission_complete()

        # Satisfy goals
        ms.satisfy_goal("login_flow", "OBS-LOGIN-1")
        ms.satisfy_goal("session_state", "EVI-SESS-1")
        ms.satisfy_goal("rate_limit", "EVI-RATE-1")
        ms.satisfy_goal("revocation", "EVI-REVOKE-1")

        assert ms.is_mission_complete() is True
        summary = ms.get_progress_summary()
        assert summary["completion_percentage"] == 100.0

    def test_evidence_based_stopping(self):
        # Incomplete evidence -> should NOT stop
        partial_evidence = {"baseline_established", "differential_observed"}
        assert EvidenceStoppingEngine.should_stop_testing("SQLI", partial_evidence) is False

        # Full evidence confirmed -> STOP TESTING immediately (Zero Waste)
        full_evidence = {"baseline_established", "differential_observed", "arithmetic_poe_verified", "reproducible"}
        assert EvidenceStoppingEngine.should_stop_testing("SQLI", full_evidence) is True


class TestRiskBudgetAndApprovalQueue:
    def test_risk_budget_enforcement(self):
        mgr = RiskBudgetManager(high_limit=2)
        assert mgr.can_execute(RiskTier.HIGH_RISK) is True

        mgr.consume_budget(RiskTier.HIGH_RISK)
        mgr.consume_budget(RiskTier.HIGH_RISK)

        # Third high-risk request raises RiskBudgetExceededError
        with pytest.raises(RiskBudgetExceededError):
            mgr.consume_budget(RiskTier.HIGH_RISK)

    def test_approval_queue(self):
        queue = ApprovalQueue()
        item = queue.enqueue(
            action_id="ACT-DEL-01",
            target="api.target.local",
            endpoint="/api/v1/orders/1",
            method="DELETE",
            risk_tier=RiskTier.HIGH_RISK,
            expected_impact="Attempts cross-tenant deletion of order"
        )
        assert item.status == "PENDING"
        assert len(queue.get_pending_items()) == 1

        # Approve
        queue.approve(item.approval_id, operator_name="lead_analyst")
        assert item.status == "APPROVED"
        assert item.reviewer == "lead_analyst"
        assert len(queue.get_pending_items()) == 0


class TestAgentBlackboard:
    def test_epistemic_separation(self):
        bb = AgentBlackboard()
        bb.post_observation("browser_agent", "Observed script reflection", {"sink": "innerHTML"})
        bb.post_hypothesis("reasoner", "DOM XSS possible", {"param": "q"})

        # Posting to FACTS without verification proof is an Epistemic Category Violation
        with pytest.raises(EpistemicCategoryViolation):
            bb.post_fact("reasoner", "Target is XSS vulnerable", {"confirmed": True}, verification_proof="")

        # Posting to FACTS with proof succeeds
        fact = bb.post_fact("verifier", "DOM XSS confirmed", {"cwe": "CWE-79"}, verification_proof="PoE verified")
        assert fact.slot == BlackboardSlot.FACTS

        state = bb.get_blackboard_state()
        assert state["OBSERVATIONS"] == 1
        assert state["HYPOTHESES"] == 1
        assert state["FACTS"] == 1


class TestScanHealthScore:
    def test_scan_health_and_wait_diagnostics(self):
        report = ScanHealthScoreEngine.calculate_health(
            scope_violations=0,
            evidence_corrupted=0,
            probed_endpoints=90,
            total_endpoints=100,
            tested_roles=4,
            total_roles=4,
            verified_findings=10,
            total_findings=10,
            tool_failures=2,
            total_tool_calls=100
        )
        assert report.overall_reliability_pct >= 90.0
        assert report.grade == "EXCELLENT"

        # Diagnostic natural language output
        diag = AgentStateObserver.diagnose_wait_state(
            AgentWaitState.WAITING_FOR_OPERATOR_APPROVAL,
            {"action_id": "ACT-101"}
        )
        assert "requires operator sign-off" in diag


class TestFindingFingerprintsAndTestCases:
    def test_fingerprint_consistency(self):
        # Numerical IDs normalized to {id} -> same structural fingerprint
        fp1 = FindingFingerprinter.compute_fingerprint("BOLA", "Missing Authorization Middleware", "/api/v1/orders/101", "order_id")
        fp2 = FindingFingerprinter.compute_fingerprint("BOLA", "Missing Authorization Middleware", "/api/v1/orders/999", "order_id")
        assert fp1 == fp2

    def test_test_case_generator(self):
        tc = TestCaseGenerator.generate_test_case(
            finding_id="F-4042",
            vulnerability_class="SQLi",
            title="Blind SQL Injection",
            endpoint="https://api.target.local/search",
            parameter="query",
            payload="' UNION SELECT 1,2,3--",
            expected_status=403
        )
        assert tc.test_case_id.startswith("TC-SQLI-")
        assert "curl" in tc.reproduce_command
        assert tc.expected_safe_behavior is not None
from core.resilience.stability_guard import StabilityGuard, RedirectLoopError, CircuitOpenError
from core.orchestration.checkpoint_manager import CheckpointManager


class TestStabilityAndCheckpoints:
    def test_stability_truncation_and_redirects(self):
        guard = StabilityGuard(max_response_bytes=100, max_redirect_hops=3)

        # Truncation
        large_payload = b"A" * 250
        truncated, was_cut = guard.truncate_payload(large_payload)
        assert was_cut is True
        assert len(truncated) == 100

        # Circular redirect loop detection
        with pytest.raises(RedirectLoopError):
            guard.validate_redirect_chain(["https://target/a", "https://target/b", "https://target/a"])

        # Excessive redirect hops
        with pytest.raises(RedirectLoopError):
            guard.validate_redirect_chain(["/1", "/2", "/3", "/4"])

    def test_circuit_breaker(self):
        guard = StabilityGuard(consecutive_failure_threshold=2, circuit_cooldown_sec=30.0)
        ep = "GET:/api/slow"

        # Record 2 consecutive timeouts -> trips circuit
        guard.record_outcome(ep, is_success=False, is_timeout=True)
        guard.record_outcome(ep, is_success=False, is_timeout=True)

        with pytest.raises(CircuitOpenError):
            guard.pre_request_check(ep)

        # Successful recovery
        guard.record_outcome(ep, is_success=True)
        guard.pre_request_check(ep)  # Should not raise

    def test_checkpoint_atomic_save_and_resume(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = CheckpointManager(checkpoints_dir=Path(tmpdir))
            saved_file = mgr.save_checkpoint(
                mission_id="MSS-100",
                target="api.target.local",
                started_at=1700000000.0,
                completed_endpoints={"/api/v1/login", "/api/v1/users"},
                pending_queue=["/api/v1/orders"],
                findings_count=3,
                coverage_pct=66.7
            )
            assert saved_file.exists()

            # Load checkpoint
            loaded = mgr.load_checkpoint("MSS-100")
            assert loaded is not None
            assert loaded.target == "api.target.local"
            assert "/api/v1/login" in loaded.completed_endpoints
            assert loaded.findings_count == 3
            assert loaded.coverage_percentage == 66.7
