"""
HunterAI V19.0 Epistemic Security OS Test Suite
================================================
Comprehensive verification of the 5 Grand Epistemic Pillars:
1. Security Finding Contract Engine (preconditions, tripartite evidence, zero-heuristic, reproduction gating)
2. Evidence Drift & Replay Classifier (6 distinct regression/drift classifications)
3. Adversarial Agent Epistemic Benchmark (prompt injection, fake reflection traps, server jitter, bombs)
4. Portable Investigation Bundle (export, SHA-256 tamper seal, EvidenceTamperError detection)
5. Cost-to-Evidence Optimizer & Categorized Budget Allocator (Knapsack Pareto selection & category pools)
6. Policy-as-Code Engine & Policy Receipts (versioned policies v1.4, environment tiers, audit receipts)
7. Agent Decision Trace (observable chronological reasoning trace without opaque CoT)
8. AutonomousBrain V19 End-to-End Epistemic Integration
9. Platform CLI Subcommands Dispatch
"""
import pytest
from pathlib import Path
import tempfile
import json
import subprocess
import sys
from unittest.mock import MagicMock, AsyncMock

from core.contract.security_contract import (
    SecurityContractEngine,
    SecurityFindingContract,
    EvidenceRequirement,
    RequirementStatus,
    ContractEvaluationResult,
)
from core.drift.evidence_drift_classifier import (
    EvidenceDriftClassifier,
    DriftClassification,
    DriftVerdict,
)
from core.benchmark.adversarial_agent_benchmark import (
    AdversarialAgentBenchmark,
    AdversarialTestCase,
)
from core.bundle.investigation_bundle import (
    InvestigationBundleManager,
    InvestigationBundle,
    EvidenceTamperError,
)
from core.optimization.cost_to_evidence import (
    CostToEvidenceOptimizer,
    ExperimentCandidate,
    OptimizedExperimentPlan,
)
from core.budget.categorized_budget import (
    CategorizedBudgetManager,
    BudgetCategory,
)
from core.policy.policy_as_code import (
    PolicyAsCodeEngine,
    EnvironmentTier,
    PolicyDecision,
    PolicyReceipt,
)
from core.trace.agent_decision_trace import (
    AgentDecisionTrace,
    DecisionTraceStep,
)
from core.brain.autonomous_brain import AutonomousBrain


class TestSecurityFindingContractEngine:
    """1. Formal typed evidence contracts per vulnerability family"""

    def test_sqli_contract_full_fulfillment(self):
        contract = SecurityContractEngine.get_contract("SQLI")
        assert contract is not None
        assert contract.cwe_id == "CWE-89"

        evidence = {
            "baseline_stable": True,
            "computational_nonce_proven": True,
            "syntax_differential_proven": True,
            "negative_control_passed": True,
        }
        res = contract.evaluate(evidence, reproduction_count=2)
        assert res.is_satisfied is True
        assert res.verdict == "CONFIRMED"
        assert len(res.fulfilled_requirements) == 4
        assert len(res.unfulfilled_requirements) == 0

    def test_zero_heuristic_rejection_when_missing_nonce(self):
        contract = SecurityContractEngine.get_contract("SQLI")
        evidence = {
            "baseline_stable": True,
            "computational_nonce_proven": False,  # Missing mandatory computational nonce!
            "syntax_differential_proven": True,
            "negative_control_passed": True,
        }
        res = contract.evaluate(evidence, reproduction_count=3)
        assert res.is_satisfied is False
        assert res.verdict == "INSUFFICIENT_EVIDENCE"
        assert any("Arithmetic Computational Nonce" in r for r in res.unfulfilled_requirements)

    def test_reproduction_threshold_gating(self):
        contract = SecurityContractEngine.get_contract("BOLA")
        assert contract is not None
        evidence = {
            "tenant_a_access": True,
            "tenant_b_replay": True,
            "differential_data_matched": True,
            "invalid_token_rejected": True,
        }
        # Only 1 run when 2 required
        res_single = contract.evaluate(evidence, reproduction_count=1)
        assert res_single.is_satisfied is False
        assert res_single.verdict == "INSUFFICIENT_EVIDENCE"

        # 2 verified runs -> passes
        res_multi = contract.evaluate(evidence, reproduction_count=2)
        assert res_multi.is_satisfied is True
        assert res_multi.verdict == "CONFIRMED"


class TestEvidenceDriftClassificationMatrix:
    """2. Forensic classification of replay divergence during regression retesting"""

    def test_classify_vulnerability_still_exists(self):
        orig = {"status_code": 200, "proof_nonce": "NONCE-777"}
        curr = {"status_code": 200, "body": "Record found: NONCE-777 leaked."}
        verdict = EvidenceDriftClassifier.classify_replay("F-01", orig, curr)
        assert verdict.classification == DriftClassification.VULNERABILITY_STILL_EXISTS
        assert verdict.confidence == 1.0

    def test_classify_genuinely_fixed(self):
        orig = {"status_code": 200, "proof_nonce": "NONCE-777"}
        curr = {"status_code": 200, "body": "Safe sanitized output: clean"}
        verdict = EvidenceDriftClassifier.classify_replay("F-02", orig, curr)
        assert verdict.classification == DriftClassification.VULNERABILITY_GENUINELY_FIXED

    def test_classify_waf_or_rate_limit(self):
        orig = {"status_code": 200, "proof_nonce": "NONCE-777"}
        curr = {"status_code": 403, "body": "<html>Cloudflare error: Attention Required!</html>"}
        verdict = EvidenceDriftClassifier.classify_replay("F-03", orig, curr)
        assert verdict.classification == DriftClassification.WAF_OR_RATE_LIMIT_BLOCKED

    def test_classify_auth_session_expired(self):
        orig = {"status_code": 200, "proof_nonce": "NONCE-777"}
        curr = {"status_code": 401, "body": "Unauthorized: Session token invalid"}
        verdict = EvidenceDriftClassifier.classify_replay("F-04", orig, curr)
        assert verdict.classification == DriftClassification.AUTH_SESSION_EXPIRED

    def test_classify_endpoint_decommissioned(self):
        orig = {"status_code": 200, "proof_nonce": "NONCE-777"}
        curr = {"status_code": 404, "body": "Not Found: API route removed"}
        verdict = EvidenceDriftClassifier.classify_replay("F-05", orig, curr)
        assert verdict.classification == DriftClassification.ENDPOINT_DECOMMISSIONED

    def test_classify_host_timeout_or_unreachable(self):
        orig = {"status_code": 200, "proof_nonce": "NONCE-777"}
        curr = {"status_code": 0, "is_timeout": True, "body": ""}
        verdict = EvidenceDriftClassifier.classify_replay("F-06", orig, curr)
        assert verdict.classification == DriftClassification.HOST_UNREACHABLE_OR_TIMEOUT


class TestAdversarialAgentBenchmark:
    """3. Epistemic robustness against prompt injection, fake reflections, and server jitter"""

    def test_benchmark_suite_execution(self):
        report = AdversarialAgentBenchmark.run_benchmark()
        assert report["total_adversarial_cases"] == 5
        assert report["passed_cases"] == 5
        assert report["failed_cases"] == 0
        assert report["epistemic_robustness_score"] == 100.0

        results = {r["case_id"]: r for r in report["results"]}
        assert results["ADV-INJECT-01"]["observed"] == "PROMPT_INJECTION_STRIPPED"
        assert results["ADV-TRAP-02"]["observed"] == "REFUTED"
        assert results["ADV-JITTER-03"]["observed"] == "INCONCLUSIVE"
        assert results["ADV-LOOP-04"]["observed"] == "LOOP_TERMINATED"
        assert results["ADV-BOMB-05"]["observed"] == "TRUNCATED_SAFE"


class TestPortableInvestigationBundle:
    """4. Self-contained case packaging with cryptographic tamper seals"""

    def test_export_and_integrity_verification(self, tmp_path):
        finding_data = {
            "finding_id": "F-0042",
            "title": "Verified SQL Injection",
            "cwe_id": "CWE-89",
            "endpoint": "https://api.target.local/api/users",
        }
        bundle = InvestigationBundleManager.export_case(
            finding_id="F-0042",
            target="api.target.local",
            finding_data=finding_data,
            output_parent_dir=tmp_path
        )
        assert bundle.bundle_dir.exists()
        assert (bundle.bundle_dir / "finding.json").exists()
        assert (bundle.bundle_dir / "contract.json").exists()
        assert (bundle.bundle_dir / "replay" / "replay.py").exists()
        assert (bundle.bundle_dir / "integrity.json").exists()
        assert bundle.verify_integrity() is True

    def test_tamper_detection_raises_exception(self, tmp_path):
        bundle = InvestigationBundleManager.export_case(
            finding_id="F-TAMPER",
            target="api.target.local",
            finding_data={"finding_id": "F-TAMPER"},
            output_parent_dir=tmp_path
        )
        # Malicious modification of evidence artifact
        active_json = bundle.bundle_dir / "evidence" / "active.json"
        active_json.write_text('{"tampered": true}', encoding="utf-8")

        with pytest.raises(EvidenceTamperError) as exc_info:
            bundle.verify_integrity()
        assert "EVIDENCE INTEGRITY FAILURE" in str(exc_info.value)


class TestCostToEvidenceOptimizer:
    """5. Pareto-optimal experiment scheduling maximizing evidence yield per request"""

    def test_optimizer_selects_high_yield_nonce_first(self):
        candidates = [
            ExperimentCandidate("EXP-01", "Blind Timing Probe (Slow)", expected_information_gain=30.0, request_cost=10),
            ExperimentCandidate("EXP-02", "Deterministic Nonce Expression", expected_information_gain=85.0, request_cost=1, is_definitive_nonce=True),
            ExperimentCandidate("EXP-03", "Generic Error Forcing", expected_information_gain=40.0, request_cost=5),
        ]
        plan = CostToEvidenceOptimizer.optimize_plan(candidates, target_evidence_threshold=80.0)
        assert plan.total_expected_gain >= 80.0
        assert len(plan.selected_experiments) == 1
        assert plan.selected_experiments[0].experiment_id == "EXP-02"
        assert plan.total_request_cost == 1
        assert plan.savings_percentage > 50.0


class TestCategorizedBudgetAllocator:
    """6. Categorized test budgets and dynamic reallocation"""

    def test_categorized_budget_consumption_and_reserve(self):
        mgr = CategorizedBudgetManager()
        # Consume from AUTHENTICATION
        assert mgr.consume(BudgetCategory.AUTHENTICATION, 700) is True
        summary = mgr.get_summary()
        assert summary["categories"]["AUTHENTICATION"]["remaining"] == 100

        # Overdraw from AUTHENTICATION draws from RESERVE
        assert mgr.consume(BudgetCategory.AUTHENTICATION, 200) is True
        summary_after = mgr.get_summary()
        assert summary_after["categories"]["RESERVE"]["remaining"] == 100

    def test_dynamic_reallocation(self):
        mgr = CategorizedBudgetManager()
        # Move 300 requests from CLIENT_SIDE_JS to INJECTION_TESTS
        assert mgr.reallocate(BudgetCategory.CLIENT_SIDE_JS, BudgetCategory.INJECTION_TESTS, 300) is True
        summary = mgr.get_summary()
        assert summary["categories"]["CLIENT_SIDE_JS"]["allocated"] == 400
        assert summary["categories"]["INJECTION_TESTS"]["allocated"] == 1800


class TestPolicyAsCodeAndDecisionTrace:
    """7. Versioned Policy receipts and observable Agent Decision Traces"""

    def test_policy_as_code_receipt_generation(self):
        engine = PolicyAsCodeEngine(policy_version="v1.4", environment=EnvironmentTier.LAB)
        receipt = engine.evaluate_action(
            target="https://target.local/api/users",
            action_type="ACTIVE_INJECTION_TEST",
            is_state_mutating=True,
            is_in_scope=True
        )
        assert receipt.policy_version == "v1.4"
        assert receipt.decision == PolicyDecision.ALLOW
        assert receipt.receipt_id.startswith("POL-v14-")

    def test_policy_out_of_scope_denied(self):
        engine = PolicyAsCodeEngine(policy_version="v1.4", environment=EnvironmentTier.LAB)
        receipt = engine.evaluate_action(
            target="https://out-of-scope.com/leak",
            action_type="PROBE",
            is_state_mutating=False,
            is_in_scope=False
        )
        assert receipt.decision == PolicyDecision.DENY

    def test_agent_decision_trace_chronology(self):
        trace = AgentDecisionTrace("TRC-001", "api.target.local")
        s1 = trace.record_step(
            observation="Discovered /api/orders endpoint",
            evidence=["HTTP 200 OK"],
            decision="Select BOLA probe",
            policy_result="ALLOW",
            action="Replay with secondary token",
            result="HTTP 403"
        )
        assert s1.step_id.startswith("TRC-")
        assert len(trace.steps) == 1
        timeline = trace.format_timeline_ascii()
        assert "Total Auditable Steps: 1" in timeline
        assert "Discovered /api/orders" in timeline


class TestAutonomousBrainV19Integration:
    """8. AutonomousBrain Epistemic OS integration"""

    def test_brain_v19_subsystems_attached(self):
        brain = AutonomousBrain(resource_manager=MagicMock(), tool_manager=MagicMock(), dry_run=True)
        assert brain.decision_trace is not None
        assert brain.policy_engine is not None
        assert brain.contract_engine is not None
        assert brain.budget_manager is not None
        assert brain.drift_classifier is not None
        assert brain.bundle_manager is not None

    @pytest.mark.asyncio
    async def test_brain_run_scan_epistemic_provenance(self):
        brain = AutonomousBrain(resource_manager=MagicMock(), tool_manager=MagicMock(), dry_run=True)
        res = await brain.run_scan("https://target.local")
        assert res is not None
        assert len(brain.decision_trace.steps) >= 1
        assert "armed into active scope" in brain.decision_trace.steps[0].observation_summary


class TestCLIAllEpistemicSubcommands:
    """9. CLI subcommands execution verification"""

    def test_cli_epistemic_commands(self):
        cmds = [
            ["benchmark-agent"],
            ["contract", "--vuln", "SQLI"],
            ["drift", "--replay-status", "403"],
            ["budget"],
            ["trace"],
            ["unknowns"],
        ]
        for c in cmds:
            res = subprocess.run([sys.executable, "cli/hunter_cli.py"] + c, capture_output=True, text=True)
            assert res.returncode == 0, f"Command {c} failed: {res.stderr}"
