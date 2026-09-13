"""
HunterAI V6.0 Agent Security Engineering Test Suite
===================================================
Comprehensive tests for:
- SecurityContractEngine (contract requirements, reproduction gating, zero-heuristic)
- EvidenceDriftClassifier (replay drift: fixed, expired auth, WAF, decommissioned)
- AdversarialAgentBenchmark (epistemic defense against injections, traps, jitter, bombs)
- InvestigationBundleManager (tamper-evident export, SHA-256 verification, tamper exceptions)
- CostToEvidenceOptimizer (greedy knapsack information gain per request)
- PolicyAsCodeEngine (versioned policies, environment tiers, audit receipts)
- CategorizedBudgetManager (category pools, reserve fallback, reallocation)
- NegativeKnowledgeBase (recording and querying verified negative proofs)
"""
import pytest
from pathlib import Path
import tempfile
import json

from core.contract.security_contract import (
    SecurityContractEngine,
    SecurityFindingContract,
    EvidenceRequirement,
    RequirementStatus,
)
from core.drift.evidence_drift_classifier import (
    EvidenceDriftClassifier,
    DriftClassification,
    DriftVerdict,
)
from core.benchmark.adversarial_agent_benchmark import AdversarialAgentBenchmark
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
from core.policy.policy_as_code import (
    PolicyAsCodeEngine,
    EnvironmentTier,
    PolicyDecision,
    PolicyReceipt,
)
from core.budget.categorized_budget import (
    CategorizedBudgetManager,
    BudgetCategory,
)
from core.memory.negative_knowledge_base import (
    NegativeKnowledgeBase,
    NegativeProof,
)


class TestSecurityContractEngine:
    def test_sqli_contract_satisfied(self):
        evidence = {
            "baseline_stable": True,
            "computational_nonce_proven": True,
            "syntax_differential_proven": True,
            "negative_control_passed": True,
        }
        res = SecurityContractEngine.evaluate_claim("SQLI", evidence, reproduction_count=2)
        assert res.is_satisfied is True
        assert res.verdict == "CONFIRMED"
        assert len(res.unfulfilled_requirements) == 0

    def test_sqli_contract_breached_on_missing_nonce(self):
        evidence = {
            "baseline_stable": True,
            "computational_nonce_proven": False,  # Missing proof!
            "syntax_differential_proven": True,
            "negative_control_passed": True,
        }
        res = SecurityContractEngine.evaluate_claim("SQLI", evidence, reproduction_count=2)
        assert res.is_satisfied is False
        assert res.verdict == "INSUFFICIENT_EVIDENCE"
        assert any("Arithmetic Computational Nonce" in u for u in res.unfulfilled_requirements)

    def test_reproduction_threshold_gating(self):
        evidence = {
            "baseline_stable": True,
            "computational_nonce_proven": True,
            "syntax_differential_proven": True,
            "negative_control_passed": True,
        }
        # Only 1 reproduction when contract mandates 2
        res = SecurityContractEngine.evaluate_claim("SQLI", evidence, reproduction_count=1)
        assert res.is_satisfied is False
        assert any("Reproduction threshold not met" in u for u in res.unfulfilled_requirements)

    def test_bola_contract(self):
        evidence = {
            "tenant_a_access": True,
            "tenant_b_replay": True,
            "differential_data_matched": True,
            "invalid_token_rejected": True,
        }
        res = SecurityContractEngine.evaluate_claim("BOLA", evidence, reproduction_count=3)
        assert res.is_satisfied is True
        assert res.verdict == "CONFIRMED"


class TestEvidenceDriftClassifier:
    def test_vulnerability_still_exists(self):
        orig = {"status_code": 200, "proof_nonce": "CONF_DATA_42"}
        curr = {"status_code": 200, "body": "Welcome user. Here is CONF_DATA_42"}
        v = EvidenceDriftClassifier.classify_replay("F-1", orig, curr)
        assert v.classification == DriftClassification.VULNERABILITY_STILL_EXISTS
        assert v.confidence == 1.0

    def test_genuinely_fixed(self):
        orig = {"status_code": 200, "proof_nonce": "CONF_DATA_42"}
        curr = {"status_code": 200, "body": "Order details safely retrieved without sensitive leak."}
        v = EvidenceDriftClassifier.classify_replay("F-2", orig, curr)
        assert v.classification == DriftClassification.VULNERABILITY_GENUINELY_FIXED
        assert v.confidence >= 0.9

    def test_auth_expired(self):
        orig = {"status_code": 200, "proof_nonce": "CONF_DATA_42"}
        curr = {"status_code": 401, "body": "Unauthorized: Session token expired"}
        v = EvidenceDriftClassifier.classify_replay("F-3", orig, curr)
        assert v.classification == DriftClassification.AUTH_SESSION_EXPIRED
        assert "Refresh session" in v.recommended_action

    def test_waf_rate_limit(self):
        orig = {"status_code": 200, "proof_nonce": "CONF_DATA_42"}
        curr = {"status_code": 429, "body": "Rate limit exceeded"}
        v = EvidenceDriftClassifier.classify_replay("F-4", orig, curr)
        assert v.classification == DriftClassification.WAF_OR_RATE_LIMIT_BLOCKED

    def test_endpoint_decommissioned(self):
        orig = {"status_code": 200, "proof_nonce": "CONF_DATA_42"}
        curr = {"status_code": 404, "body": "Not Found"}
        v = EvidenceDriftClassifier.classify_replay("F-5", orig, curr)
        assert v.classification == DriftClassification.ENDPOINT_DECOMMISSIONED


class TestAdversarialAgentBenchmark:
    def test_adversarial_suite_execution(self):
        res = AdversarialAgentBenchmark.run_benchmark()
        assert res["total_adversarial_cases"] == 5
        assert res["passed_cases"] == 5
        assert res["epistemic_robustness_score"] == 100.0


class TestInvestigationBundle:
    def test_export_and_integrity_verification(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir)
            finding = {"finding_id": "F-100", "title": "SQLi in Cart", "endpoint": "/api/cart"}
            bundle = InvestigationBundleManager.export_case("F-100", "shop.target.local", finding, out)
            
            assert bundle.bundle_dir.exists()
            assert (bundle.bundle_dir / "manifest.json").exists()
            assert (bundle.bundle_dir / "integrity.json").exists()
            assert (bundle.bundle_dir / "evidence" / "active.json").exists()
            assert (bundle.bundle_dir / "replay" / "replay.py").exists()
            
            # Verify integrity
            loaded = InvestigationBundleManager.load_case(bundle.bundle_dir)
            assert loaded.verify_integrity() is True

    def test_tamper_detection(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir)
            finding = {"finding_id": "F-200", "title": "BOLA", "endpoint": "/api/users"}
            bundle = InvestigationBundleManager.export_case("F-200", "api.target.local", finding, out)
            
            # Tamper with active.json
            active_file = bundle.bundle_dir / "evidence" / "active.json"
            active_file.write_text('{"tampered": true}', encoding="utf-8")
            
            # Loading or verifying must raise EvidenceTamperError
            with pytest.raises(EvidenceTamperError):
                bundle.verify_integrity()


class TestCostToEvidenceOptimizer:
    def test_optimizer_selects_high_efficiency_probes(self):
        candidates = [
            ExperimentCandidate("EXP-1", "Heavy Fuzzing (50 payloads)", expected_information_gain=50.0, request_cost=50),
            ExperimentCandidate("EXP-2", "Definitive Nonce Probe", expected_information_gain=85.0, request_cost=2, is_definitive_nonce=True),
            ExperimentCandidate("EXP-3", "Minor Header Probe", expected_information_gain=20.0, request_cost=10),
        ]
        
        # Target threshold: 80 units
        plan = CostToEvidenceOptimizer.optimize_plan(candidates, target_evidence_threshold=80.0)
        
        assert len(plan.selected_experiments) == 1
        assert plan.selected_experiments[0].experiment_id == "EXP-2"
        assert plan.total_request_cost == 2
        assert plan.savings_percentage > 90.0  # Saved 60 requests!


class TestPolicyAsCodeEngine:
    def test_out_of_scope_denied(self):
        engine = PolicyAsCodeEngine(policy_version="v1.4", environment=EnvironmentTier.LAB)
        receipt = engine.evaluate_action("evil.com", "GET", False, is_in_scope=False)
        assert receipt.decision == PolicyDecision.DENY
        assert receipt.policy_version == "v1.4"

    def test_production_mutations_require_approval(self):
        engine = PolicyAsCodeEngine(policy_version="v2.0", environment=EnvironmentTier.PRODUCTION)
        receipt = engine.evaluate_action("prod.target.com", "POST", is_state_mutating=True, is_in_scope=True)
        assert receipt.decision == PolicyDecision.APPROVAL_REQUIRED

    def test_lab_allows_active_mutations(self):
        engine = PolicyAsCodeEngine(policy_version="v1.4", environment=EnvironmentTier.LAB)
        receipt = engine.evaluate_action("lab.target.local", "POST", is_state_mutating=True, is_in_scope=True)
        assert receipt.decision == PolicyDecision.ALLOW


class TestCategorizedBudgetManager:
    def test_budget_consumption_and_reserve(self):
        bm = CategorizedBudgetManager({
            BudgetCategory.AUTHENTICATION: 5,
            BudgetCategory.RESERVE: 10
        })
        
        # Consume primary allocation
        assert bm.consume(BudgetCategory.AUTHENTICATION, 5) is True
        assert bm.quotas[BudgetCategory.AUTHENTICATION].remaining == 0
        
        # Next consumption draws from RESERVE
        assert bm.consume(BudgetCategory.AUTHENTICATION, 3) is True
        assert bm.quotas[BudgetCategory.RESERVE].remaining == 7

    def test_reallocation(self):
        bm = CategorizedBudgetManager({
            BudgetCategory.CLIENT_SIDE_JS: 200,
            BudgetCategory.INJECTION_TESTS: 500
        })
        success = bm.reallocate(BudgetCategory.CLIENT_SIDE_JS, BudgetCategory.INJECTION_TESTS, 100)
        assert success is True
        assert bm.quotas[BudgetCategory.CLIENT_SIDE_JS].allocated == 100
        assert bm.quotas[BudgetCategory.INJECTION_TESTS].allocated == 600


class TestNegativeKnowledgeBase:
    def test_negative_proof_caching(self):
        nkb = NegativeKnowledgeBase()
        assert nkb.is_known_negative("/api/search", "GET", "SQL_INJECTION") is None
        
        proof = nkb.record_negative_proof("/api/search", "GET", "SQL_INJECTION", 200, "Clean arithmetic evaluation")
        assert proof.confidence_score >= 0.9
        
        cached = nkb.is_known_negative("/api/search", "GET", "SQL_INJECTION")
        assert cached is not None
        assert cached.endpoint == "/api/search"
        assert nkb.count() == 1
