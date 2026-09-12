"""
Tests for SecurityResearchOS, CoverageTracker, CausalGraph, and NextBestAction
"""
import pytest

from hunter_ai.runtime import (
    SecurityResearchOS, CoverageTracker, CausalGraph, ScientificExperiment,
    NextBestAction, ActionKind, HypothesisTree, HypothesisStatus
)


# ─── 1. CoverageTracker & Dead Zones Tests ────────────────────────────────────
class TestCoverageTracker:
    def test_dead_zone_detection(self):
        tracker = CoverageTracker()
        tracker.record_discovered_endpoint("/api/users", ["id", "role"])
        tracker.record_discovered_endpoint("/api/orders", ["order_id"])
        tracker.record_discovered_endpoint("/api/untested_endpoint")

        # Test only one endpoint and param
        tracker.record_tested("/api/users", param="id")

        dead_zones = tracker.get_dead_zones()
        assert "/api/untested_endpoint" in dead_zones["untested_endpoints"]
        assert "/api/orders" in dead_zones["untested_endpoints"]
        assert "/api/users::role" in dead_zones["untested_params"]

        metrics = tracker.get_metrics()
        assert metrics["total_discovered_endpoints"] == 3
        assert metrics["total_tested_endpoints"] == 1
        assert metrics["endpoint_coverage_pct"] == 33.3


# ─── 2. CausalGraph & Chains Tests ────────────────────────────────────────────
class TestCausalGraph:
    def test_exploit_chain_formation(self):
        graph = CausalGraph()
        graph.add_causal_relation("Unauthenticated Registration", "Tenant Account Created", "CAUSES")
        graph.add_causal_relation("Tenant Account Created", "Predictable Object ID Exposed", "ENABLES")
        graph.add_causal_relation("Predictable Object ID Exposed", "Cross-Tenant Private Invoice Read", "EXPOSES")

        chains = graph.get_chains()
        assert len(chains) == 1
        chain = chains[0]
        assert chain[0] == "Unauthenticated Registration"
        assert chain[-1] == "Cross-Tenant Private Invoice Read"
        assert len(chain) == 4


# ─── 3. Scientific Experiment & Active Learning Utility ────────────────────────
class TestScientificExperiment:
    def test_active_learning_utility_calculation(self):
        exp = ScientificExperiment(
            id="EXP-001",
            hypothesis_id="H1",
            target_endpoint="/api/query",
            param_name="id",
            probe_kind="BOOLEAN_PAIR",
            baseline_request={"url": "/api/query?id=1"},
            mutated_request={"url": "/api/query?id=1' AND 1=1--"},
            counterfactual_check="Revert to baseline on 1=2",
            expected_information_gain=0.8,
            cost=2.0
        )

        # High confidence hypothesis (0.9)
        # Utility = (0.8 * 0.9) / 2.0 = 0.36
        utility = exp.calculate_utility(hypothesis_confidence=0.9)
        assert pytest.approx(utility, 0.01) == 0.36


# ─── 4. SecurityResearchOS & Next Best Action Tests ────────────────────────────
class TestSecurityResearchOS:
    def test_next_best_action_prefers_high_utility_hypothesis(self):
        os_brain = SecurityResearchOS(target_domain="shop.example.com")
        tree = HypothesisTree()

        # Add active hypothesis
        tree.create_hypothesis(
            category="SQLi",
            variant="boolean_differential",
            title="SQL Injection on Category",
            description="Testing category filter",
            target_endpoint="http://shop.example.com/products",
            param_name="category",
            initial_confidence=0.75
        )

        nba = os_brain.compute_next_best_action(tree)
        assert nba.action_kind == ActionKind.TEST_HIGH_CONFIDENCE_HYPOTHESIS
        assert nba.target_endpoint == "http://shop.example.com/products"
        assert nba.target_param == "category"
        assert nba.utility_score > 0
        assert nba.experiment is not None

    def test_next_best_action_explores_dead_zones_when_frontier_empty(self):
        os_brain = SecurityResearchOS(target_domain="shop.example.com")
        tree = HypothesisTree() # Empty tree

        # Register discovered endpoints
        os_brain.coverage.record_discovered_endpoint("/api/unexplored")

        nba = os_brain.compute_next_best_action(tree)
        assert nba.action_kind == ActionKind.PROBE_DEAD_ZONE
        assert nba.target_endpoint == "/api/unexplored"

    def test_mission_dna_export(self):
        os_brain = SecurityResearchOS(target_domain="target.local")
        tree = HypothesisTree()
        dna = os_brain.to_dna_summary(tree)

        assert dna["target"] == "target.local"
        assert "coverage_metrics" in dna
        assert "next_best_action" in dna
        assert "world_model" in dna
