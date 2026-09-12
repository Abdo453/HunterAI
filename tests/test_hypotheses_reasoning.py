"""
Unit Tests for Hypotheses Reasoning Engine
Tests: HypothesisTracker lifecycle, GraphHypothesisGenerator topological rules, and BayesianHypothesisScorer
"""
import pytest
from core.hypotheses.tracker import HypothesisTracker, TrackedHypothesis, HypothesisState
from core.hypotheses.generator import GraphHypothesisGenerator
from core.hypotheses.scorer import BayesianHypothesisScorer
from core.attack_graph.graph import CausalAttackGraph
from core.attack_graph.nodes import AttackNode, NodeType
from agents.security_intelligence.schemas import EvidenceItem, EvidenceType


class TestHypothesesReasoning:
    def test_hypothesis_tracker_lifecycle(self):
        tracker = HypothesisTracker()
        hyp = TrackedHypothesis(
            title="Test BOLA",
            vuln_type="BOLA",
            target_node_id="ep1",
            target_endpoint="/api/v1/users/123"
        )
        tracker.register_hypothesis(hyp)
        assert hyp.status == HypothesisState.UNTESTED

        tracker.update_status(hyp.id, HypothesisState.IN_PROGRESS, "Probing started")
        assert tracker.get_hypothesis(hyp.id).status == HypothesisState.IN_PROGRESS

        tracker.update_status(hyp.id, HypothesisState.VALIDATED, "Confirmed differential")
        assert tracker.get_hypothesis(hyp.id).status == HypothesisState.VALIDATED
        assert len(tracker.get_hypothesis(hyp.id).experiment_log) == 2

    def test_graph_hypothesis_generator_rules(self):
        graph = CausalAttackGraph(target="app.local")

        # 1. BOLA endpoint with ID
        graph.add_node(AttackNode(
            id="ep1", node_type=NodeType.ENDPOINT, label="/api/v1/invoices/9921",
            properties={"auth_required": True, "parameters": ["format"]}
        ))
        # 2. Admin endpoint for BFLA
        graph.add_node(AttackNode(
            id="ep2", node_type=NodeType.ENDPOINT, label="/admin/system/settings",
            properties={"auth_required": True}
        ))
        # 3. Search endpoint for SQLi
        graph.add_node(AttackNode(
            id="ep3", node_type=NodeType.ENDPOINT, label="/products",
            properties={"parameters": ["search", "limit", "sort"]}
        ))

        generator = GraphHypothesisGenerator(graph)
        hypotheses = generator.generate_hypotheses_from_graph()

        assert len(hypotheses) == 3
        types = {h.vuln_type for h in hypotheses}
        assert "BOLA" in types
        assert "BFLA" in types
        assert "SQLi" in types

    def test_bayesian_scorer_increases_probability_on_differential_evidence(self):
        scorer = BayesianHypothesisScorer()
        hyp = TrackedHypothesis(
            title="Potential BOLA",
            vuln_type="BOLA",
            target_node_id="ep1",
            target_endpoint="/api/v1/invoices/100",
            prior_probability=0.50
        )

        diff_ev = EvidenceItem(
            type=EvidenceType.BEHAVIOR_DIFF,
            source="test",
            description="Differential 200 OK observed",
            weight=0.90
        )

        posterior = scorer.update_probability(hyp, diff_ev, is_refuting=False)
        assert posterior > 0.50
        assert posterior >= 0.85

    def test_bayesian_scorer_decreases_probability_on_refuting_evidence(self):
        scorer = BayesianHypothesisScorer()
        hyp = TrackedHypothesis(
            title="Potential SQLi",
            vuln_type="SQLi",
            target_node_id="ep2",
            target_endpoint="/search",
            prior_probability=0.50
        )

        refute_ev = EvidenceItem(
            type=EvidenceType.STATUS_CODE,
            source="test",
            description="Standard 404 response",
            weight=0.80
        )

        posterior = scorer.update_probability(hyp, refute_ev, is_refuting=True)
        assert posterior < 0.50
        assert posterior <= 0.20
