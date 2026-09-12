"""
Unit & Mathematical Property Tests for BeliefState and UncertaintyModel
Tests: Versioning, Immutable history replay, Shannon entropy bounds (0 <= H <= log2 N), and normalization.
"""
import math
import pytest

from core.reasoning.belief_state import BeliefState
from core.reasoning.uncertainty import UncertaintyModel


class TestBeliefStateAndUncertainty:
    """Test append-only versioned belief tracking and mathematical uncertainty bounds"""

    def test_belief_state_versioning_and_immutability(self):
        belief = BeliefState(investigation_id="INV-TEST-001")
        assert belief.version == 0
        assert len(belief.history) == 1  # v0 baseline snapshot

        # Update hypotheses -> version increments to 1
        belief.set_hypotheses({"BOLA": 0.6, "Public": 0.4}, justification="First update")
        assert belief.version == 1
        assert len(belief.history) == 2

        # Add fact -> version increments to 2
        belief.add_fact("Endpoint /api/v1/invoices/100 exists", justification="Crawl fact")
        assert belief.version == 2
        assert len(belief.history) == 3

        # Test historical replay
        snap_v0 = belief.replay(version=0)
        snap_v1 = belief.replay(version=1)
        snap_v2 = belief.replay(version=2)

        assert snap_v0 is not None and snap_v0.version == 0
        assert snap_v0.hypotheses == {}

        assert snap_v1 is not None and snap_v1.version == 1
        assert snap_v1.hypotheses == {"BOLA": 0.6, "Public": 0.4}
        assert snap_v1.facts == []

        assert snap_v2 is not None and snap_v2.version == 2
        assert "Endpoint /api/v1/invoices/100 exists" in snap_v2.facts

    def test_belief_state_strict_normalization(self):
        belief = BeliefState()
        # Unnormalized input
        belief.set_hypotheses({"H1": 3.0, "H2": 7.0})
        assert sum(belief.hypotheses.values()) == pytest.approx(1.0, abs=1e-3)
        assert belief.hypotheses["H1"] == 0.3
        assert belief.hypotheses["H2"] == 0.7

    def test_shannon_entropy_mathematical_invariants(self):
        # 1. Zero entropy for certain belief (1 hypothesis with P=1.0)
        h_certain = UncertaintyModel.compute_entropy({"H1": 1.0, "H2": 0.0})
        assert h_certain == 0.0

        # 2. Maximum entropy for uniform distribution over N items = log2(N)
        n = 4
        uniform_dist = {f"H{i}": 1.0 / n for i in range(n)}
        h_uniform = UncertaintyModel.compute_entropy(uniform_dist)
        expected_h = math.log2(n)  # log2(4) = 2.0 bits
        assert h_uniform == pytest.approx(expected_h, abs=1e-3)

        # 3. Normalized entropy is exactly 1.0 for uniform and 0.0 for certain
        norm_uniform = UncertaintyModel.compute_normalized_entropy(uniform_dist)
        assert norm_uniform == pytest.approx(1.0, abs=1e-3)

        norm_certain = UncertaintyModel.compute_normalized_entropy({"H1": 1.0})
        assert norm_certain == 0.0

        # 4. Entropy delta reflects information gain
        prior = {"H1": 0.5, "H2": 0.5}  # H = 1.0 bit
        post = {"H1": 0.9, "H2": 0.1}   # H ~ 0.469 bits
        rec = UncertaintyModel.record_transition(prior, post)
        assert rec.prior_entropy == pytest.approx(1.0, abs=1e-3)
        assert rec.posterior_entropy < rec.prior_entropy
        assert rec.entropy_delta > 0.0  # Positive information gain
