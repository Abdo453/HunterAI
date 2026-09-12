"""
Unit Tests for Confidence Calibration and Failure Recovery Engine
Tests: Expected Calibration Error (ECE) measurement, hypothesis refutation detection, and abductive recovery.
"""
import pytest

from core.learning.calibration_recovery import ConfidenceCalibrationTracker, FailureRecoveryEngine


class TestCalibrationAndFailureRecovery:
    def test_calibration_tracker_computes_ece(self):
        tracker = ConfidenceCalibrationTracker(num_bins=5)

        # Record well-calibrated predictions:
        # High confidence (0.90) that are indeed correct
        for _ in range(9):
            tracker.record_prediction(confidence=0.90, actual_correct=True)
        tracker.record_prediction(confidence=0.90, actual_correct=False)

        # Low confidence (0.20) with low empirical truth
        tracker.record_prediction(confidence=0.20, actual_correct=False)
        tracker.record_prediction(confidence=0.20, actual_correct=False)

        ece = tracker.compute_ece()
        assert ece >= 0.0
        assert ece <= 0.20  # Well calibrated

    def test_failure_recovery_triggers_when_hypothesis_collapses(self):
        # Hypothesis collapses from prior 0.70 to posterior 0.10
        decision = FailureRecoveryEngine.handle_refutation(
            refuted_hypothesis="SQLi_Injected_Where",
            prior_probability=0.70,
            current_probability=0.10,
            observed_signals=["query_echo", "403_waf_block"]
        )

        assert decision is not None
        assert decision.action_taken == "DISCARD_AND_PIVOT"
        assert decision.refuted_hypothesis == "SQLi_Injected_Where"
        assert len(decision.alternative_hypotheses) >= 2
        assert "Safe_Parameterized_Query" in decision.alternative_hypotheses

    def test_failure_recovery_does_not_trigger_when_hypothesis_remains_viable(self):
        decision = FailureRecoveryEngine.handle_refutation(
            refuted_hypothesis="SQLi_Injected_Where",
            prior_probability=0.70,
            current_probability=0.45,  # Still viable
            observed_signals=["query_echo"]
        )
        assert decision is None
