"""
Unit Test Suite for HunterAI Validation Arena
=============================================
Tests benchmark evaluation, precision/recall calculations, proof-of-execution verification,
and strict false positive suppression on negative controls.
"""
from core.arena.arena_targets import get_all_arena_targets
from core.arena.arena_evaluator import ArenaEvaluator


def test_arena_ground_truth_catalog():
    targets = get_all_arena_targets()
    assert len(targets) == 12

    # Verify all targets have valid schemas
    categories = [t.category for t in targets]
    assert "Remote Code Execution" in categories
    assert "SQL Injection" in categories
    assert "Broken Object Level Authorization" in categories
    assert "Server-Side Request Forgery" in categories
    assert "Server-Side Template Injection" in categories
    assert "Cross-Site Scripting" in categories
    assert "Broken Authentication" in categories
    assert "Unrestricted File Upload" in categories
    assert "Safe Negative Control" in categories


def test_validation_arena_benchmark_execution():
    scorecard = ArenaEvaluator.run_all()

    # Core Metric Assertions across all 12 standardized ground-truth targets
    assert scorecard.total_targets == 12
    assert scorecard.true_positives == 10
    assert scorecard.true_negatives == 2
    assert scorecard.false_positives == 0, "FATAL: False Positive detected in Validation Arena!"
    assert scorecard.false_negatives == 0, "Target missed by Reasoning Agent!"

    # Quantitative Rate Assertions
    assert scorecard.detection_rate_pct == 100.0
    assert scorecard.precision_pct == 100.0
    assert scorecard.false_positive_rate_pct == 0.0
    assert scorecard.proof_success_rate_pct == 100.0
    assert scorecard.provenance_completeness_pct == 100.0


def test_false_positive_trap_suppression():
    targets = {t.target_id: t for t in get_all_arena_targets()}

    # Trap 1: HTML encoded profile with unhandled 500 error
    fp_trap_1 = targets["LAB-BENIGN-11"]
    res1 = ArenaEvaluator.evaluate_target(fp_trap_1)
    assert res1.is_true_negative is True
    assert res1.is_false_positive is False
    assert res1.court_verdict in ("REFUTED", "UNPROVEN", "UNVERIFIED", "FALSE_POSITIVE")
    assert res1.proof_verified is False

    # Trap 2: Strict regex query filter with 400 Bad Request
    fp_trap_2 = targets["LAB-BENIGN-12"]
    res2 = ArenaEvaluator.evaluate_target(fp_trap_2)
    assert res2.is_true_negative is True
    assert res2.is_false_positive is False
    assert res2.court_verdict in ("REFUTED", "UNPROVEN", "UNVERIFIED", "FALSE_POSITIVE")
    assert res2.proof_verified is False


def test_network_scope_guard_egress_firewall():
    import pytest
    from core.network_scope_guard import NetworkScopeGuard, ScopeViolationError
    from core.scope_engine import ScopePolicy

    policy = ScopePolicy(
        allowed_targets=["shop.lab.local", "health.lab.local"],
        allow_private_ips_override=False,
        excluded_paths=["/admin/secret"]
    )
    guard = NetworkScopeGuard(policy)

    # In-scope URL allowed
    allowed, _ = guard.check_url("https://shop.lab.local/api/products")
    assert allowed is True
    guard.assert_allowed("https://shop.lab.local/api/products")

    # Out-of-scope domain blocked
    allowed, reason = guard.check_url("https://evil-hacker.com/steal")
    assert allowed is False
    assert "outside authorized scope" in reason

    with pytest.raises(ScopeViolationError) as exc_info:
        guard.assert_allowed("https://evil-hacker.com/steal", caller_context="test_agent")
    assert "evil-hacker.com" in str(exc_info.value)
    assert len(guard.blocked_audit_log) == 1
    assert guard.blocked_audit_log[0]["event_type"] == "NETWORK_EGRESS_BLOCKED"

    # Cloud metadata blocked
    with pytest.raises(ScopeViolationError):
        guard.assert_allowed("http://169.254.169.254/latest/meta-data/")


def test_regression_tracker_comparison():
    import tempfile
    from pathlib import Path
    from core.arena.regression_tracker import RegressionTracker

    scorecard = ArenaEvaluator.run_all()
    with tempfile.TemporaryDirectory() as tmpdir:
        history_path = Path(tmpdir) / "history.json"
        tracker = RegressionTracker(history_path)

        # Baseline comparison
        comp = tracker.compare_with_baseline(scorecard, current_version="v2.0-arena")
        assert comp.current_detection_rate == 100.0
        assert comp.current_fpr == 0.0
        assert comp.regression_detected is False

        # Record run
        tracker.record_run(scorecard, version_tag="v2.0-arena")
        assert len(tracker.history) == 1

