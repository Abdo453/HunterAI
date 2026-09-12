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
    assert len(targets) == 8

    # Verify all targets have valid schemas
    categories = [t.category for t in targets]
    assert "Remote Code Execution" in categories
    assert "SQL Injection" in categories
    assert "Broken Object Level Authorization" in categories
    assert "Server-Side Request Forgery" in categories
    assert "Server-Side Template Injection" in categories
    assert "Cross-Site Scripting" in categories
    assert "Broken Authentication" in categories
    assert "Safe Negative Control" in categories


def test_validation_arena_benchmark_execution():
    scorecard = ArenaEvaluator.run_all()

    # Core Metric Assertions
    assert scorecard.total_targets == 8
    assert scorecard.true_positives == 7
    assert scorecard.true_negatives == 1
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
    fp_trap = targets["LAB-BENIGN-08"]

    res = ArenaEvaluator.evaluate_target(fp_trap)
    assert res.is_true_negative is True
    assert res.is_false_positive is False
    assert res.court_verdict in ("REFUTED", "UNPROVEN", "UNVERIFIED", "FALSE_POSITIVE")
    assert res.proof_verified is False
