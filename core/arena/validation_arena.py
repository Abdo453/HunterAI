"""Compatibility wrapper for the ground-truth validation arena."""
from __future__ import annotations

from dataclasses import dataclass

from core.arena.arena_evaluator import ArenaEvaluator, ArenaScorecard


@dataclass(frozen=True)
class ValidationArenaResult:
    passed: int
    total: int
    fpr_percentage: float
    scorecard: ArenaScorecard


class ValidationArena:
    def run_suite(self) -> ValidationArenaResult:
        scorecard = ArenaEvaluator.run_all()
        return ValidationArenaResult(
            passed=scorecard.true_positives + scorecard.true_negatives,
            total=scorecard.total_targets,
            fpr_percentage=scorecard.false_positive_rate_pct,
            scorecard=scorecard,
        )
