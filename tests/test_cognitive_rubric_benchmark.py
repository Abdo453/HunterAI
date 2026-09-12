"""
Test Suite for Cognitive Rubric & Reasoning Benchmark (100 Points)
"""
from __future__ import annotations

import pytest
from core.benchmark.cognitive_rubric_evaluator import CognitiveRubricEvaluator, CognitiveRubricReport


def test_cognitive_rubric_full_scorecard():
    evaluator = CognitiveRubricEvaluator()
    report: CognitiveRubricReport = evaluator.run_full_rubric_evaluation()

    print("\n" + report.to_markdown())

    assert len(report.criteria) == 9
    for crit in report.criteria:
        assert crit.passed is True, f"Failed criterion: {crit.category} ({crit.notes})"
        assert crit.awarded == crit.weight

    assert report.total_score == 100.0
    assert "Grade A+" in report.grade
