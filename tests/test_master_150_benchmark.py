"""
Test Suite for HunterAI 150-Point Master Cognitive & Autonomous Benchmark
"""
from __future__ import annotations

import pytest
from core.benchmark.master_150_benchmark import Master150BenchmarkRunner, MasterBenchmarkReport


def test_master_150_benchmark_execution():
    runner = Master150BenchmarkRunner()
    report: MasterBenchmarkReport = runner.run_master_benchmark()

    # Print markdown report for verification
    print("\n" + report.to_markdown())

    # Assert all 17 dimensions executed and passed
    assert len(report.dimensions) == 17
    for dim in report.dimensions:
        assert dim.passed is True, f"Dimension {dim.index} ({dim.name}) failed: {dim.notes}"
        assert dim.awarded == dim.weight

    # Assert perfect score 150.0 / 150.0 (Grade A+)
    assert report.total_score == 150.0
    assert "Grade A+" in report.grade
    assert report.verdict != ""
