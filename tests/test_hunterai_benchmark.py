"""
Test Suite for HunterAI Agent Validation & Benchmark Suite (Stages 0-12)
"""
from __future__ import annotations

import asyncio
import shutil
import tempfile
from pathlib import Path

import pytest

from core.benchmark.hunterai_benchmark import HunterAIBenchmarkRunner, BenchmarkReport


@pytest.fixture
def temp_benchmark_workspace():
    tmp = tempfile.mkdtemp()
    yield Path(tmp)
    shutil.rmtree(tmp, ignore_errors=True)


@pytest.mark.asyncio
async def test_hunterai_benchmark_full_run(temp_benchmark_workspace):
    runner = HunterAIBenchmarkRunner(workspace_root=temp_benchmark_workspace)
    report: BenchmarkReport = await runner.run_full_benchmark()

    # Print markdown report for test logs
    print("\n" + report.to_markdown())

    # Assert all 13 stages (0-12) executed and passed
    assert len(report.stages) == 13
    for stage in report.stages:
        assert stage.passed is True, f"Stage {stage.stage_number} ({stage.stage_name}) failed: {stage.details}"
        assert stage.awarded_score == stage.max_score

    # Assert total score is 100/100
    assert report.total_score == 100.0
    assert "Autonomous Cognitive Agent" in report.grade
    assert report.verdict != "Unspecified"
