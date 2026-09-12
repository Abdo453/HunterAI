"""
Integration Tests for Evaluation Benchmark Framework and REST APIs
Tests: BOLAMultiTenantScenario, BlindSQLiScenario, Scorecard generation, and Web endpoints.
"""
import pytest
import httpx

from evaluation.benchmark_runner import BenchmarkRunner
from evaluation.scenarios.bola_scenario import BOLAMultiTenantScenario
from evaluation.scenarios.sqli_scenario import BlindSQLiScenario
from ui.web.app import app


class TestEvaluationBenchmark:
    def test_bola_multi_tenant_benchmark_execution(self):
        runner = BenchmarkRunner()
        scenario = BOLAMultiTenantScenario()
        scorecard = runner.run_scenario(scenario, max_steps=4)

        assert scorecard.scenario_name == "BOLA_MultiTenant_Enterprise"
        assert scorecard.goal_achieved is True
        assert scorecard.false_positive_rate_pct == 0.0  # Zero false positives
        assert scorecard.step_efficiency_pct >= 60.0
        assert scorecard.overall_reasoning_score >= 70.0

        # Print terminal report for inspection
        report_str = scorecard.format_terminal_report()
        assert "HunterAI Reasoning Benchmark Scorecard" in report_str
        assert "Goal Achieved:            ✅ YES" in report_str

    def test_sqli_benchmark_execution(self):
        runner = BenchmarkRunner()
        scenario = BlindSQLiScenario()
        scorecard = runner.run_scenario(scenario, max_steps=3)

        assert scorecard.category == "SQLi"
        assert scorecard.goal_achieved is True
        assert scorecard.false_positive_rate_pct == 0.0
        assert scorecard.overall_reasoning_score >= 75.0

    @pytest.mark.asyncio
    async def test_rest_api_reasoning_investigate(self):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            payload = {"target": "target.enterprise.local"}
            res = await client.post("/api/reasoning/investigate", json=payload)
            assert res.status_code == 200
            data = res.json()
            assert "investigation_id" in data
            assert "step_result" in data
            assert "latest_snapshot" in data

    @pytest.mark.asyncio
    async def test_rest_api_evaluation_benchmark(self):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            res = await client.get("/api/evaluation/benchmark")
            assert res.status_code == 200
            data = res.json()
            assert "scorecards" in data
            assert len(data["scorecards"]) >= 2
            assert data["summary"]["zero_false_positives"] is True
            assert data["summary"]["mean_score"] >= 70.0
