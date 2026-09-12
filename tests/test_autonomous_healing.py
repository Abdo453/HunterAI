"""
Autonomous Problem-Solving & Self-Healing Engine Test Suite
===========================================================
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from core.resilience.autonomous_healing_engine import (
    FailureRootCause, HealingAction, RootCauseAnalyzer,
    JSONSelfRepairEngine, AICascadeFailover, AutonomousProblemSolver
)


class TestRootCauseAnalyzer:
    def test_detects_cloudflare_waf(self):
        rca = RootCauseAnalyzer.analyze_http_failure(
            status_code=403,
            response_text="<html><title>Access Denied | Cloudflare</title></html>",
            response_headers={"cf-ray": "123456789abcdef"}
        )
        assert rca == FailureRootCause.WAF_BLOCK_OR_CHALLENGE

    def test_detects_rate_limiting(self):
        rca = RootCauseAnalyzer.analyze_http_failure(
            status_code=429,
            response_text="Too Many Requests",
            response_headers={"Retry-After": "30"}
        )
        assert rca == FailureRootCause.RATE_LIMIT_THROTTLING

    def test_detects_session_expiration(self):
        rca = RootCauseAnalyzer.analyze_http_failure(
            status_code=302,
            response_headers={"Location": "https://target.com/login?expired=true"}
        )
        assert rca == FailureRootCause.SESSION_OR_CSRF_INVALID

    def test_detects_network_timeout(self):
        ex = TimeoutError("Connection timed out while waiting for server response")
        rca = RootCauseAnalyzer.analyze_http_failure(500, exception=ex)
        assert rca == FailureRootCause.NETWORK_OR_TIMEOUT


class TestJSONSelfRepairEngine:
    def test_strip_markdown_fences(self):
        raw = "```json\n{\"focus\": \"sqli\", \"confidence\": 0.9}\n```"
        res = JSONSelfRepairEngine.repair(raw)
        assert res is not None
        assert res["focus"] == "sqli"
        assert res["confidence"] == 0.9

    def test_repair_trailing_commas(self):
        raw = '{"tools": ["SmartPoC", "SQLiSkill",], "mode": "offensive",}'
        res = JSONSelfRepairEngine.repair(raw)
        assert res is not None
        assert len(res["tools"]) == 2
        assert res["mode"] == "offensive"

    def test_extract_outermost_json(self):
        raw = 'Here is the analysis:\n{\n  "decision": "proceed",\n  "reason": "high confidence"\n}\nHope this helps!'
        res = JSONSelfRepairEngine.repair(raw)
        assert res is not None
        assert res["decision"] == "proceed"

    def test_fallback_heuristic_parser(self):
        raw = 'unstructured text: "target_param": "id", "action": "test"'
        res = JSONSelfRepairEngine.repair(raw)
        assert res is not None
        assert res.get("target_param") == "id"


class TestAICascadeFailover:
    @pytest.mark.asyncio
    async def test_deterministic_fallback_when_tiers_fail(self):
        cascade = AICascadeFailover(ollama_url="http://127.0.0.1:99999")  # Unreachable
        res = await cascade.execute_cascade(
            prompt="Analyze target",
            deterministic_fallback=lambda: {"mode": "deterministic_safe", "plan": "SmartPoC"}
        )
        assert res["success"] is True
        assert res["provider"] == "Deterministic/RuleEngine"
        assert res["data"]["mode"] == "deterministic_safe"


class TestAutonomousProblemSolver:
    @pytest.mark.asyncio
    async def test_successful_operation_without_healing(self):
        solver = AutonomousProblemSolver()
        async def _success_task():
            return {"status": "ok", "value": 42}

        res = await solver.execute_with_healing("test_task", _success_task)
        assert res["status"] == "ok"
        assert res["value"] == 42

    @pytest.mark.asyncio
    async def test_heals_and_recovers_after_transient_failure(self):
        solver = AutonomousProblemSolver(max_retries=3)
        attempts = 0

        async def _flaky_task():
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise TimeoutError("Temporary network timeout")
            return {"status": "healed", "attempt": attempts}

        res = await solver.execute_with_healing("flaky_task", _flaky_task)
        assert res is not None
        assert res["status"] == "healed"
        assert attempts == 2
        assert len(solver.incidents) > 0
        assert solver.incidents[0].root_cause == FailureRootCause.NETWORK_OR_TIMEOUT
