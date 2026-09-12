"""
Tests for AI Startup Diagnostics Engine
"""
import pytest
from core.ai_diagnostics import check_local_ai_status, check_cloud_ai_status, run_full_ai_diagnostics, run_startup_ai_diagnostic
from starlette.testclient import TestClient
from ui.web.app import app


@pytest.mark.asyncio
async def test_check_local_ai_status_structure():
    stat = await check_local_ai_status()
    assert "online" in stat
    assert "host" in stat
    assert "installed_tags" in stat
    assert "models" in stat
    assert "WhiteRabbitNeo" in stat["models"]
    assert "xploiter" in stat["models"]
    assert "qwen_coder" in stat["models"]
    assert "sylink" in stat["models"]


def test_check_cloud_ai_status_structure():
    stat = check_cloud_ai_status()
    assert "openrouter" in stat
    assert "gemini" in stat
    assert "taskade" in stat
    assert "openrouter" in stat and "configured" in stat["openrouter"]


@pytest.mark.asyncio
async def test_run_full_ai_diagnostics():
    res = await run_full_ai_diagnostics(verbose=False)
    assert "local" in res
    assert "cloud" in res
    assert "ready" in res


def test_run_startup_ai_diagnostic_sync():
    res = run_startup_ai_diagnostic(verbose=False)
    assert "ready" in res or "error" in res


def test_api_ai_diagnostics_endpoint():
    client = TestClient(app)
    r = client.get("/api/ai/diagnostics")
    assert r.status_code == 200
    data = r.json()
    assert "local" in data
    assert "cloud" in data
    assert "ready" in data
