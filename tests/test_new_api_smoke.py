"""
Smoke Tests for New Web API Endpoints (Engines + Run Control + Budget)
Tests: كل endpoint جديد يردّ دون 5xx ويملك الشكل المتوقّع.
الغرض: منع تسرّب أخطاء مثل NameError في مسارات الـ API غير المغطاة.
"""
import pytest
import httpx

from hunter_backend.testing import make_async_client


@pytest.mark.asyncio
async def test_engines_list_endpoint():
    async with make_async_client() as client:
        res = await client.get("/api/engines")
        assert res.status_code == 200
        data = res.json()
        assert "engines" in data
        names = {e["engine"] for e in data["engines"]}
        assert {"claude", "codex", "opencode"} <= names


@pytest.mark.asyncio
async def test_engines_selfcheck_endpoint():
    async with make_async_client() as client:
        res = await client.post("/api/engines/selfcheck", json={"engines": []})
        assert res.status_code == 200
        data = res.json()
        assert "results" in data
        assert "healthy_count" in data


@pytest.mark.asyncio
async def test_engines_run_requires_body():
    async with make_async_client() as client:
        # empty payload -> 422 (validation)
        res = await client.post("/api/engines/run", json={})
        assert res.status_code == 422


@pytest.mark.asyncio
async def test_runs_list_endpoint():
    async with make_async_client() as client:
        res = await client.get("/api/runs")
        assert res.status_code == 200
        assert isinstance(res.json(), (list, dict))


@pytest.mark.asyncio
async def test_budget_get_endpoint():
    async with make_async_client() as client:
        res = await client.get("/api/budget")
        assert res.status_code == 200
        assert isinstance(res.json(), dict)


@pytest.mark.asyncio
async def test_budget_update_endpoint():
    async with make_async_client() as client:
        res = await client.post(
            "/api/budget", json={"per_run_usd": 5.0, "per_day_usd": 20.0}
        )
        assert res.status_code == 200
