"""
Smoke Tests for New Web API Endpoints (Engines + Run Control + Budget)
Tests: كل endpoint جديد يردّ دون 5xx ويملك الشكل المتوقّع.
الغرض: منع تسرّب أخطاء مثل NameError في مسارات الـ API غير المغطاة.
"""
import pytest
import httpx

from ui.web.app import app


@pytest.mark.asyncio
async def test_engines_list_endpoint():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test"
    ) as client:
        res = await client.get("/api/engines")
        assert res.status_code == 200
        data = res.json()
        assert "engines" in data
        names = {e["engine"] for e in data["engines"]}
        assert {"claude", "codex", "opencode"} <= names


@pytest.mark.asyncio
async def test_engines_selfcheck_endpoint():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test"
    ) as client:
        res = await client.post("/api/engines/selfcheck", json={"engines": []})
        assert res.status_code == 200
        data = res.json()
        assert "results" in data
        assert "healthy_count" in data


@pytest.mark.asyncio
async def test_engines_run_requires_body():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test"
    ) as client:
        # بدون حمولة ⇒ 422 (validation) — لا يُنفَّذ أي تشغيل
        res = await client.post("/api/engines/run")
        assert res.status_code == 422


@pytest.mark.asyncio
async def test_runs_list_endpoint():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test"
    ) as client:
        res = await client.get("/api/runs")
        assert res.status_code == 200
        assert isinstance(res.json(), (list, dict))


@pytest.mark.asyncio
async def test_budget_get_endpoint():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test"
    ) as client:
        res = await client.get("/api/budget")
        assert res.status_code == 200
        assert isinstance(res.json(), dict)


@pytest.mark.asyncio
async def test_budget_update_endpoint():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test"
    ) as client:
        res = await client.post(
            "/api/budget", json={"per_run_usd": 5.0, "per_day_usd": 20.0}
        )
        assert res.status_code == 200
