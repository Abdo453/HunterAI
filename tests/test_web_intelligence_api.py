"""
Tests for Security Intelligence Web UI Endpoints & Unified Integration in FastAPI
"""
import pytest
import httpx
from ui.web.app import app


@pytest.mark.asyncio
async def test_intelligence_status_endpoint():
    transport = httpx.ASGITransport(app=app)
    prev_brain = getattr(app.state, "active_brain", None)
    try:
        app.state.active_brain = None
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            res = await client.get("/api/intelligence/status")
            assert res.status_code == 200
            data = res.json()
            assert data["status"] in {"online", "idle", "degraded"}
            assert "subsystems" in data
            assert data["subsystems"]["security_intelligence"] == "active"
            assert data["subsystems"]["autonomous_brain"] in {"idle", "offline"}

            app.state.active_brain = object()
            res_connected = await client.get("/api/intelligence/status")
            assert res_connected.status_code == 200
            data_connected = res_connected.json()
            assert data_connected["status"] == "online"
            assert data_connected["subsystems"]["autonomous_brain"] == "connected"
    finally:
        app.state.active_brain = prev_brain


@pytest.mark.asyncio
async def test_intelligence_scope_endpoint():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post("/api/intelligence/scope", json={
            "target": "target.local",
            "allowed_domains": ["target.local", "api.target.local"],
            "excluded_paths": ["/admin/delete"],
            "allow_active_tests": True
        })
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "updated"
        assert data["mode"] == "ACTIVE"
        assert data["target"] == "target.local"


@pytest.mark.asyncio
async def test_intelligence_explain_endpoint():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post("/api/intelligence/explain", json={
            "subject": "BOLA",
            "language": "ar"
        })
        assert res.status_code == 200
        data = res.json()
        assert "explanations" in data
        assert "simple" in data["explanations"]
        assert "المستوى 1" in data["explanations"]["simple"]


@pytest.mark.asyncio
async def test_intelligence_quiz_endpoints():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Start quiz
        q_res = await client.post("/api/intelligence/quiz/start", json={"topic": "bola"})
        assert q_res.status_code == 200
        quiz = q_res.json()
        assert "scenario" in quiz
        assert len(quiz["options"]) == 4

        # Evaluate answer
        eval_res = await client.post("/api/intelligence/quiz/evaluate", json={
            "quiz": quiz,
            "choice_idx": quiz.get("correct_option_index", 0)
        })
        assert eval_res.status_code == 200
        evaluation = eval_res.json()
        assert evaluation["is_correct"] is True
        assert evaluation["understanding_score"] >= 0.0

