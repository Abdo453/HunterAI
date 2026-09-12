"""
Integration Tests for AutonomousBrain with SecurityState and Web API /api/intelligence/state
"""
import pytest
from unittest.mock import AsyncMock, MagicMock
import httpx

from core.brain.autonomous_brain import AutonomousBrain
from ui.web.app import app


@pytest.mark.asyncio
async def test_autonomous_brain_initializes_and_populates_security_state():
    """Test that AutonomousBrain creates and enriches SecurityState during OODA scan"""
    rm = MagicMock()
    tm = MagicMock()
    tm.is_available.return_value = True
    brain = AutonomousBrain(resource_manager=rm, tool_manager=tm, dry_run=True)

    # Mock fetch and burp check
    mock_html = """
    <html>
        <body>
            <a href="/api/v1/users/10">User Profile</a>
            <a href="/api/v1/settings">Settings</a>
            <form action="/login" method="POST">
                <input name="user_id" />
                <input name="password" type="password" />
            </form>
        </body>
    </html>
    """
    brain._fetch_target = AsyncMock(return_value=(mock_html, 200, {"server": "uvicorn", "x-powered-by": "FastAPI"}))
    brain._check_burp_online = AsyncMock(return_value=True)

    # Run scan
    res = await brain.run_scan(target="https://api.testapp.local")

    assert "security_state" in res
    snap = res["security_state"]
    assert snap is not None
    assert snap["target"] == "https://api.testapp.local"
    assert "api.testapp.local" in snap["assets"]

    # Endpoints should be discovered and populated
    endpoints = snap["endpoints"]
    assert any("/api/v1/users/10" in ep for ep in endpoints) or any("/login" in ep for ep in endpoints)

    # Unknowns should be populated from SecurityIntelligence hypotheses
    assert len(snap["unknowns"]) > 0
    assert any("BOLA" in unk or "vulnerable" in unk for unk in snap["unknowns"])


@pytest.mark.asyncio
async def test_web_intelligence_state_api_endpoint():
    """Test GET /api/intelligence/state endpoint"""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/intelligence/state")
        assert res.status_code == 200
        data = res.json()
        assert "target" in data
        assert "summary" in data
        assert "assets_count" in data["summary"]
        assert "vulnerabilities_count" in data["summary"]
        assert "status_breakdown" in data["summary"]
        assert "OBSERVED" in data["summary"]["status_breakdown"]
        assert "CONFIRMED" in data["summary"]["status_breakdown"]
