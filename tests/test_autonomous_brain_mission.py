"""
Integration Tests for AutonomousBrain Mission Execution and Web API /api/planner/mission
"""
import pytest
from unittest.mock import AsyncMock, MagicMock
import httpx

from core.brain.autonomous_brain import AutonomousBrain
from core.planner.schemas import SecurityGoal, GoalType
from ui.web.app import app


@pytest.mark.asyncio
async def test_autonomous_brain_run_mission():
    """Test that AutonomousBrain can execute a mission using StateSpacePlanner"""
    rm = MagicMock()
    tm = MagicMock()
    tm.is_available.return_value = True

    brain = AutonomousBrain(resource_manager=rm, tool_manager=tm, dry_run=True)

    goal = SecurityGoal(
        title="Discover Surface and Check Isolation",
        goal_type=GoalType.DATA_ISOLATION_CHECK,
        target="api.testapp.local"
    )

    report = await brain.run_mission(goal, max_steps=4)
    assert report.target == "api.testapp.local"
    assert report.steps_taken > 0
    assert report.goal_title == "Discover Surface and Check Isolation"


@pytest.mark.asyncio
async def test_rest_api_planner_mission_endpoint():
    """Test POST /api/planner/mission endpoint"""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "title": "Autonomous BOLA Audit",
            "goal_type": "DATA_ISOLATION_CHECK",
            "target": "target.local",
            "max_steps": 3
        }
        res = await client.post("/api/planner/mission", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert "goal_id" in data
        assert "achieved" in data
        assert "steps_taken" in data
        assert "state_snapshot" in data
        assert "execution_steps" in data
