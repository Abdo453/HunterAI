"""
Integration Tests for Attack Graph & Multi-Agent Specialists in AutonomousBrain and Web API
"""
import pytest
from unittest.mock import MagicMock
import httpx

from core.brain.autonomous_brain import AutonomousBrain
from ui.web.app import app


def test_autonomous_brain_attack_graph_attached():
    rm = MagicMock()
    tm = MagicMock()
    tm.is_available.return_value = True

    brain = AutonomousBrain(resource_manager=rm, tool_manager=tm, dry_run=True)
    assert brain.attack_graph is not None
    assert brain.lead_analyst is not None


@pytest.mark.asyncio
async def test_rest_api_attack_graph_snapshot():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/attack_graph/snapshot")
        assert res.status_code == 200
        data = res.json()
        assert "target" in data
        assert "summary" in data
        assert "nodes" in data
        assert "edges" in data


@pytest.mark.asyncio
async def test_rest_api_multi_agent_analyze():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {"target": "testcorp.local"}
        res = await client.post("/api/multi_agent/analyze", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["target"] == "testcorp.local"
        assert data["status"] == "COMPLETED"
        assert "graph_summary" in data
        assert "blast_radius" in data
        assert "investigation_trace" in data
