"""
Integration Tests for Attack Graph & Multi-Agent Specialists in AutonomousBrain and Web API
"""
import pytest
from unittest.mock import MagicMock
import httpx

from core.brain.autonomous_brain import AutonomousBrain
from hunter_backend.asgi import application


def test_autonomous_brain_attack_graph_attached():
    rm = MagicMock()
    tm = MagicMock()
    tm.is_available.return_value = True

    brain = AutonomousBrain(resource_manager=rm, tool_manager=tm, dry_run=True)
    assert brain.attack_graph is not None
    assert brain.lead_analyst is not None


@pytest.mark.asyncio
async def test_rest_api_attack_graph_snapshot():
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as client:
        res = await client.get("/api/attack_graph/snapshot")
        assert res.status_code == 200
        data = res.json()
        assert "target" in data
        assert "summary" in data
        assert isinstance(data["nodes"], list)
        assert isinstance(data["edges"], list)
        assert data["summary"]["nodes_count"] == len(data["nodes"])
        assert data["summary"]["edges_count"] == len(data["edges"])


@pytest.mark.asyncio
async def test_rest_api_attack_graph_snapshot_normalizes_dict_nodes_and_edges(monkeypatch):
    import core.reasoning.attack_surface_graph as asg

    orig_init = asg.AttackSurfaceGraph.__init__

    def _populated_init(self, target_domain="target.local"):
        orig_init(self, target_domain=target_domain)
        self.add_node(
            asg.SurfaceNode(
                node_id="ep_1",
                node_type="ENDPOINT",
                name="/api/item",
                epistemic_status=asg.EpistemicStatus.OBSERVED,
            )
        )
        self.add_edge(
            asg.SurfaceEdge(
                edge_id="edge_1",
                source_node_id="ep_1",
                target_node_id="ep_1",
                relation_type="TRANSITION",
                epistemic_status=asg.EpistemicStatus.CANDIDATE,
            )
        )

    monkeypatch.setattr(asg.AttackSurfaceGraph, "__init__", _populated_init)

    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as client:
        res = await client.get("/api/attack_graph/snapshot")
        assert res.status_code == 200
        data = res.json()
        assert isinstance(data["nodes"], list) and len(data["nodes"]) == 1
        assert isinstance(data["edges"], list) and len(data["edges"]) == 1
        assert data["nodes"][0]["node_id"] == "ep_1"
        assert data["edges"][0]["edge_id"] == "edge_1"
        assert data["summary"] == {"nodes_count": 1, "edges_count": 1}


@pytest.mark.asyncio
async def test_rest_api_multi_agent_analyze():
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as client:
        payload = {"target": "testcorp.local"}
        res = await client.post("/api/multi_agent/analyze", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["target"] == "testcorp.local"
        assert data["status"] == "COMPLETED"
        assert "graph_summary" in data
        assert "blast_radius" in data
        assert "investigation_trace" in data
