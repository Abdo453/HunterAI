"""Tests for ReconAgent"""
import sys
import os
import asyncio
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.recon_agent import ReconAgent
from agents.base_agent import AgentTask
from tools.tool_manager import ToolManager
from core.osint.tool_manager import ToolManager
from agents.recon_agent import ReconAgent

async def test_recon_agent_run():
    agent = ReconAgent(mgr)
    task = AgentTask(target="abdo123", extra={"username": "abdo123", "vectors": ["username"], "max_platforms": 60})
    res = asyncio.run(agent.run(task))
    
    assert res.success is True
    assert len(res.findings) == 1
    finding = res.findings[0]
    assert finding["cluster_id"] == clusters[0].cluster_id  # BUG: clusters not defined
    assert finding["anchor"] == "abdo123"
    assert finding["confidence"] == 0.75
    assert finding["confidence_label"] == "strong"
    assert finding["members"][0]["confidence_label"] == "strong"
    assert finding["members"][0]["context"]["is_administration"] is True
    print("[PASS] recon agent run")