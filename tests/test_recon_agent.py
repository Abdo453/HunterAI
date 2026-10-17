"""Tests for ReconAgent"""
import sys
import os
import asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.recon_agent import ReconAgent
from agents.base_agent import AgentTask
from tools.tool_manager import ToolManager


def test_recon_agent_run():
    """يُنفّذ ReconAgent بدون أدوات خارجية مثبتة → يُعيد نتيجة ناجحة وقائمة نتائج."""
    mgr = ToolManager()
    agent = ReconAgent(mgr)
    task = AgentTask(target="abdo123", extra={"username": "abdo123", "vectors": ["username"], "max_platforms": 60})
    res = asyncio.run(agent.run(task))

    assert res.success is True
    assert res.agent_name == "recon_agent"
    assert isinstance(res.findings, list)
    print("[PASS] recon agent run")