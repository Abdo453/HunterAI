"""Tests for ReconAgent"""
import sys
import os
import asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.recon_agent import ReconAgent
from agents.base_agent import AgentTask
from tools.tool_manager import ToolManager


def test_recon_agent_run(monkeypatch):
    """يُنفّذ ReconAgent بدون أدوات خارجية مثبتة → يُعيد نتيجة ناجحة وقائمة نتائج."""
    from core.ai_reasoning_core import AIReasoningCore

    mgr = ToolManager()
    # Explicitly simulate no external CLI tools installed (hermetic even on hosts with nmap/httpx).
    monkeypatch.setattr(mgr, "is_available", lambda _tool: False)
    # Prevent live Ollama/LLM network timeout inside AIReasoningCore during offline unit test.
    async def _mock_surface(*args, **kwargs):
        return None
    monkeypatch.setattr(AIReasoningCore, "analyze_recon_surface", staticmethod(_mock_surface))
    agent = ReconAgent(mgr)
    task = AgentTask(target="abdo123", extra={"username": "abdo123", "vectors": ["username"], "max_platforms": 60})
    res = asyncio.run(agent.run(task))

    assert res.success is True
    assert res.agent_name == "recon_agent"
    assert isinstance(res.findings, list)
    print("[PASS] recon agent run")