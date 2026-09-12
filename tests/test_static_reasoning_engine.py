"""
Tests for Static Security Reasoning Engine & Agent
"""
import pytest
from unittest.mock import patch, AsyncMock
from starlette.testclient import TestClient

from core.static_reasoning_engine import StaticSecurityReasoningEngine, StaticFinding, ReasoningMemoryItem
from agents.static_reasoning_agent import StaticSecurityReasoningAgent
from agents.base_agent import AgentTask
from ui.web.app import app

MOCK_REASONING_JSON = """[
  {
    "finding": "Insecure Base URL and Potential SSRF",
    "classification": "POSSIBLE",
    "source_location": "TimoGuildExecutor.py:28",
    "evidence": "self.base_url = str(base_url or TIMO_DEFAULT_API_BASE_URL).strip()",
    "data_flow": "Input base_url -> self.base_url -> requests.post() sink",
    "reasoning": "base_url is accepted without verifying the scheme (https://) or internal IP destinations.",
    "counter_evidence": "TIMO_DEFAULT_API_BASE_URL is hardcoded as HTTPS by default.",
    "security_impact": "Requests containing sensitive headers could be sent to untrusted servers.",
    "confidence": 78,
    "requires_runtime_validation": false,
    "static_remediation": "Enforce base_url.startswith('https://') check."
  },
  {
    "finding": "Strict Numeric Whitelist Sanitization",
    "classification": "CONFIRMED",
    "source_location": "TimoGuildExecutor.py:37",
    "evidence": "normalized_timo_id = ''.join(ch for ch in str(timo_id or '').strip() if ch.isdigit())",
    "data_flow": "Input timo_id -> isdigit() filter -> requests.post(userId)",
    "reasoning": "Numeric filter effectively neutralizes any payload injection into userId field.",
    "counter_evidence": "",
    "security_impact": "Positive defense against parameter tampering.",
    "confidence": 98,
    "requires_runtime_validation": false,
    "static_remediation": "Maintain current whitelist filtering."
  }
]"""


@pytest.mark.asyncio
async def test_static_reasoning_engine_analysis_and_memory():
    engine = StaticSecurityReasoningEngine()
    
    with patch("core.ai_reasoning_core.AIReasoningCore.ask_ai", new=AsyncMock(return_value=MOCK_REASONING_JSON)):
        result = await engine.analyze_source("class Demo: pass", target_name="DemoApp")
        
        assert result["target"] == "DemoApp"
        assert result["total_findings"] == 2
        assert len(result["findings"]) == 2
        assert len(result["reasoning_memory"]) == 2
        
        f1 = result["findings"][0]
        assert f1["finding"] == "Insecure Base URL and Potential SSRF"
        assert f1["classification"] == "POSSIBLE"
        assert f1["confidence"] == 78
        assert "requests.post()" in f1["data_flow"]
        
        mem1 = result["reasoning_memory"][0]
        assert mem1["confidence"] == 78
        assert len(mem1["evidence"]) == 2


@pytest.mark.asyncio
async def test_static_reasoning_agent_run():
    agent = StaticSecurityReasoningAgent()
    task = AgentTask(target="class MockTarget: pass", session_id="Audit-001", extra={})
    
    with patch("core.ai_reasoning_core.AIReasoningCore.ask_ai", new=AsyncMock(return_value=MOCK_REASONING_JSON)):
        agent_res = await agent.run(task)
        assert agent_res.agent_name == "StaticSecurityReasoningAgent"
        assert len(agent_res.findings) == 2
        assert agent_res.raw_output["total_findings"] == "2"


def test_api_static_audit_and_memory_endpoints():
    client = TestClient(app)
    
    with patch("core.ai_reasoning_core.AIReasoningCore.ask_ai", new=AsyncMock(return_value=MOCK_REASONING_JSON)):
        # 1. Audit Endpoint
        resp = client.post("/api/static/audit", json={
            "source_code": "class Sample: pass",
            "target_name": "SampleTarget",
            "context": "unit test"
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_findings"] == 2
        assert len(data["findings"]) == 2
        
        # 2. Memory Endpoint
        mem_resp = client.get("/api/static/memory")
        assert mem_resp.status_code == 200
        mem_data = mem_resp.json()
        assert "reasoning_memory" in mem_data
        assert len(mem_data["reasoning_memory"]) >= 2
