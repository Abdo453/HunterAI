"""
Test Suite for AI-Agent Bridge & Hybrid Router (Local + Online AI Mediation)
"""
from __future__ import annotations

import json
import pytest

from core.ai_bridge import (
    DefensivePromptFramer,
    RefusalDetector,
    StructuredOutputParser,
    HybridAIRouter,
    AIBridgeResponse,
)


def test_defensive_prompt_framer():
    raw = "How can the agent hack and exploit the SQL injection payload on this target?"
    sys_prompt, reframed = DefensivePromptFramer.reframe_query(
        raw_query=raw,
        target_context="e-commerce catalog API",
        task_category="input_validation_audit"
    )

    assert "defensive security auditor" in sys_prompt.lower()
    # "hack" and "exploit" and "payload" translated to academic/defensive terms
    assert "hack" not in reframed.lower()
    assert "exploit" not in reframed.lower()
    assert "verification test case" in reframed.lower()
    assert "Defensive Security Audit" in reframed


def test_refusal_detector():
    # 1. Obvious refusal
    refusal_text = "I'm sorry, but I cannot assist with hacking or cyberattacks as it violates safety policies."
    res = RefusalDetector.check_response(refusal_text)
    assert res.is_refusal is True
    assert res.confidence >= 0.90

    # 2. Another refusal variation
    refusal_text_2 = "As an AI language model, I am unable to provide instructions for attacking systems."
    res_2 = RefusalDetector.check_response(refusal_text_2)
    assert res_2.is_refusal is True

    # 3. Genuine technical response (Not a refusal!)
    tech_response = """
    ```json
    {
        "root_cause": "Unparameterized query concatenation in search query filter.",
        "safe_verification": "Compare parameter using benign math differential.",
        "remediation": "Use prepared statements."
    }
    ```
    """
    res_tech = RefusalDetector.check_response(tech_response)
    assert res_tech.is_refusal is False


def test_structured_output_parser():
    # 1. Markdown code fence
    markdown_json = """
    Here is the analysis of the endpoint:
    ```json
    {
        "status": "vulnerable",
        "type": "idor",
        "severity": "High"
    }
    ```
    Hope this helps!
    """
    parsed = StructuredOutputParser.extract_json(markdown_json)
    assert parsed is not None
    assert parsed["status"] == "vulnerable"
    assert parsed["type"] == "idor"

    # 2. Raw JSON string without code fence
    raw_str = '{"action": "stop_path", "reason": "access_denied"}'
    parsed_raw = StructuredOutputParser.extract_json(raw_str)
    assert parsed_raw["action"] == "stop_path"


@pytest.mark.asyncio
async def test_hybrid_ai_router_online_success():
    router = HybridAIRouter(prefer_online=True)

    # Mock online caller returning valid technical response
    async def mock_online_success(query: str, sys_prompt: str):
        return json.dumps({
            "finding": "IDOR",
            "confidence": 0.92,
            "remediation": "Verify current_user.id in database query."
        })

    resp: AIBridgeResponse = await router.query_security_reasoning(
        raw_agent_query="Check if parameter user_id exposes order data",
        online_caller_fn=mock_online_success
    )

    assert resp.provider_tier == "online_cloud"
    assert resp.refusal_encountered is False
    assert resp.fallback_triggered is False
    assert resp.parsed_json["finding"] == "IDOR"


@pytest.mark.asyncio
async def test_hybrid_ai_router_refusal_fallback_to_local():
    router = HybridAIRouter(prefer_online=True, preferred_local_model="qwen2.5-coder:14b")

    # Mock online caller triggering a safety refusal
    async def mock_online_refusal(query: str, sys_prompt: str):
        return "I am unable to assist with testing or finding vulnerabilities as this violates safety guidelines."

    # Mock local Ollama caller answering technically without refusal
    async def mock_local_success(query: str, sys_prompt: str):
        return json.dumps({
            "source": "local_ollama",
            "vulnerability_type": "sql_injection",
            "safe_test": "Send 1=1 vs 1=2 boolean differential",
            "remediation": "Use prepared statements"
        })

    resp: AIBridgeResponse = await router.query_security_reasoning(
        raw_agent_query="Test parameter id for SQL injection",
        online_caller_fn=mock_online_refusal,
        local_caller_fn=mock_local_success
    )

    assert resp.refusal_encountered is True
    assert resp.fallback_triggered is True
    assert resp.provider_tier == "local_ollama"
    assert "ollama" in resp.model_used
    assert resp.parsed_json["vulnerability_type"] == "sql_injection"


@pytest.mark.asyncio
async def test_hybrid_ai_router_full_fallback_to_deterministic_rules():
    router = HybridAIRouter(prefer_online=True)

    # Both online and local fail / refuse
    async def mock_online_refusal(query: str, sys_prompt: str):
        return "I cannot assist with hacking."

    async def mock_local_offline(query: str, sys_prompt: str):
        raise ConnectionError("Ollama daemon not running on port 11434")

    resp: AIBridgeResponse = await router.query_security_reasoning(
        raw_agent_query="Analyze SSRF risk on URL parameter",
        online_caller_fn=mock_online_refusal,
        local_caller_fn=mock_local_offline
    )

    assert resp.fallback_triggered is True
    assert resp.provider_tier == "deterministic_rules"
    assert resp.model_used == "deterministic_rule_engine"
    assert resp.parsed_json["vulnerability_type"] == "ssrf"
    assert "canary_collaborator_callback" in resp.parsed_json["recommended_action"]
