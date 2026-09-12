"""
Test Suite for HunterAI Agent AI Control Plane & Intelligence Layer
"""
from __future__ import annotations

import pytest

from hunter_ai import (
    HunterTask,
    TaskLifecycleState,
    HunterAIResult,
    AgentCapability,
    AgentRegistry,
    ModelRegistry,
    ModelProfile,
    FallbackEngine,
    FailureReason,
    FallbackAction,
    ContextCompressor,
    ContextManager,
    AICritic,
    FindingValidator,
    HunterAIControlPlane,
    AIRouter
)


def test_agent_registry():
    registry = AgentRegistry()

    web_agent = registry.get_agent("WebAgent")
    assert web_agent is not None
    assert AgentCapability.WEB_ANALYSIS in web_agent.capabilities
    assert AgentCapability.JAVASCRIPT_ANALYSIS in web_agent.capabilities

    burp_agent = registry.get_agent("BurpAgent")
    assert AgentCapability.TRAFFIC_ANALYSIS in burp_agent.capabilities

    capable = registry.find_capable_agents(AgentCapability.RECONNAISSANCE)
    names = [a.agent_name for a in capable]
    assert "ReconAgent" in names


def test_context_compressor_and_manager():
    # 1. Header stripping
    headers = {
        "Host": "api.local",
        "Authorization": "Bearer token123",
        "User-Agent": "Mozilla/5.0",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive"
    }
    compressed_headers = ContextCompressor.compress_http_headers(headers)
    assert "Host" in compressed_headers
    assert "Authorization" in compressed_headers
    assert "Connection" not in compressed_headers
    assert "Accept-Encoding" not in compressed_headers

    # 2. Endpoint deduplication
    endpoints = [
        "https://app.local/api/users",
        "https://app.local/api/users?id=1",
        "https://app.local/assets/logo.png",
        "https://app.local/style.css",
        "https://app.local/api/orders"
    ]
    clean_endpoints = ContextCompressor.deduplicate_endpoints(endpoints)
    assert len(clean_endpoints) == 2
    assert "https://app.local/api/users" in clean_endpoints
    assert "https://app.local/api/orders" in clean_endpoints

    # 3. Context Manager compact task preparation
    payload = {
        "headers": headers,
        "endpoints": endpoints,
        "response_body": "A" * 5000,
        "canary_marker": "CANARY_123"
    }
    prepared = ContextManager.prepare_compact_task_context(payload, max_token_budget=2000)
    assert "Connection" not in prepared["headers"]
    assert len(prepared["endpoints"]) == 2


def test_fallback_engine_failure_classification():
    # 1. Context too large
    res_ctx = FallbackEngine.diagnose_and_resolve(
        context_tokens=40000,
        model_context_limit=32768
    )
    assert res_ctx.reason == FailureReason.CONTEXT_TOO_LARGE
    assert res_ctx.action == FallbackAction.COMPRESS_CONTEXT_AND_RETRY

    # 2. Timeout
    res_timeout = FallbackEngine.diagnose_and_resolve(
        error=TimeoutError("Connection timed out after 30s")
    )
    assert res_timeout.reason == FailureReason.TIMEOUT
    assert res_timeout.action == FallbackAction.SWITCH_TO_CLOUD

    # 3. Low confidence
    res_conf = FallbackEngine.diagnose_and_resolve(confidence_score=0.45)
    assert res_conf.reason == FailureReason.LOW_CONFIDENCE
    assert res_conf.action == FallbackAction.SWITCH_TO_CLOUD

    # 4. Unsupported capability
    res_cap = FallbackEngine.diagnose_and_resolve(has_required_capability=False)
    assert res_cap.reason == FailureReason.UNSUPPORTED_CAPABILITY
    assert res_cap.action == FallbackAction.SWITCH_TO_CLOUD


def test_ai_critic_and_finding_validator():
    # 1. Critic rejects WAF block
    res_waf = AICritic.evaluate_finding(
        vulnerability_type="sql_injection",
        observation_text="Server returned HTTP 403 Forbidden on single quote",
        evidence_list=["HTTP 403 Forbidden"],
        is_waf_block=True
    )
    assert res_waf.verdict == "rejected"
    assert res_waf.confidence_penalty >= 0.50

    # 2. Critic challenges lack of evidence
    res_weak = AICritic.evaluate_finding(
        vulnerability_type="idor",
        observation_text="Maybe user_id parameter allows access",
        evidence_list=[],
        has_baseline_differential=False
    )
    assert res_weak.verdict == "challenged"
    assert len(res_weak.missing_evidence) > 0

    # 3. Critic passes solid verifiable evidence
    res_solid = AICritic.evaluate_finding(
        vulnerability_type="sql_injection",
        observation_text="Canary reflected with mathematical differential (21+21 vs 42)",
        evidence_list=["Differential body length delta: 45 bytes", "Status code 200 OK"],
        has_baseline_differential=True
    )
    assert res_solid.verdict == "passed"
    assert res_solid.confidence_penalty == 0.0

    # 4. Finding Validator scores high confidence on passed critic review
    scorecard = FindingValidator.calculate_confidence(
        base_confidence=0.85,
        evidence_count=2,
        has_reproducible_poc=True,
        critic_review=res_solid
    )
    assert scorecard.final_confidence >= 0.90
    assert scorecard.confidence_tier == "High"
    assert scorecard.is_acceptable_for_reporting is True


@pytest.mark.asyncio
async def test_control_plane_end_to_end_flow():
    control_plane = HunterAIControlPlane.get_instance()

    # Create a task from WebAgent
    task = HunterTask(
        origin_agent="WebAgent",
        required_capabilities={AgentCapability.HTTP_ANALYSIS, AgentCapability.VULNERABILITY_ANALYSIS},
        target_url="https://app.local/api/v1/orders",
        raw_payload={
            "headers": {"Host": "app.local", "User-Agent": "Hunter"},
            "endpoints": ["/api/v1/orders", "/api/v1/orders?id=1"],
            "canary_marker": "HNT_CANARY_101"
        },
        contains_sensitive_data=False
    )

    # Submit task to Control Plane
    result: HunterAIResult = await control_plane.submit_task(task)

    assert result.status == "success"
    assert result.confidence >= 0.85
    assert result.critic_verdict == "passed"
    assert result.model == "qwen2.5-coder:14b"  # Local-first selected Qwen!
    assert task.state == TaskLifecycleState.COMPLETED
    assert TaskLifecycleState.PLANNING in task.state_history
    assert TaskLifecycleState.CRITIC_REVIEW in task.state_history

    # Check system health reporting
    health = control_plane.get_system_health()
    assert health["control_plane_status"] == "ONLINE"
    assert "WebAgent" in health["registered_agents"]
    assert health["total_tasks_processed"] >= 1
