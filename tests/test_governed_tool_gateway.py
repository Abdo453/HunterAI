"""
Integration Tests for GovernedToolGateway & Web API Endpoint
Tests: Safe execution, Destructive blocking, Evidence synthesis, SecurityState ingestion, and REST API
"""
import pytest
from unittest.mock import AsyncMock, MagicMock
import httpx

from core.gateway.schemas import ActionProposal, RiskTier, GovernedExecutionResult
from core.gateway.tool_gateway import GovernedToolGateway
from core.gateway.policy_engine import PolicyEngine
from agents.security_intelligence.scope_guard import ScopeGuard
from agents.security_intelligence.schemas import ScopeRule, EvidenceType
from tools.tool_manager import ToolManager, ToolResult
from core.state.security_state import SecurityState
from ui.web.app import app


@pytest.fixture
def sample_gateway():
    rule = ScopeRule(
        target="api.target.local",
        allowed_domains=["api.target.local"],
        allow_active_tests=True
    )
    guard = ScopeGuard(rule)
    policy = PolicyEngine(scope_guard=guard)
    tm = MagicMock(spec=ToolManager)
    
    # Mock successful tool result
    tm.execute_tool = AsyncMock(return_value=ToolResult(
        tool="ffuf",
        command="ffuf -u https://api.target.local/FUZZ",
        stdout="Found /api/target.local/admin [Status: 200, Size: 1044]\nDifferential behavior detected",
        stderr="",
        returncode=0,
        duration=1.2
    ))

    state = SecurityState(target="api.target.local")
    gateway = GovernedToolGateway(
        policy_engine=policy,
        tool_manager=tm,
        security_state=state
    )
    return gateway, tm, state


@pytest.mark.asyncio
async def test_safe_proposal_execution(sample_gateway):
    gateway, tm, state = sample_gateway
    prop = ActionProposal(
        target="https://api.target.local/test",
        tool_name="ffuf",
        command_args="-u https://api.target.local/FUZZ",
        action_type="FUZZ",
        rationale="Discover unlinked endpoints"
    )
    result = await gateway.execute_proposal(prop)
    assert result.success is True
    assert result.blocked is False
    assert result.risk_tier == RiskTier.TIER_2_PROBE
    assert tm.execute_tool.called

    # Check evidence item was generated
    assert result.evidence_item is not None
    assert result.evidence_item.type in [EvidenceType.BEHAVIOR_DIFF, EvidenceType.STATUS_CODE]

    # Check evidence was automatically ingested into SecurityState
    assert result.evidence_item.id in state.evidence_store
    assert len(state.evidence_store) == 1

    # Check audit trail
    assert len(gateway.audit_trail) >= 2


@pytest.mark.asyncio
async def test_destructive_proposal_blocked(sample_gateway):
    gateway, tm, state = sample_gateway
    prop = ActionProposal(
        target="https://api.target.local/test",
        tool_name="sqlmap",
        command_args="--sql-query 'DROP TABLE users;'",
        action_type="CLI_TOOL"
    )
    result = await gateway.execute_proposal(prop)
    assert result.success is False
    assert result.blocked is True
    assert result.risk_tier == RiskTier.TIER_4_PROHIBITED_DESTRUCTIVE
    assert not tm.execute_tool.called
    assert "anti-destruction" in result.error.lower()


@pytest.mark.asyncio
async def test_rest_api_gateway_execute():
    """Test POST /api/gateway/execute endpoint"""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Safe proposal
        payload = {
            "target": "target.local",
            "tool_name": "whois",
            "command_args": "target.local",
            "action_type": "PASSIVE_ANALYSIS",
            "rationale": "Gather domain registrar information"
        }
        res = await client.post("/api/gateway/execute", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert "success" in data
        assert "blocked" in data
        assert "risk_tier" in data

        # Destructive proposal
        destructive_payload = {
            "target": "target.local",
            "tool_name": "bash",
            "command_args": "rm -rf / --no-preserve-root",
            "action_type": "CLI_TOOL"
        }
        res_dest = await client.post("/api/gateway/execute", json=destructive_payload)
        assert res_dest.status_code == 200
        dest_data = res_dest.json()
        assert dest_data["blocked"] is True
        assert dest_data["risk_tier"] == "TIER_4_PROHIBITED_DESTRUCTIVE"
