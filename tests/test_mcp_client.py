"""
اختبارات عميل MCP (core/mcp_client.py) — مرحلة E.
يختبر: التكوين، اكتشاف الأدوات، استدعاء الأداة، الصحة، الإلغاء، مدير العملاء المتعددين.
لا يستهدف أي نظام خارجي؛ يستخدم محاكاة داخلية للاتصال.
"""
import asyncio
import json
import pytest

from core.mcp_client import MCPClient, MCPClientManager, MCPCallResult, MCPClientError
from core.mcp_config import MCPServerConfig, MCPTransport


def _config(**overrides):
    base = dict(
        server_id="test-server",
        name="Test Server",
        transport=MCPTransport.STDIO,
        command="python",
        args=["-c", "import sys; print('mcp stub')"],
        enabled=True,
    )
    base.update(overrides)
    return MCPServerConfig(**base)


class TestMCPConfig:
    def test_config_defaults(self):
        cfg = _config()
        assert cfg.server_id == "test-server"
        assert cfg.transport == MCPTransport.STDIO
        assert cfg.enabled is True
        assert cfg.timeout_s == 30.0

    def test_effective_env_no_secrets(self):
        cfg = _config(env={"NORMAL_VAR": "value", "API_KEY": "secret"})
        env = cfg.effective_env()
        assert env.get("NORMAL_VAR") == "value"
        assert "API_KEY" not in env  # الأسرار لا تُورث


class FakeMCPClient:
    """عميل MCP وهمي للاختبار دون عملية حقيقية."""
    def __init__(self, config, tools=None, should_fail_connect=False,
                 call_results=None):
        self.config = config
        self.tools = tools or []
        self.should_fail_connect = should_fail_connect
        self.call_results = call_results or {}
        self.calls = []
        self.status = "disconnected"
        self.connected = False

    async def connect(self):
        if self.should_fail_connect:
            raise MCPClientError("connect failed", category="CONNECTION_ERROR")
        self.status = "connected"
        self.connected = True

    async def health_check(self):
        return self.connected

    def list_tools(self):
        return self.tools

    def get_tool(self, namespaced_name):
        for t in self.tools:
            if t.namespaced_name == namespaced_name:
                return t
        return None

    async def call_tool(self, namespaced_name, arguments, timeout_s=None):
        self.calls.append((namespaced_name, arguments))
        result = self.call_results.get(namespaced_name)
        if result is None:
            return MCPCallResult(
                ok=True, server_id=self.config.server_id,
                tool_name=namespaced_name.split("::", 1)[-1],
                content=[{"type": "text", "text": "mock result"}])
        return result

    async def cancel(self):
        self.connected = False
        self.status = "disconnected"

    def audit_log(self):
        return []

    def snapshot(self):
        return {"server_id": self.config.server_id, "status": self.status}


class TestMCPClient:
    def test_snapshot_structure(self):
        cfg = _config()
        client = MCPClient(cfg)
        snap = client.snapshot()
        assert snap["server_id"] == "test-server"
        assert snap["transport"] == "stdio"

    @pytest.mark.asyncio
    async def test_call_tool_unknown_returns_error(self):
        cfg = _config()
        client = MCPClient(cfg)
        # لا يوجد اتصال، لكن get_tool يُرجع None → خطأ أداة غير معروفة
        result = await client.call_tool("unknown::tool", {})
        assert result.ok is False
        assert result.error_category == "UNKNOWN_TOOL"

    def test_audit_log_default_empty(self):
        cfg = _config()
        client = MCPClient(cfg)
        assert client.audit_log() == []


class TestMCPClientManager:
    def test_manager_list_tools(self):
        from dataclasses import replace
        cfg = _config()
        # نستخدم FakeMCPClient بدلاً من MCPClient حقيقي لتجنب العمليات
        manager = MCPClientManager([cfg])
        # استبدال العملاء بالزنك
        manager._clients = {}
        manager._configs = {}
        fake = FakeMCPClient(cfg)
        manager._clients["test-server"] = fake
        manager._configs["test-server"] = cfg

        tools = manager.list_tools_all()
        assert "test-server" in tools
        assert tools["test-server"] == []

    def test_manager_get_tool_namespaced(self):
        cfg = _config()
        manager = MCPClientManager([cfg])
        manager._clients = {}
        manager._configs = {}
        from core.mcp_client import MCPToolInfo
        tool = MCPToolInfo(
            server_id="test-server", tool_name="grep",
            namespaced_name="test-server::grep",
            description="search", input_schema={"type": "object"})
        fake = FakeMCPClient(cfg, tools=[tool])
        manager._clients["test-server"] = fake
        manager._configs["test-server"] = cfg

        got = manager.get_tool("test-server::grep")
        assert got is not None
        client, info = got
        assert info.tool_name == "grep"

    def test_manager_get_tool_no_namespace_returns_none(self):
        cfg = _config()
        manager = MCPClientManager([cfg])
        manager._clients = {}
        manager._configs = {}
        assert manager.get_tool("bare-name") is None

    def test_manager_disabled_server_not_loaded(self):
        cfg = _config(enabled=False)
        manager = MCPClientManager([cfg])
        assert manager.get_client("test-server") is None

    @pytest.mark.asyncio
    async def test_manager_connect_all(self):
        cfg = _config()
        manager = MCPClientManager([cfg])
        manager._clients = {}
        manager._configs = {}
        fake = FakeMCPClient(cfg)
        manager._clients["test-server"] = fake
        manager._configs["test-server"] = cfg

        results = await manager.connect_all()
        assert results["test-server"] is True
        assert fake.connected is True

    @pytest.mark.asyncio
    async def test_manager_connect_all_failure(self):
        cfg = _config()
        manager = MCPClientManager([cfg])
        manager._clients = {}
        manager._configs = {}
        fake = FakeMCPClient(cfg, should_fail_connect=True)
        manager._clients["test-server"] = fake
        manager._configs["test-server"] = cfg

        results = await manager.connect_all()
        assert results["test-server"] is False

    @pytest.mark.asyncio
    async def test_manager_health_check_all(self):
        cfg = _config()
        manager = MCPClientManager([cfg])
        manager._clients = {}
        manager._configs = {}
        fake = FakeMCPClient(cfg)
        fake.connected = True
        fake.status = "connected"
        manager._clients["test-server"] = fake
        manager._configs["test-server"] = cfg

        health = await manager.health_check_all()
        assert health["test-server"] is True

    @pytest.mark.asyncio
    async def test_manager_disconnect_all(self):
        cfg = _config()
        manager = MCPClientManager([cfg])
        manager._clients = {}
        manager._configs = {}
        fake = FakeMCPClient(cfg)
        fake.connected = True
        manager._clients["test-server"] = fake
        manager._configs["test-server"] = cfg

        await manager.disconnect_all()
        assert fake.connected is False


class TestMCPCallResult:
    def test_result_structure(self):
        r = MCPCallResult(
            ok=True, server_id="s", tool_name="t",
            content=[{"type": "text", "text": "hello"}],
            duration_s=1.5)
        assert r.ok is True
        assert r.content[0]["text"] == "hello"

    def test_error_result(self):
        r = MCPCallResult(
            ok=False, server_id="s", tool_name="t",
            error="boom", error_category="MCP_ERROR")
        assert r.ok is False
        assert r.error_category == "MCP_ERROR"
