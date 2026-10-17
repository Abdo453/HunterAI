"""Tests لـ MCP Tools Manager"""
import sys
import os
import asyncio
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.mcp_tools.manager import (
    MCPToolManager, MCPTool, MCPServer, MCPServerStatus,
    mcp_tool_manager, get_mcp_tool_manager,
)


def test_register_server():
    mgr = MCPToolManager()
    server = mgr.register_server(
        server_id="fs_server",
        name="Filesystem Server",
        command="npx",
        args=["@modelcontextprotocol/server-filesystem", "/tmp"],
    )
    assert server.server_id == "fs_server"
    assert server.name == "Filesystem Server"
    assert server.status == MCPServerStatus.DISCONNECTED
    print("[PASS] mcp register server")


def test_register_tool():
    mgr = MCPToolManager()
    mgr.register_server("fs_server", "Filesystem", "npx", [])
    tool = mgr.register_tool(
        server_id="fs_server",
        tool_name="read_file",
        description="Read a file from the filesystem",
        input_schema={"path": {"type": "string"}},
        output_schema={"content": {"type": "string"}},
    )
    assert tool.tool_id.startswith("mcp_tool_")
    assert tool.name == "read_file"
    assert tool.server_id == "fs_server"
    print("[PASS] mcp register tool")


def test_list_tools_by_server():
    mgr = MCPToolManager()
    mgr.register_server("fs_server", "Filesystem", "npx", [])
    mgr.register_tool("fs_server", "read_file", "Read file", {"path": {"type": "string"}})
    mgr.register_tool("fs_server", "write_file", "Write file", {"path": {"type": "string"}, "content": {"type": "string"}})

    tools = mgr.list_tools_by_server("fs_server")
    assert len(tools) == 2
    print("[PASS] mcp list tools by server")


def test_connect_disconnect():
    mgr = MCPToolManager()
    mgr.register_server("fs_server", "Filesystem", "npx", [])
    assert mgr.connect_server("fs_server") is True
    assert mgr.get_server("fs_server").status == MCPServerStatus.CONNECTED
    assert mgr.disconnect_server("fs_server") is True
    assert mgr.get_server("fs_server").status == MCPServerStatus.DISCONNECTED
    print("[PASS] mcp connect/disconnect")


@pytest.mark.asyncio
async def test_call_tool():
    mgr = MCPToolManager()
    mgr.register_server("fs_server", "Filesystem", "npx", [])
    mgr.register_tool("fs_server", "read_file", "Read file", {"path": {"type": "string"}})
    mgr.connect_server("fs_server")

    result = await mgr.call_tool(
        tool_id=list(mgr.tools.values())[0].tool_id,
        arguments={"path": "/etc/passwd"},
    )
    assert result["success"] is True
    assert result["tool_name"] == "read_file"
    print("[PASS] mcp call tool")


def test_summary():
    mgr = MCPToolManager()
    mgr.register_server("fs_server", "Filesystem", "npx", [])
    mgr.register_tool("fs_server", "read_file", "Read file", {"path": {"type": "string"}})
    summary = mgr.summary()
    assert summary["total_servers"] == 1
    assert summary["total_tools"] == 1
    print("[PASS] mcp summary")


def test_agent_import():
    from core.mcp_tools.manager import MCPToolManager
    assert MCPToolManager is not None
    print("[PASS] mcp manager import")


if __name__ == "__main__":
    test_register_server()
    test_register_tool()
    test_list_tools_by_server()
    test_connect_disconnect()
    asyncio.run(test_call_tool())
    test_summary()
    test_agent_import()
    print("\n[INFO] جميع اختبارات MCP Tools Manager نجحت!")
