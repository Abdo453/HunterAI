"""
HunterAI MCP Tools Manager (واجهة التكامل مع أدوات خارجية عبر بروتوكول MCP)
Model Context Protocol — يسمح لـ HunterAI بالتكامل مع أدوات خارجية وخدمات سحابية محلياً
"""
from __future__ import annotations

import logging
import asyncio
import json
import time
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

log = logging.getLogger("hunter_ai.mcp")


class MCPServerStatus(str):
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ERROR = "error"


@dataclass
class MCPTool:
    """أداة MCP واحدة"""
    tool_id: str
    name: str
    description: str
    server_id: str
    input_schema: Dict[str, Any] = field(default_factory=dict)
    output_schema: Dict[str, Any] = field(default_factory=dict)
    is_available: bool = True

    def to_dict(self) -> dict:
        return {
            "tool_id": self.tool_id,
            "name": self.name,
            "description": self.description,
            "server_id": self.server_id,
            "input_schema": self.input_schema,
            "output_schema": self.output_schema,
            "is_available": self.is_available,
        }


@dataclass
class MCPServer:
    """خادم MCP واحد"""
    server_id: str
    name: str
    command: str  # الأمر لتشغيل الخادم (مثلاً: npx @modelcontextprotocol/server-filesystem)
    args: List[str] = field(default_factory=list)
    env: Dict[str, str] = field(default_factory=dict)
    status: str = MCPServerStatus.DISCONNECTED
    tools: List[MCPTool] = field(default_factory=list)
    last_connected: Optional[float] = None
    error_message: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "server_id": self.server_id,
            "name": self.name,
            "command": self.command,
            "args": self.args,
            "env": self.env,
            "status": self.status,
            "tools": [t.to_dict() for t in self.tools],
            "last_connected": self.last_connected,
            "error_message": self.error_message,
        }


class MCPToolManager:
    """
    مدير أدوات MCP — يسجل خوادم MCP وأدواتها ويسمح باستدعائها من HunterAI
    """

    def __init__(self):
        self.servers: Dict[str, MCPServer] = {}
        self.tools: Dict[str, MCPTool] = {}  # tool_id -> MCPTool
        self._tool_counter = 0

    def register_server(
        self,
        server_id: str,
        name: str,
        command: str,
        args: Optional[List[str]] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> MCPServer:
        """تسجيل خادم MCP جديد"""
        server = MCPServer(
            server_id=server_id,
            name=name,
            command=command,
            args=args or [],
            env=env or {},
        )
        self.servers[server_id] = server
        log.info(f"[MCP] Registered server: {name} ({server_id})")
        return server

    def register_tool(
        self,
        server_id: str,
        tool_name: str,
        description: str,
        input_schema: Optional[Dict[str, Any]] = None,
        output_schema: Optional[Dict[str, Any]] = None,
    ) -> MCPTool:
        """تسجيل أداة MCP جديدة"""
        self._tool_counter += 1
        tool_id = f"mcp_tool_{self._tool_counter:04d}"
        tool = MCPTool(
            tool_id=tool_id,
            name=tool_name,
            description=description,
            server_id=server_id,
            input_schema=input_schema or {},
            output_schema=output_schema or {},
        )
        self.tools[tool_id] = tool

        # إضافة الأداة لخادمها
        if server_id in self.servers:
            self.servers[server_id].tools.append(tool)

        log.info(f"[MCP] Registered tool: {tool_name} ({tool_id}) on server {server_id}")
        return tool

    def get_tool(self, tool_id: str) -> Optional[MCPTool]:
        return self.tools.get(tool_id)

    def list_tools(self) -> List[MCPTool]:
        return list(self.tools.values())

    def list_tools_by_server(self, server_id: str) -> List[MCPTool]:
        return [t for t in self.tools.values() if t.server_id == server_id]

    def list_servers(self) -> List[MCPServer]:
        return list(self.servers.values())

    def get_server(self, server_id: str) -> Optional[MCPServer]:
        return self.servers.get(server_id)

    async def call_tool(
        self,
        tool_id: str,
        arguments: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        استدعاء أداة MCP بمعاملات معينة.
        في النسخة الحالية، يتم محاكاة الاستدعاء. في المستقبل، يمكن الاتصال بخادم MCP حقيقي.
        """
        tool = self.get_tool(tool_id)
        if not tool:
            return {
                "success": False,
                "error": f"Tool {tool_id} not found",
                "tool_id": tool_id,
            }

        server = self.get_server(tool.server_id)
        if not server or server.status != MCPServerStatus.CONNECTED:
            return {
                "success": False,
                "error": f"Server {tool.server_id} is not connected",
                "tool_id": tool_id,
            }

        # محاكاة الاستدعاء (في الإنتاج، يتم إرسال طلب MCP حقيقي للخادم)
        log.info(f"[MCP] Calling tool {tool_id} on server {tool.server_id}")
        await asyncio.sleep(0.1)  # محاكاة زمن الاستجابة

        return {
            "success": True,
            "tool_id": tool_id,
            "tool_name": tool.name,
            "server_id": tool.server_id,
            "arguments": arguments,
            "result": {
                "message": f"MCP tool {tool.name} executed successfully (simulated)",
                "data": arguments,  # في الإنتاج، يتم إرجاع النتيجة الحقيقية
            },
            "timestamp": time.time(),
        }

    def connect_server(self, server_id: str) -> bool:
        """الاتصال بخادم MCP"""
        server = self.get_server(server_id)
        if not server:
            return False

        import time
        server.status = MCPServerStatus.CONNECTED
        server.last_connected = time.time()
        server.error_message = None
        log.info(f"[MCP] Connected to server: {server.name} ({server_id})")
        return True

    def disconnect_server(self, server_id: str) -> bool:
        """فصل الاتصال بخادم MCP"""
        server = self.get_server(server_id)
        if not server:
            return False

        server.status = MCPServerStatus.DISCONNECTED
        server.error_message = None
        log.info(f"[MCP] Disconnected from server: {server.name} ({server_id})")
        return True

    def summary(self) -> dict:
        return {
            "total_servers": len(self.servers),
            "connected_servers": sum(1 for s in self.servers.values() if s.status == MCPServerStatus.CONNECTED),
            "total_tools": len(self.tools),
            "available_tools": sum(1 for t in self.tools.values() if t.is_available),
            "servers": [s.to_dict() for s in self.servers.values()],
        }


# مثيل افتراضي يمكن استخدامه في toda the system
mcp_tool_manager: Optional[MCPToolManager] = None


def get_mcp_tool_manager() -> MCPToolManager:
    global mcp_tool_manager
    if mcp_tool_manager is None:
        mcp_tool_manager = MCPToolManager()
    return mcp_tool_manager
