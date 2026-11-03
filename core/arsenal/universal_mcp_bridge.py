"""
HunterAI Universal Model Context Protocol (MCP) Bridge
======================================================
Exposes the entire Kali Linux Security Tool Catalog (50+ tools across 14 categories)
as standardized MCP Tools conforming to the Model Context Protocol specification.
Allows external AI models (Claude Desktop, Cursor, Antigravity, OpenCode) to dynamically
invoke any security tool as a native function call over JSON-RPC 2.0 / stdio.
"""
from __future__ import annotations

import asyncio
import json
import logging
import sys
from typing import Any, Dict, List, Optional

from core.arsenal.kali_catalog import KALI_TOOL_CATALOG, get_tool_definition
from core.arsenal.tool_agent_factory import ToolAgentFactory

logger = logging.getLogger("hunter_ai.arsenal.mcp_bridge")


class UniversalMCPBridge:
    """
    Standard MCP Bridge connecting LLM tool calling to the Kali Arsenal.
    """

    def __init__(self, factory: Optional[ToolAgentFactory] = None):
        self.factory = factory or ToolAgentFactory()

    def get_tool_definitions(self) -> List[Dict[str, Any]]:
        """
        Returns the complete list of MCP tool schemas for all cataloged security tools.
        """
        tools: List[Dict[str, Any]] = []

        # 1. Master dispatcher tool
        tools.append({
            "name": "kali_dispatch_tool",
            "description": (
                "Universal dispatcher to execute any Kali Linux security tool by name. "
                "Supports all 14 categories: recon, port_scan, web_crawl, fuzzing, vuln_scan, exploitation, etc."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "tool_name": {
                        "type": "string",
                        "description": "The name of the tool (e.g. subfinder, nmap, sqlmap, ffuf, nuclei).",
                    },
                    "target": {
                        "type": "string",
                        "description": "Target hostname, IP, domain, or URL.",
                    },
                    "extra_args": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional CLI arguments to customize the scan.",
                    },
                },
                "required": ["tool_name", "target"],
            },
        })

        # 2. Individual tool schemas for all cataloged tools
        for tool_name, tool_def in KALI_TOOL_CATALOG.items():
            agent = self.factory.get_agent(tool_name)
            if agent:
                tools.append(agent.skill.to_mcp_tool_schema())

        return tools

    def handle_tool_call(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes the requested MCP tool call synchronously.
        """
        target = arguments.get("target", "")
        extra_args = arguments.get("extra_args")

        # Handle dispatcher
        if tool_name == "kali_dispatch_tool":
            resolved_tool = arguments.get("tool_name", "")
            if not resolved_tool:
                return {"error": "Missing 'tool_name' in dispatch arguments"}
            agent = self.factory.get_agent(resolved_tool)
        else:
            # Handle specific kali tool (strip prefix)
            clean_name = tool_name
            if clean_name.startswith("kali_"):
                clean_name = clean_name[len("kali_"):]
            agent = self.factory.get_agent(clean_name)

        if not agent:
            return {"error": f"Tool '{tool_name}' not found in Kali Arsenal Catalog."}

        res = agent.execute(target=target, extra_args=extra_args)
        return {
            "tool": agent.tool_def.name,
            "category": agent.tool_def.category.value,
            "target": target,
            "success": res.success,
            "exit_code": res.exit_code,
            "used_fallback": res.used_fallback,
            "stdout": res.stdout,
            "stderr": res.stderr,
            "duration_secs": res.duration_secs,
            "structured_data": res.structured_data,
        }

    async def handle_tool_call_async(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Asynchronously dispatches tool execution."""
        return await asyncio.to_thread(self.handle_tool_call, tool_name, arguments)


# ── JSON-RPC 2.0 Stdio Server ──────────────────────────────────────────────────

class MCPServerRunner:
    """
    Stdio-based JSON-RPC 2.0 server for Claude Desktop, Cursor, and IDE extensions.
    """

    def __init__(self, bridge: Optional[UniversalMCPBridge] = None):
        self.bridge = bridge or UniversalMCPBridge()

    def process_rpc_request(self, request_str: str) -> Optional[str]:
        """Processes a single JSON-RPC line request and returns the JSON-RPC response."""
        try:
            req = json.loads(request_str)
        except Exception as exc:
            return json.dumps({
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {exc}"},
            })

        req_id = req.get("id")
        method = req.get("method")
        params = req.get("params", {})

        # Handle standard MCP endpoints
        if method == "initialize":
            result = {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {"listChanged": False},
                },
                "serverInfo": {
                    "name": "hunter-ai-kali-arsenal-mcp",
                    "version": "2.0.0",
                },
            }
            return json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result})

        elif method == "tools/list":
            result = {"tools": self.bridge.get_tool_definitions()}
            return json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result})

        elif method == "tools/call":
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})
            call_res = self.bridge.handle_tool_call(tool_name, arguments)
            result = {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(call_res, indent=2),
                    }
                ],
                "isError": not call_res.get("success", False) if "error" in call_res else False,
            }
            return json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result})

        elif method == "ping":
            return json.dumps({"jsonrpc": "2.0", "id": req_id, "result": {}})

        else:
            return json.dumps({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Method '{method}' not found"},
            })

    def run_stdio(self) -> None:
        """Runs the MCP server loop reading from stdin and writing to stdout."""
        logger.info("[MCPServerRunner] Starting Universal MCP Server on stdio...")
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            response = self.process_rpc_request(line)
            if response:
                sys.stdout.write(response + "\n")
                sys.stdout.flush()
