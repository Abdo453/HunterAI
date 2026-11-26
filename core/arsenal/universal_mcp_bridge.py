"""
HunterAI Universal Model Context Protocol (MCP) Bridge
======================================================
Exposes the entire Kali Linux Security Tool Catalog (50+ tools across 14 categories)
as standardized MCP Tools conforming to the Model Context Protocol specification.
Allows external AI models (Claude Desktop, Cursor, Antigravity, OpenCode) to dynamically
invoke any security tool as a native function call over JSON-RPC 2.0 / stdio.

Phase 4 Hardening (adapted from PentesterFlow commit ``0759d87``, Apache-2.0 License):
- Enforces ``PolicyGate`` and ``StrictScopeEngine`` before tool execution (fail-closed)
- Scrubs all returned content through ``SecretSanitizer``
- Bounds untrusted output via ``bound_content`` (char/block/depth caps) before serialization
- Handles MCP ``notifications/initialized`` notifications without error responses
- Supports SHA-256 ``mcpServerFingerprint`` launch consent & async JSON-RPC execution
"""
from __future__ import annotations

import asyncio
import json
import logging
import sys
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from core.arsenal.kali_catalog import KALI_TOOL_CATALOG
from core.arsenal.tool_agent_factory import ToolAgentFactory
from core.mcp_client import (
    MCP_RESULT_CHAR_CAP,
    bound_content,
    boundContent,
    mcp_server_fingerprint,
    mcpServerFingerprint,
    truncate_mcp_string,
)
from core.scope_engine import (
    HARD_BLOCKED_HOSTS,
    INVIOLABLE_IPV4_SUBNETS,
    INVIOLABLE_IPV6_SUBNETS,
    ScopePolicy,
    StrictScopeEngine,
    normalize_ip_literal,
    validate_http_url_target,
)
from core.secret_sanitizer import SecretSanitizer
from core.security_mode import unrestricted_mode

logger = logging.getLogger("hunter_ai.arsenal.mcp_bridge")

_CLOUD_METADATA_IPS = {"169.254.169.254", "169.254.170.2", "100.100.100.200", "fd00:ec2::254"}


class UniversalMCPBridge:
    """
    Standard MCP Bridge connecting LLM tool calling to the Kali Arsenal,
    hardened with PolicyGate, StrictScopeEngine, SecretSanitizer, and boundContent.
    """

    def __init__(
        self,
        factory: Optional[ToolAgentFactory] = None,
        *,
        policy_gate: Optional[Any] = None,
        scope_engine: Optional[StrictScopeEngine] = None,
        scope_policy: Optional[ScopePolicy] = None,
        result_char_cap: int = MCP_RESULT_CHAR_CAP,
    ):
        self.factory = factory or ToolAgentFactory()
        self.policy_gate = policy_gate
        self.scope_engine = scope_engine or (
            StrictScopeEngine(scope_policy) if scope_policy is not None else None
        )
        self.result_char_cap = max(1024, int(result_char_cap))

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
        for tool_name, _tool_def in KALI_TOOL_CATALOG.items():
            agent = self.factory.get_agent(tool_name)
            if agent:
                tools.append(agent.skill.to_mcp_tool_schema())

        return tools

    def _enforce_policy_and_scope(
        self,
        resolved_tool: str,
        target: str,
        extra_args: Optional[List[str]],
        risk_level: str = "medium",
    ) -> Optional[Dict[str, Any]]:
        """Evaluate non-overridable SSRF/scheme invariants (EVEN under unrestricted_mode),
        then PolicyGate + StrictScopeEngine before invoking any tool (fail-closed)."""
        target_clean = (target or "").strip()

        # 0. Non-overridable scheme, cloud-metadata, and inviolable IP invariants
        #    run unconditionally — NEVER bypassed by unrestricted_mode().
        if target_clean:
            if any(ord(ch) < 32 or ch.isspace() for ch in target_clean):
                return {
                    "tool": resolved_tool,
                    "target": target_clean,
                    "success": False,
                    "error": f"SCOPE VIOLATION: target '{target_clean}' contains control or whitespace characters.",
                    "error_category": "SCOPE_VIOLATION",
                }
            if target_clean.startswith("//"):
                return {
                    "tool": resolved_tool,
                    "target": target_clean,
                    "success": False,
                    "error": f"SCOPE VIOLATION: scheme-relative target '{target_clean}' rejected.",
                    "error_category": "SCOPE_VIOLATION",
                }
            if "://" in target_clean:
                scheme = target_clean.split("://", 1)[0].lower()
                if scheme not in ("http", "https"):
                    return {
                        "tool": resolved_tool,
                        "target": target_clean,
                        "success": False,
                        "error": f"SCOPE VIOLATION: disallowed URL scheme '{scheme}://' in target '{target_clean}'.",
                        "error_category": "SCOPE_VIOLATION",
                    }
            elif ":" in target_clean and not target_clean.startswith("["):
                # Catch bare non-HTTP schemes like file:/etc/passwd or javascript:alert(1)
                prefix, rest = target_clean.split(":", 1)
                if prefix.isalpha() and not (rest.split("/", 1)[0].isdigit()):
                    return {
                        "tool": resolved_tool,
                        "target": target_clean,
                        "success": False,
                        "error": f"SCOPE VIOLATION: disallowed URL scheme '{prefix}:' in target '{target_clean}'.",
                        "error_category": "SCOPE_VIOLATION",
                    }

        parsed = urlparse(target_clean if "://" in target_clean else f"http://{target_clean}") if target_clean else None
        host = (parsed.hostname or target_clean).lower().rstrip(".") if parsed and target_clean else ""

        if host:
            if host in _CLOUD_METADATA_IPS or host in HARD_BLOCKED_HOSTS:
                return {
                    "tool": resolved_tool,
                    "target": target_clean,
                    "success": False,
                    "error": f"SCOPE VIOLATION: target '{target_clean}' is a hard-blocked host/metadata endpoint.",
                    "error_category": "SCOPE_VIOLATION",
                }
            ip_obj = normalize_ip_literal(host)
            if ip_obj is not None:
                inviolable_hit = False
                if ip_obj.version == 4:
                    inviolable_hit = any(ip_obj in net for net in INVIOLABLE_IPV4_SUBNETS)
                else:
                    inviolable_hit = any(ip_obj in net for net in INVIOLABLE_IPV6_SUBNETS)
                    if not inviolable_hit and getattr(ip_obj, "ipv4_mapped", None) is not None:
                        inviolable_hit = any(ip_obj.ipv4_mapped in net for net in INVIOLABLE_IPV4_SUBNETS)
                if inviolable_hit or str(ip_obj) in _CLOUD_METADATA_IPS:
                    return {
                        "tool": resolved_tool,
                        "target": target_clean,
                        "success": False,
                        "error": f"SCOPE VIOLATION: target '{target_clean}' resolves to an inviolable/metadata IP ({ip_obj}).",
                        "error_category": "SCOPE_VIOLATION",
                    }

        if unrestricted_mode():
            return None

        # 1. PolicyGate (fail-closed when attached)
        if self.policy_gate is not None:
            try:
                from core.control_plane.policy_gate import ActionCategory, ActionRequest

                is_high_risk = str(risk_level).lower() in ("high", "critical")
                category = (
                    ActionCategory.ACTIVE_FUZZING
                    if is_high_risk
                    else ActionCategory.TERMINAL_COMMAND
                )
                cmd_str = " ".join([resolved_tool, *(str(a) for a in (extra_args or [])), target_clean]).strip()
                req = ActionRequest(
                    category=category,
                    target=target_clean or "local_terminal",
                    url=target_clean if target_clean.startswith(("http://", "https://")) else None,
                    command=cmd_str,
                    reason=f"UniversalMCPBridge:{resolved_tool}",
                    requested_by_model="universal_mcp_bridge",
                    metadata={"tool": resolved_tool, "risk_level": risk_level},
                )
                decision = self.policy_gate.evaluate(req)
                if not decision.allowed:
                    return {
                        "tool": resolved_tool,
                        "target": target_clean,
                        "success": False,
                        "error": f"PolicyGate denied '{resolved_tool}': {decision.reason}",
                        "error_category": "POLICY_DENIED",
                    }
            except Exception as exc:
                return {
                    "tool": resolved_tool,
                    "target": target_clean,
                    "success": False,
                    "error": f"PolicyGate error (fail-closed): {exc}",
                    "error_category": "POLICY_ERROR",
                }

        # 2. StrictScopeEngine (fail-closed when attached)
        if self.scope_engine is not None:
            if not host:
                return {
                    "tool": resolved_tool,
                    "target": target_clean,
                    "success": False,
                    "error": f"SCOPE VIOLATION: empty target rejected for '{resolved_tool}'.",
                    "error_category": "SCOPE_VIOLATION",
                }
            try:
                allowed, reason = self.scope_engine.is_allowed(
                    target=host,
                    path=parsed.path if parsed else "",
                    port=parsed.port if parsed else None,
                )
                if not allowed:
                    return {
                        "tool": resolved_tool,
                        "target": target_clean,
                        "success": False,
                        "error": f"SCOPE VIOLATION: {reason}",
                        "error_category": "SCOPE_VIOLATION",
                    }
            except Exception as exc:
                return {
                    "tool": resolved_tool,
                    "target": target_clean,
                    "success": False,
                    "error": f"StrictScopeEngine error (fail-closed): {exc}",
                    "error_category": "SCOPE_ERROR",
                }

        return None

    def _sanitize_and_bound(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Apply PentesterFlow ``bound_content`` caps AND ``SecretSanitizer`` scrubbing."""
        bounded = bound_content(payload, self.result_char_cap)
        sanitized = SecretSanitizer.sanitize_data(bounded)
        return sanitized if isinstance(sanitized, dict) else {"result": sanitized}

    def handle_tool_call(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes the requested MCP tool call synchronously with PolicyGate,
        StrictScopeEngine, SecretSanitizer, and boundContent enforcement.
        """
        args = arguments if isinstance(arguments, dict) else {}
        target = str(args.get("target", "") or "")
        extra_args = args.get("extra_args")

        if tool_name == "kali_dispatch_tool":
            resolved_tool = str(args.get("tool_name", "") or "")
            if not resolved_tool:
                return {"success": False, "error": "Missing 'tool_name' in dispatch arguments"}
            agent = self.factory.get_agent(resolved_tool)
        else:
            clean_name = tool_name[len("kali_"):] if tool_name.startswith("kali_") else tool_name
            resolved_tool = clean_name
            agent = self.factory.get_agent(clean_name)

        if not agent:
            return {"success": False, "error": f"Tool '{tool_name}' not found in Kali Arsenal Catalog."}

        denial = self._enforce_policy_and_scope(
            agent.tool_def.name,
            target,
            extra_args if isinstance(extra_args, list) else None,
            risk_level=agent.tool_def.risk_level,
        )
        if denial is not None:
            return self._sanitize_and_bound(denial)

        res = agent.execute(target=target, extra_args=extra_args)
        raw_payload = {
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
        return self._sanitize_and_bound(raw_payload)

    async def handle_tool_call_async(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Asynchronously dispatches tool execution without blocking the event loop."""
        return await asyncio.to_thread(self.handle_tool_call, tool_name, arguments)


# ── JSON-RPC 2.0 Stdio Server ──────────────────────────────────────────────────

class MCPServerRunner:
    """
    Stdio-based JSON-RPC 2.0 server for Claude Desktop, Cursor, and IDE extensions.
    Handles ``initialize``, ``notifications/initialized``, ``tools/list``,
    ``tools/call`` (sync & async), and ``ping``.
    """

    def __init__(self, bridge: Optional[UniversalMCPBridge] = None):
        self.bridge = bridge or UniversalMCPBridge()
        self.initialized: bool = False

    def _format_tool_call_response(self, req_id: Any, call_res: Dict[str, Any]) -> str:
        bounded = bound_content(call_res, self.bridge.result_char_cap)
        serialized = truncate_mcp_string(
            json.dumps(bounded, indent=2, ensure_ascii=False),
            self.bridge.result_char_cap,
        )
        is_err = (not call_res.get("success", False)) if ("error" in call_res or "success" in call_res) else False
        result = {
            "content": [{"type": "text", "text": serialized}],
            "isError": bool(is_err),
        }
        return json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result})

    def _parse_rpc_line(self, request_str: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        try:
            req = json.loads(request_str)
            if not isinstance(req, dict):
                raise ValueError("JSON-RPC payload must be an object")
            return req, None
        except Exception as exc:
            err_resp = json.dumps({
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {exc}"},
            })
            return None, err_resp

    def _handle_non_call_method(self, req: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Handle initialize, notifications/initialized, tools/list, ping, and unknown methods.

        Returns ``(handled, response_json_or_none)``.
        """
        req_id = req.get("id")
        method = req.get("method")

        # JSON-RPC 2.0 notifications (including MCP `notifications/initialized`) have no response
        if method in ("notifications/initialized", "initialized"):
            self.initialized = True
            return True, None
        if isinstance(method, str) and method.startswith("notifications/"):
            return True, None

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
            return True, json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result})

        if method == "tools/list":
            result = {"tools": self.bridge.get_tool_definitions()}
            return True, json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result})

        if method == "ping":
            return True, json.dumps({"jsonrpc": "2.0", "id": req_id, "result": {}})

        if method == "tools/call":
            return False, None

        # Unknown notification with no id -> silently ignore per JSON-RPC 2.0 spec
        if req_id is None:
            return True, None

        return True, json.dumps({
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method '{method}' not found"},
        })

    def process_rpc_request(self, request_str: str) -> Optional[str]:
        """Processes a single JSON-RPC line request synchronously."""
        req, parse_err = self._parse_rpc_line(request_str)
        if parse_err is not None or req is None:
            return parse_err

        handled, resp = self._handle_non_call_method(req)
        if handled:
            return resp

        params = req.get("params") or {}
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})
        call_res = self.bridge.handle_tool_call(tool_name, arguments)
        return self._format_tool_call_response(req.get("id"), call_res)

    async def process_rpc_request_async(self, request_str: str) -> Optional[str]:
        """Processes a single JSON-RPC line request asynchronously (non-blocking tools/call)."""
        req, parse_err = self._parse_rpc_line(request_str)
        if parse_err is not None or req is None:
            return parse_err

        handled, resp = self._handle_non_call_method(req)
        if handled:
            return resp

        params = req.get("params") or {}
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})
        call_res = await self.bridge.handle_tool_call_async(tool_name, arguments)
        return self._format_tool_call_response(req.get("id"), call_res)

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

    async def run_stdio_async(self) -> None:
        """Async stdio loop running tool calls off the event loop via asyncio.to_thread."""
        logger.info("[MCPServerRunner] Starting Async Universal MCP Server on stdio...")
        while True:
            line = await asyncio.to_thread(sys.stdin.readline)
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            response = await self.process_rpc_request_async(line)
            if response:
                sys.stdout.write(response + "\n")
                sys.stdout.flush()


__all__ = [
    "MCPServerRunner",
    "UniversalMCPBridge",
    "boundContent",
    "bound_content",
    "mcpServerFingerprint",
    "mcp_server_fingerprint",
]
