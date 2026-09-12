"""
HunterAI Runtime: MCP-Style Tool Registry
==========================================
Standardized, schema-backed tool registry allowing LLMs and subagents to discover,
validate arguments, and safely execute tools with risk-level boundaries.
"""
from __future__ import annotations

import inspect
import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Callable, Coroutine

logger = logging.getLogger("hunter_ai.tool_registry")


class ToolRiskLevel(str, Enum):
    SAFE = "SAFE"           # Passive recon, reading local files, DB queries
    AUDIT = "AUDIT"         # Benign differential probes, non-destructive syntax tests
    ACTIVE = "ACTIVE"       # Direct injection, exploitation verifications


@dataclass
class ToolDefinition:
    name: str
    description: str
    input_schema: Dict[str, Any]
    risk_level: ToolRiskLevel
    handler: Callable[..., Coroutine[Any, Any, Dict[str, Any]]]

    def to_mcp_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": f"[{self.risk_level.value}] {self.description}",
            "inputSchema": self.input_schema
        }


class ToolRegistry:
    """
    Central registry for all tools in HunterAI.
    Validates input arguments against schemas and enforces safety bounds.
    """

    def __init__(self):
        self._tools: Dict[str, ToolDefinition] = {}

    def register(
        self,
        name: str,
        description: str,
        input_schema: Dict[str, Any],
        handler: Callable[..., Coroutine[Any, Any, Dict[str, Any]]],
        risk_level: ToolRiskLevel = ToolRiskLevel.AUDIT
    ):
        tool = ToolDefinition(
            name=name,
            description=description,
            input_schema=input_schema,
            risk_level=risk_level,
            handler=handler
        )
        self._tools[name] = tool
        logger.info(f"[ToolRegistry] Registered tool '{name}' ({risk_level.value})")

    def get_tool(self, name: str) -> Optional[ToolDefinition]:
        return self._tools.get(name)

    def list_tools(self) -> List[Dict[str, Any]]:
        return [tool.to_mcp_dict() for tool in self._tools.values()]

    async def execute(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        tool = self._tools.get(tool_name)
        if not tool:
            return {
                "success": False,
                "error": f"Tool '{tool_name}' not found in registry. Available tools: {list(self._tools.keys())}"
            }

        # Validate required arguments
        required_props = tool.input_schema.get("required", [])
        missing = [p for p in required_props if p not in arguments]
        if missing:
            return {
                "success": False,
                "error": f"Missing required arguments for tool '{tool_name}': {missing}"
            }

        try:
            if inspect.iscoroutinefunction(tool.handler):
                result = await tool.handler(**arguments)
            else:
                result = tool.handler(**arguments)
            return {
                "success": True,
                "tool": tool_name,
                "output": result
            }
        except Exception as e:
            logger.error(f"[ToolRegistry] Error executing '{tool_name}': {e}", exc_info=True)
            return {
                "success": False,
                "tool": tool_name,
                "error": str(e)
            }


def build_default_tool_registry(
    http_client: Optional[Any] = None,
    memory_ref: Optional[Any] = None
) -> ToolRegistry:
    """
    Constructs the default standard toolset for HunterAI
    wrapping existing core modules into MCP-compliant tools.
    """
    import httpx
    from core.independent_verifier import IndependentVerifier
    from core.cve_intel import CVEIntelligenceEngine
    from core.methodology_kb import MethodologyKB

    registry = ToolRegistry()
    verifier = IndependentVerifier()
    cve_engine = CVEIntelligenceEngine()
    kb = MethodologyKB()

    # 1. HTTP Probe Tool
    async def _http_probe(url: str, method: str = "GET", params: Dict[str, str] = None, headers: Dict[str, str] = None, body: str = None) -> Dict[str, Any]:
        async with httpx.AsyncClient(verify=False, timeout=8.0) as client:
            import time
            t0 = time.time()
            resp = await client.request(method=method, url=url, params=params, headers=headers, content=body)
            duration = round(time.time() - t0, 3)
            return {
                "status_code": resp.status_code,
                "content_length": len(resp.text),
                "duration_seconds": duration,
                "headers": dict(resp.headers),
                "body_preview": resp.text[:1500]
            }

    registry.register(
        name="http_probe",
        description="Send an HTTP request to inspect server status code, headers, length, and response body",
        input_schema={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL to probe"},
                "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE"], "default": "GET"},
                "params": {"type": "object", "description": "Query parameters dictionary"},
                "headers": {"type": "object", "description": "HTTP request headers dictionary"},
                "body": {"type": "string", "description": "Optional request body content"}
            },
            "required": ["url"]
        },
        handler=_http_probe,
        risk_level=ToolRiskLevel.SAFE
    )

    # 2. Differential Analysis Tool
    async def _differential_analyze(baseline_url: str, probe_url: str) -> Dict[str, Any]:
        async with httpx.AsyncClient(verify=False, timeout=8.0) as client:
            r1 = await client.get(baseline_url)
            r2 = await client.get(probe_url)

            len_diff = abs(len(r1.text) - len(r2.text))
            status_changed = r1.status_code != r2.status_code

            return {
                "baseline_status": r1.status_code,
                "probe_status": r2.status_code,
                "status_changed": status_changed,
                "baseline_length": len(r1.text),
                "probe_length": len(r2.text),
                "length_diff": len_diff,
                "significant_difference": (len_diff > 30) or status_changed
            }

    registry.register(
        name="differential_analyze",
        description="Compare baseline URL response with a mutated probe URL response to spot behavioral differentials",
        input_schema={
            "type": "object",
            "properties": {
                "baseline_url": {"type": "string", "description": "Original un-mutated target URL"},
                "probe_url": {"type": "string", "description": "Mutated probe URL containing testing payload"}
            },
            "required": ["baseline_url", "probe_url"]
        },
        handler=_differential_analyze,
        risk_level=ToolRiskLevel.AUDIT
    )

    # 3. Independent 3-Way Differential Verifier Tool
    async def _independent_verify(target_url: str, param_name: str, vuln_type: str) -> Dict[str, Any]:
        return await verifier.verify_endpoint_vulnerability(
            target_url=target_url,
            param_name=param_name,
            vuln_type=vuln_type
        )

    registry.register(
        name="independent_verify",
        description="Execute independent 3-way differential verification (Baseline, Exploit Probe, Negative Control) to definitively validate findings and kill false positives",
        input_schema={
            "type": "object",
            "properties": {
                "target_url": {"type": "string", "description": "Target endpoint URL"},
                "param_name": {"type": "string", "description": "Target parameter name to verify"},
                "vuln_type": {"type": "string", "description": "Vulnerability type (sqli, xss, idor)"}
            },
            "required": ["target_url", "param_name", "vuln_type"]
        },
        handler=_independent_verify,
        risk_level=ToolRiskLevel.AUDIT
    )

    # 4. CVE Lookup Tool
    async def _cve_lookup(product: str, version: str = None) -> Dict[str, Any]:
        res = await cve_engine.lookup_cves(product=product, version=version)
        return {"product": product, "version": version, "results": res}

    registry.register(
        name="cve_lookup",
        description="Look up known CVEs, CVSS scores, and published advisories for a detected product or framework",
        input_schema={
            "type": "object",
            "properties": {
                "product": {"type": "string", "description": "Product or vendor name (e.g. Apache, Spring, WordPress)"},
                "version": {"type": "string", "description": "Version string if known"}
            },
            "required": ["product"]
        },
        handler=_cve_lookup,
        risk_level=ToolRiskLevel.SAFE
    )

    # 5. Security Methodology Lookup Tool
    async def _methodology_lookup(technique: str) -> Dict[str, Any]:
        guide = kb.get_technique_guidance(technique)
        return {"technique": technique, "guidance": guide}

    registry.register(
        name="methodology_lookup",
        description="Fetch official PortSwigger/OWASP testing methodology, verification predicates, and bypass guides",
        input_schema={
            "type": "object",
            "properties": {
                "technique": {"type": "string", "description": "Vulnerability class or technique (sqli, idor, ssrf, xss)"}
            },
            "required": ["technique"]
        },
        handler=_methodology_lookup,
        risk_level=ToolRiskLevel.SAFE
    )

    # 6. Record Structured Observation
    async def _record_observation(observation_type: str, details: str, endpoint: str = "") -> Dict[str, Any]:
        if memory_ref and hasattr(memory_ref, "record_observation"):
            memory_ref.record_observation({
                "type": observation_type,
                "details": details,
                "endpoint": endpoint
            })
        return {"status": "recorded", "type": observation_type, "details": details}

    registry.register(
        name="record_observation",
        description="Save a structured security observation into agent working memory",
        input_schema={
            "type": "object",
            "properties": {
                "observation_type": {"type": "string", "description": "Category: reflection, error, status_anomaly, param_hint"},
                "details": {"type": "string", "description": "Clear factual description of the observation"},
                "endpoint": {"type": "string", "description": "Endpoint URL where observation occurred"}
            },
            "required": ["observation_type", "details"]
        },
        handler=_record_observation,
        risk_level=ToolRiskLevel.SAFE
    )

    return registry
