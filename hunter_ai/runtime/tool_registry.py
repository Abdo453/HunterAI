"""
HunterAI Runtime: MCP-Style Tool Registry
==========================================
Standardized, schema-backed tool registry allowing LLMs and subagents to discover,
validate arguments, enforce immutable PolicyGate + StrictScopeEngine boundaries,
and execute tools with risk-level controls.
"""
from __future__ import annotations

import inspect
import logging
import os
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Coroutine, Dict, List, Optional, Sequence, Union

from core.control_plane.policy_gate import ActionCategory, ActionRequest, PolicyGate
from core.scope_engine import ScopePolicy, StrictScopeEngine
from core.security_mode import unrestricted_mode

logger = logging.getLogger("hunter_ai.tool_registry")

_URL_ARGUMENT_KEYS = ("url", "baseline_url", "probe_url", "target_url", "target")


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
            "inputSchema": self.input_schema,
        }


class ToolRegistry:
    """
    Central registry for all runtime tools in HunterAI.
    Validates input arguments against schemas and enforces PolicyGate + StrictScopeEngine.
    """

    def __init__(
        self,
        *,
        policy_gate: Optional[PolicyGate] = None,
        scope_engine: Optional[StrictScopeEngine] = None,
    ):
        self._tools: Dict[str, ToolDefinition] = {}
        self.policy_gate: Optional[PolicyGate] = policy_gate
        self.scope_engine: Optional[StrictScopeEngine] = scope_engine or (
            getattr(policy_gate, "_scope_engine", None) if policy_gate is not None else None
        )

    def register(
        self,
        name: str,
        description: str,
        input_schema: Dict[str, Any],
        handler: Callable[..., Coroutine[Any, Any, Dict[str, Any]]],
        risk_level: ToolRiskLevel = ToolRiskLevel.AUDIT,
    ):
        tool = ToolDefinition(
            name=name,
            description=description,
            input_schema=input_schema,
            risk_level=risk_level,
            handler=handler,
        )
        self._tools[name] = tool
        logger.info(f"[ToolRegistry] Registered tool '{name}' ({risk_level.value})")

    def get_tool(self, name: str) -> Optional[ToolDefinition]:
        return self._tools.get(name)

    def list_tools(self) -> List[Dict[str, Any]]:
        return [tool.to_mcp_dict() for tool in self._tools.values()]

    def _check_policy_and_scope(
        self,
        tool: ToolDefinition,
        arguments: Dict[str, Any],
    ) -> Optional[str]:
        """Enforce StrictScopeEngine + PolicyGate before invoking any network/target tool."""
        if unrestricted_mode():
            return None

        candidates: List[str] = []
        for key in _URL_ARGUMENT_KEYS:
            val = arguments.get(key)
            if isinstance(val, str) and val.strip():
                candidates.append(val.strip())

        if not candidates:
            if (
                tool.risk_level == ToolRiskLevel.ACTIVE
                and self.policy_gate is not None
                and not self.policy_gate.is_authorized
            ):
                return f"Active tool '{tool.name}' requires explicit authorization"
            return None

        category = (
            ActionCategory.ACTIVE_FUZZING
            if tool.risk_level == ToolRiskLevel.ACTIVE
            else ActionCategory.HTTP_REQUEST
        )
        method = str(arguments.get("method") or "GET").upper()

        for candidate in candidates:
            if self.scope_engine is not None:
                ok_scope, scope_reason = self.scope_engine.validate_url(candidate)
                if not ok_scope:
                    return f"StrictScopeEngine denied '{candidate}': {scope_reason}"
            if self.policy_gate is not None:
                decision = self.policy_gate.evaluate(
                    ActionRequest(
                        category=category,
                        target=candidate,
                        url=candidate,
                        method=method,
                        reason=f"runtime_tool_registry:{tool.name}",
                    )
                )
                if not decision.allowed:
                    return f"PolicyGate denied '{candidate}': {decision.reason}"
        return None

    async def execute(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        tool = self._tools.get(tool_name)
        if not tool:
            return {
                "success": False,
                "error": f"Tool '{tool_name}' not found in registry. Available tools: {list(self._tools.keys())}",
            }

        # Validate required arguments
        required_props = tool.input_schema.get("required", [])
        missing = [p for p in required_props if p not in arguments]
        if missing:
            return {
                "success": False,
                "error": f"Missing required arguments for tool '{tool_name}': {missing}",
            }

        # Enforce immutable PolicyGate + StrictScopeEngine before execution
        denial = self._check_policy_and_scope(tool, arguments)
        if denial is not None:
            logger.warning("[ToolRegistry] Blocked tool '%s': %s", tool_name, denial)
            return {
                "success": False,
                "blocked": True,
                "tool": tool_name,
                "error": denial,
            }

        try:
            if inspect.iscoroutinefunction(tool.handler):
                result = await tool.handler(**arguments)
            else:
                result = tool.handler(**arguments)
            return {
                "success": True,
                "tool": tool_name,
                "output": result,
            }
        except Exception as e:
            logger.error(f"[ToolRegistry] Error executing '{tool_name}': {e}", exc_info=True)
            return {
                "success": False,
                "tool": tool_name,
                "error": str(e),
            }


def build_default_tool_registry(
    http_client: Optional[Any] = None,
    memory_ref: Optional[Any] = None,
    *,
    policy_gate: Optional[PolicyGate] = None,
    scope_engine: Optional[StrictScopeEngine] = None,
    allowed_targets: Optional[Sequence[str]] = None,
    excluded_targets: Optional[Sequence[str]] = None,
    authorized: bool = False,
    allow_destructive: bool = False,
    vuln_db_path: Optional[Union[str, Path]] = None,
) -> ToolRegistry:
    """
    Constructs the default standard toolset for HunterAI, wiring immutable
    ``PolicyGate`` + ``StrictScopeEngine`` enforcement and ``core/vuln_intel/``
    SQLite advisory lookup.
    """
    import httpx
    from core.independent_verifier import IndependentVerifier
    from core.methodology_kb import MethodologyKB
    from core.vuln_intel.cli import DEFAULT_DB
    from core.vuln_intel.db import VulnerabilityStore
    from core.vuln_intel.models import (
        Ecosystem,
        ProjectPackage,
        ProjectProfile,
        record_from_stored,
    )
    from core.vuln_intel.triage import triage_project

    if policy_gate is None:
        if scope_engine is not None:
            resolved_policy = scope_engine.policy
        else:
            resolved_policy = ScopePolicy(
                allowed_targets=list(allowed_targets or []),
                excluded_targets=list(excluded_targets or []),
            )
            scope_engine = StrictScopeEngine(resolved_policy)
        policy_gate = PolicyGate(
            scope_policy=resolved_policy,
            authorized=authorized,
            allow_destructive=allow_destructive,
        )
    elif scope_engine is None:
        scope_engine = getattr(policy_gate, "_scope_engine", None)

    registry = ToolRegistry(policy_gate=policy_gate, scope_engine=scope_engine)
    verifier = IndependentVerifier()
    kb = MethodologyKB()

    def _resolve_vuln_store() -> VulnerabilityStore:
        raw_path = vuln_db_path or (os.environ.get("HUNTER_VULN_INTEL_DB") or "").strip() or DEFAULT_DB
        return VulnerabilityStore(raw_path)

    # 1. HTTP Probe Tool
    async def _http_probe(
        url: str,
        method: str = "GET",
        params: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
    ) -> Dict[str, Any]:
        t0 = time.time()
        if http_client is not None:
            resp = await http_client.request(method=method, url=url, params=params, headers=headers, content=body)
        else:
            async with httpx.AsyncClient(verify=False, timeout=8.0, follow_redirects=False) as client:
                resp = await client.request(method=method, url=url, params=params, headers=headers, content=body)
        duration = round(time.time() - t0, 3)
        return {
            "status_code": resp.status_code,
            "content_length": len(resp.text),
            "duration_seconds": duration,
            "headers": dict(resp.headers),
            "body_preview": resp.text[:1500],
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
                "body": {"type": "string", "description": "Optional request body content"},
            },
            "required": ["url"],
        },
        handler=_http_probe,
        risk_level=ToolRiskLevel.SAFE,
    )

    # 2. Differential Analysis Tool
    async def _differential_analyze(baseline_url: str, probe_url: str) -> Dict[str, Any]:
        if http_client is not None:
            r1 = await http_client.get(baseline_url)
            r2 = await http_client.get(probe_url)
        else:
            async with httpx.AsyncClient(verify=False, timeout=8.0, follow_redirects=False) as client:
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
            "significant_difference": (len_diff > 30) or status_changed,
        }

    registry.register(
        name="differential_analyze",
        description="Compare baseline URL response with a mutated probe URL response to spot behavioral differentials",
        input_schema={
            "type": "object",
            "properties": {
                "baseline_url": {"type": "string", "description": "Original un-mutated target URL"},
                "probe_url": {"type": "string", "description": "Mutated probe URL containing testing payload"},
            },
            "required": ["baseline_url", "probe_url"],
        },
        handler=_differential_analyze,
        risk_level=ToolRiskLevel.AUDIT,
    )

    # 3. Independent 3-Way Differential Verifier Tool
    async def _independent_verify(target_url: str, param_name: str, vuln_type: str) -> Dict[str, Any]:
        return await verifier.verify_endpoint_vulnerability(
            target_url=target_url,
            param_name=param_name,
            vuln_type=vuln_type,
        )

    registry.register(
        name="independent_verify",
        description="Execute independent 3-way differential verification (Baseline, Exploit Probe, Negative Control) to definitively validate findings and kill false positives",
        input_schema={
            "type": "object",
            "properties": {
                "target_url": {"type": "string", "description": "Target endpoint URL"},
                "param_name": {"type": "string", "description": "Target parameter name to verify"},
                "vuln_type": {"type": "string", "description": "Vulnerability type (sqli, xss, idor)"},
            },
            "required": ["target_url", "param_name", "vuln_type"],
        },
        handler=_independent_verify,
        risk_level=ToolRiskLevel.AUDIT,
    )

    # 4. CVE Lookup Tool (backed by canonical core/vuln_intel/ SQLite store)
    async def _cve_lookup(
        product: str,
        version: Optional[str] = None,
        ecosystem: Optional[str] = None,
        limit: int = 25,
    ) -> Dict[str, Any]:
        store = _resolve_vuln_store()
        db_total = store.count()
        needle = (product or "").strip()
        basename = needle.split("/")[-1]
        cap_limit = max(1, min(int(limit), 200))

        seen: Dict[str, Dict[str, Any]] = {}
        for batch in (
            store.search(package=needle, ecosystem=ecosystem, limit=cap_limit),
            store.search(product=basename, ecosystem=ecosystem, limit=cap_limit),
            store.search(text=needle, ecosystem=ecosystem, limit=cap_limit),
        ):
            for row in batch:
                rid = str(row.get("record_id") or "")
                if rid and rid not in seen:
                    seen[rid] = row

        matched_rows = list(seen.values())[:cap_limit]

        if not matched_rows:
            return {
                "product": product,
                "version": version,
                "status": "UNAVAILABLE" if db_total == 0 else "NO_MATCHES",
                "db_records_total": db_total,
                "provenance": "core.vuln_intel",
                "results": [],
            }

        eco_enum = Ecosystem.COMPOSER if "/" in needle else Ecosystem.CPE
        if ecosystem:
            try:
                eco_enum = Ecosystem(ecosystem.strip().lower())
            except ValueError:
                pass

        project = ProjectProfile(
            project_id=f"lookup:{needle}",
            name=needle,
            ecosystem=eco_enum,
            packages=[ProjectPackage(name=needle, version=version, ecosystem=eco_enum)],
            php_version=version if needle.lower() == "php" else None,
            inventory_complete=False,
        )

        enriched: List[Dict[str, Any]] = []
        for row in matched_rows:
            record = record_from_stored(row)
            triage = triage_project(project, record)
            enriched.append({
                "record_id": record.record_id,
                "canonical_id": record.canonical_id,
                "title": record.title or record.summary or record.canonical_id,
                "severity": record.severity.value,
                "cvss_score": record.cvss.score if record.cvss else None,
                "cwes": list(record.cwes),
                "source_id": record.source_id,
                "published_at": record.published_at.isoformat() if record.published_at else None,
                "applicability": triage.classification.value,
                "confidence": triage.confidence.value,
                "fixed_versions": list(triage.fixed_versions),
                "reasons": list(triage.reasons),
                "recommended_action": triage.recommended_action,
            })

        return {
            "product": product,
            "version": version,
            "status": "OK",
            "db_records_total": db_total,
            "provenance": "core.vuln_intel",
            "results": enriched,
        }

    registry.register(
        name="cve_lookup",
        description="Look up normalized CVEs, CVSS scores, and applicability triage from core/vuln_intel/ SQLite store",
        input_schema={
            "type": "object",
            "properties": {
                "product": {"type": "string", "description": "Product or package name (e.g. nginx, symfony/http-kernel, WordPress)"},
                "version": {"type": "string", "description": "Version string if known"},
                "ecosystem": {"type": "string", "description": "Optional ecosystem filter (composer, cpe, npm, pypi, php, wordpress)"},
                "limit": {"type": "integer", "description": "Maximum advisories to return", "default": 25},
            },
            "required": ["product"],
        },
        handler=_cve_lookup,
        risk_level=ToolRiskLevel.SAFE,
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
                "technique": {"type": "string", "description": "Vulnerability class or technique (sqli, idor, ssrf, xss)"},
            },
            "required": ["technique"],
        },
        handler=_methodology_lookup,
        risk_level=ToolRiskLevel.SAFE,
    )

    # 6. Record Structured Observation
    async def _record_observation(observation_type: str, details: str, endpoint: str = "") -> Dict[str, Any]:
        if memory_ref and hasattr(memory_ref, "record_observation"):
            memory_ref.record_observation({
                "type": observation_type,
                "details": details,
                "endpoint": endpoint,
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
                "endpoint": {"type": "string", "description": "Endpoint URL where observation occurred"},
            },
            "required": ["observation_type", "details"],
        },
        handler=_record_observation,
        risk_level=ToolRiskLevel.SAFE,
    )

    return registry
