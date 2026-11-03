"""
HunterAI Tool Agent & Skill Factory
====================================
Dynamically generates specialized AI Agents and Model Context Protocol (MCP) Skills
for every security tool in the Kali Linux Catalog.
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.arsenal.kali_catalog import (
    KALI_TOOL_CATALOG,
    ToolCategory,
    ToolDefinition,
    get_tool_definition,
)
from core.engine.real_tool_adapter import RealToolAdapter, ToolExecutionResult

logger = logging.getLogger("hunter_ai.arsenal.factory")


@dataclass
class ToolSkillDescriptor:
    skill_id: str
    name: str
    category: str
    description: str
    input_schema: Dict[str, Any]
    risk_level: str
    requires_authorization: bool
    output_format: str
    tags: List[str] = field(default_factory=list)

    def to_mcp_tool_schema(self) -> Dict[str, Any]:
        """Converts skill descriptor to standard MCP Tool JSON Schema."""
        return {
            "name": f"kali_{self.name.replace('-', '_')}",
            "description": f"[{self.category.upper()}] {self.description} (Risk: {self.risk_level.upper()})",
            "inputSchema": self.input_schema,
        }


class DynamicToolAgent:
    """
    An autonomous agent persona specialized in a single security tool from the Kali Arsenal.
    Encapsulates tool execution, safety parameters, structured output parsing, and agent persona.
    Equipped with Cognitive Deliberation for Pre-Tool Reflection and Post-Tool Self-Correction.
    """

    def __init__(
        self,
        tool_def: ToolDefinition,
        adapter: Optional[RealToolAdapter] = None,
        deliberator: Optional[Any] = None,
    ):
        self.tool_def = tool_def
        self.adapter = adapter or RealToolAdapter()
        self._deliberator = deliberator
        self.name = f"{tool_def.name.replace('-', '_')}_agent"
        self.role = f"Specialist in {tool_def.category.value.title()} ({tool_def.name})"
        self.system_prompt = self._build_system_prompt()
        self.skill = self._build_skill_descriptor()

    def get_deliberator(self):
        if self._deliberator is None:
            from core.cognitive.cognitive_deliberator import CognitiveDeliberator
            self._deliberator = CognitiveDeliberator()
        return self._deliberator

    def _build_system_prompt(self) -> str:
        return (
            f"You are the specialized AI Security Agent for '{self.tool_def.name}' "
            f"categorized under '{self.tool_def.category.value.upper()}'.\n"
            f"Package: {self.tool_def.kali_package} | Binary: {self.tool_def.binary_name}\n"
            f"Capability Description: {self.tool_def.description}\n"
            f"Default execution arguments: {' '.join(self.tool_def.default_args)}\n"
            f"Risk Level: {self.tool_def.risk_level.upper()}\n"
            f"Requires Explicit Target Authorization: {self.tool_def.requires_authorization}\n"
            f"Expected Output Format: {self.tool_def.output_format.upper()}\n\n"
            f"OPERATIONAL INVARIANTS:\n"
            f"1. Zero Unauthorized Drift: Never execute against any host outside target scope.\n"
            f"2. Evidence First: Parse CLI outputs into structured factual proof.\n"
            f"3. Non-Destructive: Never perform state-destroying commands or schema modifications.\n"
            f"4. Fail-Safe: If the tool binary is unavailable, seamlessly engage hermetic validation."
        )

    def _build_skill_descriptor(self) -> ToolSkillDescriptor:
        return ToolSkillDescriptor(
            skill_id=f"kali_{self.tool_def.name.replace('-', '_')}",
            name=self.tool_def.name,
            category=self.tool_def.category.value,
            description=self.tool_def.description,
            input_schema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target hostname, domain, URL, or CIDR range.",
                    },
                    "extra_args": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional list of additional CLI flags/parameters.",
                    },
                },
                "required": ["target"],
            },
            risk_level=self.tool_def.risk_level,
            requires_authorization=self.tool_def.requires_authorization,
            output_format=self.tool_def.output_format,
            tags=list(self.tool_def.tags),
        )

    def execute(
        self,
        target: str,
        extra_args: Optional[List[str]] = None,
        force_fallback: bool = False,
        timeout: Optional[float] = None,
        deliberate: bool = True,
        verbose_thinking: bool = False,
    ) -> ToolExecutionResult:
        """
        Executes the tool against the specified target.
        Falls back to hermetic emulation if binary is not present or fallback is requested.
        Engages Pre-Tool Reflection and Post-Tool Self-Correction when deliberate=True.
        """
        delib = None
        if deliberate:
            deliberator = self.get_deliberator()
            delib = deliberator.deliberate_pre_tool(
                tool_name=self.tool_def.name,
                target=target,
                category=self.tool_def.category.value,
            )
            if verbose_thinking:
                print(deliberator.format_pre_tool_trace(delib))

        start = time.time()
        timeout_to_use = timeout or self.tool_def.timeout_secs
        use_fallback = force_fallback or self.adapter.force_fallback or not self.adapter.is_tool_available(self.tool_def.binary_name)

        if not use_fallback:
            # Construct command
            cmd = [self.tool_def.binary_name]
            for arg in self.tool_def.default_args:
                if "{target}" in arg:
                    cmd.append(arg.replace("{target}", target))
                else:
                    cmd.append(arg)
            if extra_args:
                cmd.extend(extra_args)

            logger.info("[DynamicToolAgent] Executing real tool binary: %s", " ".join(cmd))
            exit_code, stdout, stderr = self.adapter._run_subprocess(cmd, timeout=timeout_to_use)
            duration = time.time() - start

            # Structured parsing
            structured_data: Dict[str, Any] = {}
            if self.tool_def.output_format == "json" and stdout.strip():
                try:
                    structured_data = json.loads(stdout)
                except Exception:
                    # Might be json lines
                    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
                    parsed_lines = []
                    for line in lines:
                        try:
                            parsed_lines.append(json.loads(line))
                        except Exception:
                            pass
                    if parsed_lines:
                        structured_data = {"items": parsed_lines}
            elif self.tool_def.output_format == "text":
                lines = [l.strip() for l in stdout.splitlines() if l.strip()]
                structured_data = {"lines": lines, "count": len(lines)}

            result = ToolExecutionResult(
                tool_name=self.tool_def.name,
                target=target,
                command=cmd,
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                duration_secs=duration,
                used_fallback=False,
                structured_data=structured_data,
            )
        else:
            # Fallback execution (hermetic & safe)
            duration = time.time() - start
            result = self._generate_fallback_result(target, duration)

        if deliberate:
            deliberator = self.get_deliberator()
            reflection = deliberator.reflect_post_tool(
                tool_name=self.tool_def.name,
                target=target,
                exit_code=result.exit_code,
                stdout=result.stdout,
                stderr=result.stderr,
                used_fallback=result.used_fallback,
                structured_data=result.structured_data,
            )
            result.structured_data["cognitive_deliberation"] = {
                "hypothesis_tested": delib.hypothesis_tested if delib else "",
                "verdict": reflection.verdict,
                "confidence_posterior": reflection.confidence_posterior,
                "aha_moment": reflection.aha_moment,
                "next_recommended_step": reflection.next_recommended_step,
            }
            if verbose_thinking:
                print(deliberator.format_post_tool_trace(reflection))

        return result

    def _generate_fallback_result(self, target: str, duration: float) -> ToolExecutionResult:
        """Generates realistic synthetic results for hermetic unit testing and offline environments."""
        clean_target = target.replace("https://", "").replace("http://", "").split("/")[0]
        cat = self.tool_def.category

        if cat == ToolCategory.RECON:
            subdomains = [clean_target, f"api.{clean_target}", f"admin.{clean_target}", f"app.{clean_target}"]
            return ToolExecutionResult(
                tool_name=self.tool_def.name,
                target=target,
                command=["fallback", self.tool_def.binary_name, target],
                exit_code=0,
                stdout="\n".join(subdomains),
                stderr="",
                duration_secs=duration,
                used_fallback=True,
                structured_data={"subdomains": subdomains, "count": len(subdomains)},
            )
        elif cat == ToolCategory.PORT_SCAN:
            ports = [
                {"port": 80, "service": "http", "state": "open"},
                {"port": 443, "service": "https", "state": "open"},
                {"port": 8080, "service": "http-proxy", "state": "open"},
            ]
            return ToolExecutionResult(
                tool_name=self.tool_def.name,
                target=target,
                command=["fallback", self.tool_def.binary_name, target],
                exit_code=0,
                stdout=f"Discovered {len(ports)} open ports on {clean_target}",
                stderr="",
                duration_secs=duration,
                used_fallback=True,
                structured_data={"open_ports": ports},
            )
        elif cat == ToolCategory.WEB_CRAWL:
            urls = [
                f"https://{clean_target}/",
                f"https://{clean_target}/login",
                f"https://{clean_target}/api/v1/users",
                f"https://{clean_target}/dashboard",
            ]
            return ToolExecutionResult(
                tool_name=self.tool_def.name,
                target=target,
                command=["fallback", self.tool_def.binary_name, target],
                exit_code=0,
                stdout="\n".join(urls),
                stderr="",
                duration_secs=duration,
                used_fallback=True,
                structured_data={"crawled_urls": urls, "total_discovered": len(urls)},
            )
        elif cat == ToolCategory.VULN_SCAN:
            vulns = [
                {
                    "template_id": "cve-2023-sample",
                    "name": "Sample Disclosed Vulnerability",
                    "severity": "medium",
                    "matched_at": f"https://{clean_target}/api/v1",
                }
            ]
            return ToolExecutionResult(
                tool_name=self.tool_def.name,
                target=target,
                command=["fallback", self.tool_def.binary_name, target],
                exit_code=0,
                stdout=json.dumps(vulns),
                stderr="",
                duration_secs=duration,
                used_fallback=True,
                structured_data={"vulnerabilities": vulns},
            )
        elif cat == ToolCategory.FUZZING:
            endpoints = ["/admin", "/backup.zip", "/config.json", "/api"]
            return ToolExecutionResult(
                tool_name=self.tool_def.name,
                target=target,
                command=["fallback", self.tool_def.binary_name, target],
                exit_code=0,
                stdout="\n".join(endpoints),
                stderr="",
                duration_secs=duration,
                used_fallback=True,
                structured_data={"endpoints": endpoints},
            )
        else:
            # Generic fallback
            return ToolExecutionResult(
                tool_name=self.tool_def.name,
                target=target,
                command=["fallback", self.tool_def.binary_name, target],
                exit_code=0,
                stdout=f"Simulated execution for {self.tool_def.name} on {target}",
                stderr="",
                duration_secs=duration,
                used_fallback=True,
                structured_data={"status": "completed", "category": cat.value},
            )


class ToolAgentFactory:
    """
    Factory for instantiating dynamic tool agents and generating agent personas & skills
    from the Universal Kali Catalog.
    """

    def __init__(self, adapter: Optional[RealToolAdapter] = None):
        self.adapter = adapter or RealToolAdapter()
        self._cached_agents: Dict[str, DynamicToolAgent] = {}

    def get_agent(self, tool_name: str) -> Optional[DynamicToolAgent]:
        """Retrieves or builds a DynamicToolAgent for the requested tool."""
        normalized = tool_name.lower().replace("-", "_")
        if normalized in self._cached_agents:
            return self._cached_agents[normalized]

        tool_def = get_tool_definition(normalized)
        if not tool_def:
            # Fallback search by binary or tool name
            for key, t in KALI_TOOL_CATALOG.items():
                if t.name == tool_name or t.binary_name == tool_name or key == normalized:
                    tool_def = t
                    break

        if not tool_def:
            return None

        agent = DynamicToolAgent(tool_def, adapter=self.adapter)
        self._cached_agents[normalized] = agent
        return agent

    def create_all_agents(self) -> Dict[str, DynamicToolAgent]:
        """Instantiates all dynamic agents for every tool in the catalog."""
        agents = {}
        for name in KALI_TOOL_CATALOG.keys():
            agent = self.get_agent(name)
            if agent:
                agents[name] = agent
        return agents

    def list_arsenal_status(self) -> List[Dict[str, Any]]:
        """Returns catalog tools with their local installation and availability status."""
        status = []
        for name, tool in KALI_TOOL_CATALOG.items():
            avail = self.adapter.is_tool_available(tool.binary_name)
            status.append({
                "name": tool.name,
                "binary": tool.binary_name,
                "category": tool.category.value,
                "package": tool.kali_package,
                "installed": avail,
                "risk_level": tool.risk_level,
                "description": tool.description,
            })
        return status
