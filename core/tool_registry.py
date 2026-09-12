"""
HunterAI Declarative Tool Registry & Capability Matrix
======================================================
Defines all available Kali / Security tools with risk categories,
input/output schemas, and runtime capability matrix gating.
"""
from __future__ import annotations

import logging
import shutil
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("hunter_ai.tool_registry")


class ToolCategory(str, Enum):
    RECON = "recon"
    DNS = "dns"
    HTTP = "http"
    PORTS = "ports"
    CRAWLING = "crawling"
    FUZZING = "fuzzing"
    JAVASCRIPT = "javascript"
    API = "api"
    VULN = "vuln"
    CLOUD = "cloud"
    REPORTING = "reporting"


class RiskLevel(str, Enum):
    LOW = "low"          # Passive, read-only, non-intrusive
    MEDIUM = "medium"    # Active probing, crawling, light port checks
    HIGH = "high"        # Active fuzzing, exploitation tests, injection checks


@dataclass
class ToolDefinition:
    name: str
    purpose: str
    category: ToolCategory
    input_type: str
    output_type: str
    risk: RiskLevel
    requires_authorization: bool
    artifacts: List[str] = field(default_factory=lambda: ["raw", "json"])
    command_template: str = ""
    is_installed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "purpose": self.purpose,
            "category": self.category.value,
            "input_type": self.input_type,
            "output_type": self.output_type,
            "risk": self.risk.value,
            "requires_authorization": self.requires_authorization,
            "artifacts": self.artifacts,
            "command_template": self.command_template,
            "is_installed": self.is_installed,
        }


class CapabilityMatrix:
    """
    Defines the active operational bounds for the agent.
    """

    def __init__(
        self,
        authorized: bool = False,
        allow_destructive: bool = False,
        allow_browser: bool = True,
        allow_terminal: bool = True,
        allow_burp: bool = True,
    ):
        self.terminal = allow_terminal
        self.filesystem_workspace = True
        self.browser = allow_browser
        self.playwright = allow_browser
        self.burp = allow_burp
        self.screenshots = True
        self.local_ollama = True
        self.python = True
        self.git = True
        self.network_recon = True
        self.active_testing = authorized
        self.destructive_actions = allow_destructive  # False by default

    def to_dict(self) -> Dict[str, bool]:
        return {
            "terminal": self.terminal,
            "filesystem_workspace": self.filesystem_workspace,
            "browser": self.browser,
            "playwright": self.playwright,
            "burp": self.burp,
            "screenshots": self.screenshots,
            "local_ollama": self.local_ollama,
            "python": self.python,
            "git": self.git,
            "network_recon": self.network_recon,
            "active_testing": self.active_testing,
            "destructive_actions": self.destructive_actions,
        }


class ToolRegistry:
    """
    Registry of all security and Kali Linux tools with runtime availability detection.
    """

    def __init__(self, capability_matrix: Optional[CapabilityMatrix] = None):
        self.capabilities = capability_matrix or CapabilityMatrix()
        self._tools: Dict[str, ToolDefinition] = {}
        self._register_default_tools()
        self._refresh_installed_status()

    def _register_default_tools(self) -> None:
        defaults = [
            # 1. Recon & DNS
            ToolDefinition("subfinder", "Passive subdomain enumeration", ToolCategory.DNS, "domain", "jsonl", RiskLevel.LOW, False, ["raw", "json"], "subfinder -d {target} -silent -json"),
            ToolDefinition("assetfinder", "Fast asset discovery", ToolCategory.DNS, "domain", "stdout", RiskLevel.LOW, False, ["raw", "txt"], "assetfinder --subs-only {target}"),
            ToolDefinition("dnsx", "Multi-purpose DNS query & resolver", ToolCategory.DNS, "domains_list", "jsonl", RiskLevel.LOW, False, ["raw", "json"], "dnsx -l {input_file} -silent -json"),

            # 2. HTTP & Ports
            ToolDefinition("httpx", "Fast HTTP probing & tech detection", ToolCategory.HTTP, "hosts_list", "jsonl", RiskLevel.LOW, False, ["raw", "json"], "httpx -l {input_file} -silent -json -tech-detect"),
            ToolDefinition("nmap", "Network port scanning & service discovery", ToolCategory.PORTS, "target_or_ip", "xml_txt", RiskLevel.MEDIUM, False, ["raw", "xml", "json"], "nmap -sV -T3 -Pn --top-ports 100 {target}"),
            ToolDefinition("naabu", "Fast SYN port scanner", ToolCategory.PORTS, "target", "stdout", RiskLevel.MEDIUM, False, ["raw", "txt"], "naabu -host {target} -silent"),

            # 3. Crawling & JS
            ToolDefinition("katana", "Modern web crawler and spider", ToolCategory.CRAWLING, "url", "jsonl", RiskLevel.LOW, False, ["raw", "json"], "katana -u {target} -silent -json"),
            ToolDefinition("gau", "Fetch known URLs from AlienVault, Wayback, CommonCrawl", ToolCategory.CRAWLING, "domain", "stdout", RiskLevel.LOW, False, ["raw", "txt"], "gau {target} --subs"),

            # 4. Fuzzing & API
            ToolDefinition("ffuf", "Fast web fuzzer for directory and parameter discovery", ToolCategory.FUZZING, "url_wordlist", "json", RiskLevel.MEDIUM, False, ["raw", "json"], "ffuf -u {target}/FUZZ -w {wordlist} -o {output_file} -of json -s"),

            # 5. Vulnerability & Active Verification (Requires Authorization)
            ToolDefinition("nuclei", "Vulnerability scanner powered by YAML templates", ToolCategory.VULN, "targets_list", "jsonl", RiskLevel.HIGH, True, ["raw", "json"], "nuclei -l {input_file} -silent -jsonl"),
            ToolDefinition("wpscan", "WordPress vulnerability scanner", ToolCategory.VULN, "url", "json", RiskLevel.HIGH, True, ["raw", "json"], "wpscan --url {target} --format json --stealthy"),
            ToolDefinition("sqlmap", "Automatic SQL injection detection & validation", ToolCategory.VULN, "url", "stdout", RiskLevel.HIGH, True, ["raw", "txt"], "sqlmap -u {target} --batch --banner"),
        ]

        for t in defaults:
            self._tools[t.name.lower()] = t

    def _refresh_installed_status(self) -> None:
        """Checks if CLI tools exist in current PATH"""
        for name, tool in self._tools.items():
            tool.is_installed = (shutil.which(name) is not None)

    def get_tool(self, name: str) -> Optional[ToolDefinition]:
        return self._tools.get(name.lower())

    def get_tools_by_category(self, category: ToolCategory) -> List[ToolDefinition]:
        return [t for t in self._tools.values() if t.category == category]

    def is_action_allowed(self, tool_name: str) -> Tuple[bool, Optional[str]]:
        """Verifies if the tool is allowed under current CapabilityMatrix"""
        t = self.get_tool(tool_name)
        if not t:
            return True, None  # Allow custom/unregistered shell tools subject to PolicyGate

        if t.requires_authorization and not self.capabilities.active_testing:
            return False, f"Tool '{t.name}' requires explicit authorization (--authorized flag required)."

        if t.risk == RiskLevel.HIGH and not self.capabilities.active_testing:
            return False, f"High-risk tool '{t.name}' blocked because active testing is not authorized."

        return True, None
