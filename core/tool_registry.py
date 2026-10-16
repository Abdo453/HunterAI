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
from typing import Any, Dict, List, Optional, Set, Tuple

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

    def __init__(self, capability_matrix: Optional[CapabilityMatrix] = None, config_path: Optional[str] = None):
        self.capabilities = capability_matrix or CapabilityMatrix()
        self.config_path = config_path or "config/tools.json"
        self._tools: Dict[str, ToolDefinition] = {}
        self.tool_metadata: Dict[str, Dict[str, Any]] = {}
        self.usage_log: List[Dict[str, Any]] = []
        self._register_default_tools()
        self._load_config_metadata()
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
            ToolDefinition("burp_scanner", "Burp Suite automated scanner integration", ToolCategory.VULN, "url", "json", RiskLevel.MEDIUM, True, ["raw", "json"], "burp --scan {target}"),
        ]

        for t in defaults:
            self._tools[t.name.lower()] = t

    def _load_config_metadata(self) -> None:
        """Loads additional tool metadata and permissions from config/tools.json if present"""
        import json
        from pathlib import Path
        cfg_file = Path(self.config_path)
        if cfg_file.exists():
            try:
                data = json.loads(cfg_file.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    for item in data:
                        tool_id = item.get("id") or item.get("name")
                        if tool_id:
                            self.tool_metadata[tool_id.lower()] = item
            except Exception as e:
                logger.warning("Could not read tools config from %s: %s", self.config_path, e)

    def _refresh_installed_status(self) -> None:
        """Checks if CLI tools exist in current PATH"""
        for name, tool in self._tools.items():
            tool.is_installed = (shutil.which(name) is not None)

    def discover_tools(self) -> Dict[str, Dict[str, Any]]:
        """Scans environment and configuration for valid tools"""
        self._refresh_installed_status()
        self._load_config_metadata()
        discovered: Dict[str, Dict[str, Any]] = {}
        
        # Tools in definitions
        for name, t in self._tools.items():
            meta = self.tool_metadata.get(name, {})
            discovered[name] = {
                "id": name,
                "name": t.name,
                "purpose": t.purpose,
                "category": t.category.value,
                "risk": t.risk.value,
                "is_installed": t.is_installed,
                "requires_authorization": t.requires_authorization,
                "permissions": meta.get("permissions", ["recon" if t.risk == RiskLevel.LOW else "active_testing"]),
                "type": meta.get("type", "security"),
            }
            
        # Any additional from config
        for tool_id, meta in self.tool_metadata.items():
            if tool_id not in discovered:
                discovered[tool_id] = {
                    "id": tool_id,
                    "name": meta.get("name", tool_id),
                    "purpose": meta.get("purpose", ""),
                    "category": meta.get("category", "recon"),
                    "risk": meta.get("risk", "low"),
                    "is_installed": shutil.which(tool_id) is not None,
                    "requires_authorization": meta.get("requires_authorization", False),
                    "permissions": meta.get("permissions", ["recon"]),
                    "type": meta.get("type", "security"),
                }
        return discovered

    def check_permissions(self, tool_id: str, project_permissions: Optional[List[str]] = None) -> Tuple[bool, Optional[str]]:
        """Enforces project-scoped access and capability matrix gating"""
        tool_key = tool_id.lower()
        t = self.get_tool(tool_key)
        meta = self.tool_metadata.get(tool_key, {})
        
        # Capability matrix check
        allowed_by_cap, reason = self.is_action_allowed(tool_key)
        if not allowed_by_cap:
            return False, reason
            
        # Project-scoped permissions check
        if project_permissions is not None:
            tool_perms = meta.get("permissions", ["recon" if (t and t.risk == RiskLevel.LOW) else "active_testing"])
            # If tool requires a permission that project doesn't have, block
            if not any(p in project_permissions for p in tool_perms):
                return False, f"Project lacks required permissions {tool_perms} for tool '{tool_id}'."
                
        return True, None

    def log_tool_usage(
        self,
        tool_id: str,
        action: str,
        status: str = "SUCCESS",
        project_id: str = "default",
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Audits tool execution into runtime usage log"""
        import time
        entry = {
            "timestamp": time.time(),
            "tool_id": tool_id,
            "action": action,
            "status": status,
            "project_id": project_id,
            "details": details or {},
        }
        self.usage_log.append(entry)
        logger.info("Tool usage audited: tool=%s action=%s status=%s project=%s", tool_id, action, status, project_id)
        return entry

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
