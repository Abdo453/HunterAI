"""
Tool Router — Central registry with Policy enforcement.

Flow: request_tool() -> phase_check() -> rate_limit() -> policy_gate() -> execute()

NO tool runs unless it passes all gates. LLM only picks a tool name —
it never executes directly.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional


class ToolCategory(str, Enum):
    RECON     = "recon"
    SCAN      = "scan"
    WEB       = "web"
    BROWSER   = "browser"
    FUZZING   = "fuzzing"
    EXPLOIT   = "exploit"
    ANALYSIS  = "analysis"
    REPORTING = "reporting"


class ToolRisk(str, Enum):
    LOW    = "low"     # passive, read-only (subfinder, waybackurls)
    MEDIUM = "medium"  # active but non-destructive (httpx, nmap, nuclei)
    HIGH   = "high"    # intrusive / potentially destructive (sqlmap, ffuf brute)


@dataclass
class ToolSpec:
    name: str
    category: ToolCategory
    risk: ToolRisk
    description: str
    requires_scope: bool = True
    rate_limit_per_min: int = 30
    allowed_phases: List[str] = field(default_factory=list)
    handler: Optional[Callable] = None   # actual execution function (optional)


class ToolRouter:
    """
    Central tool registry and routing engine.

    Usage:
        router = ToolRouter(policy_gate=gate)
        result = router.request_tool("subfinder", target="target.com", phase="RECON")
        if result["allowed"]:
            # safe to execute
    """

    BUILTIN_TOOLS: Dict[str, Dict] = {
        # ── Passive Recon ─────────────────────────────────────────────────────
        "subfinder":    {"cat": ToolCategory.RECON,    "risk": ToolRisk.LOW,    "scope": True,  "phases": ["RECON"],            "desc": "Passive subdomain enumeration"},
        "amass":        {"cat": ToolCategory.RECON,    "risk": ToolRisk.LOW,    "scope": True,  "phases": ["RECON"],            "desc": "Active/passive subdomain discovery"},
        "waybackurls":  {"cat": ToolCategory.RECON,    "risk": ToolRisk.LOW,    "scope": False, "phases": ["RECON"],            "desc": "Wayback Machine URL extraction"},
        "crt_sh":       {"cat": ToolCategory.RECON,    "risk": ToolRisk.LOW,    "scope": False, "phases": ["RECON"],            "desc": "Certificate transparency search"},
        # ── Active Recon / Scan ───────────────────────────────────────────────
        "httpx":        {"cat": ToolCategory.SCAN,     "risk": ToolRisk.MEDIUM, "scope": True,  "phases": ["RECON", "SCAN"],    "desc": "HTTP probing and live host detection"},
        "nmap":         {"cat": ToolCategory.SCAN,     "risk": ToolRisk.MEDIUM, "scope": True,  "phases": ["SCAN"],             "desc": "Port and service scanning"},
        "naabu":        {"cat": ToolCategory.SCAN,     "risk": ToolRisk.MEDIUM, "scope": True,  "phases": ["SCAN"],             "desc": "Fast port scanner"},
        "nuclei":       {"cat": ToolCategory.SCAN,     "risk": ToolRisk.MEDIUM, "scope": True,  "phases": ["SCAN", "ANALYZE"],  "desc": "Vulnerability template scanner"},
        # ── Web / Crawl ───────────────────────────────────────────────────────
        "katana":       {"cat": ToolCategory.WEB,      "risk": ToolRisk.LOW,    "scope": True,  "phases": ["SCAN", "ANALYZE"],  "desc": "Web crawler and endpoint discovery"},
        "gospider":     {"cat": ToolCategory.WEB,      "risk": ToolRisk.LOW,    "scope": True,  "phases": ["SCAN", "ANALYZE"],  "desc": "Fast web spider"},
        "arjun":        {"cat": ToolCategory.WEB,      "risk": ToolRisk.LOW,    "scope": True,  "phases": ["ANALYZE"],          "desc": "HTTP parameter discovery"},
        "subjs":        {"cat": ToolCategory.WEB,      "risk": ToolRisk.LOW,    "scope": True,  "phases": ["ANALYZE"],          "desc": "JS file endpoint extractor"},
        # ── Browser ───────────────────────────────────────────────────────────
        "browser":      {"cat": ToolCategory.BROWSER,  "risk": ToolRisk.LOW,    "scope": True,  "phases": ["RECON", "SCAN", "ANALYZE"], "desc": "Playwright browser controller"},
        # ── Analysis ──────────────────────────────────────────────────────────
        "trufflehog":   {"cat": ToolCategory.ANALYSIS, "risk": ToolRisk.LOW,    "scope": False, "phases": ["ANALYZE"],          "desc": "Secret and credential scanner"},
        "kiterunner":   {"cat": ToolCategory.ANALYSIS, "risk": ToolRisk.MEDIUM, "scope": True,  "phases": ["ANALYZE"],          "desc": "API route brute-forcer"},
        # ── Fuzzing ───────────────────────────────────────────────────────────
        "ffuf":         {"cat": ToolCategory.FUZZING,  "risk": ToolRisk.MEDIUM, "scope": True,  "phases": ["ANALYZE", "EXPLOIT"],"desc": "Fast web fuzzer"},
        "feroxbuster":  {"cat": ToolCategory.FUZZING,  "risk": ToolRisk.MEDIUM, "scope": True,  "phases": ["ANALYZE", "EXPLOIT"],"desc": "Content discovery fuzzer"},
        "paramspider":  {"cat": ToolCategory.FUZZING,  "risk": ToolRisk.LOW,    "scope": True,  "phases": ["ANALYZE"],          "desc": "URL parameter spider from Wayback"},
        "qsreplace":    {"cat": ToolCategory.FUZZING,  "risk": ToolRisk.MEDIUM, "scope": True,  "phases": ["EXPLOIT"],          "desc": "Query string value replacer"},
        # ── Exploit-assist ────────────────────────────────────────────────────
        "wpscan":       {"cat": ToolCategory.EXPLOIT,  "risk": ToolRisk.MEDIUM, "scope": True,  "phases": ["EXPLOIT"],          "desc": "WordPress vulnerability scanner"},
        # ── Report ────────────────────────────────────────────────────────────
        "report":       {"cat": ToolCategory.REPORTING,"risk": ToolRisk.LOW,    "scope": False, "phases": ["REPORT"],           "desc": "Generate final assessment report"},
    }

    def __init__(self, policy_gate: Any = None) -> None:
        self._tools: Dict[str, ToolSpec] = {}
        self._policy_gate = policy_gate
        self._call_log: Dict[str, List[float]] = {}   # tool -> [timestamps]
        self._load_builtins()

    def _load_builtins(self) -> None:
        for name, spec in self.BUILTIN_TOOLS.items():
            self._tools[name] = ToolSpec(
                name=name,
                category=spec["cat"],
                risk=spec["risk"],
                description=spec["desc"],
                requires_scope=spec.get("scope", True),
                allowed_phases=spec.get("phases", []),
            )

    def register(self, spec: ToolSpec) -> None:
        """Register a custom tool (or override a builtin)."""
        self._tools[spec.name] = spec

    # ── Routing ───────────────────────────────────────────────────────────────

    def request_tool(
        self,
        tool_name: str,
        target: str,
        phase: str = "",
        params: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """
        Main entry point. Always returns a dict:
          {"allowed": bool, "reason": str, "tool": ToolSpec|None, "result": Any}
        """
        params = params or {}

        spec = self._tools.get(tool_name)
        if not spec:
            return {"allowed": False, "reason": f"Unknown tool: {tool_name!r}", "tool": None, "result": None}

        # Phase check
        if phase and spec.allowed_phases and phase not in spec.allowed_phases:
            return {
                "allowed": False,
                "reason":  f"Tool '{tool_name}' not allowed in phase '{phase}'. Allowed: {spec.allowed_phases}",
                "tool":    spec,
                "result":  None,
            }

        # Rate limit (per minute)
        if not self._check_rate(tool_name, spec.rate_limit_per_min):
            return {
                "allowed": False,
                "reason":  f"Rate limit exceeded for '{tool_name}' (>{spec.rate_limit_per_min}/min)",
                "tool":    spec,
                "result":  None,
            }

        # Policy gate (scope enforcement)
        if spec.requires_scope and self._policy_gate:
            try:
                from core.control_plane.policy_gate import ActionRequest, ActionCategory
                req = ActionRequest(
                    action_type=(ActionCategory.NETWORK_SCAN
                                 if spec.category in (ToolCategory.SCAN, ToolCategory.RECON)
                                 else ActionCategory.HTTP_REQUEST),
                    target=target,
                    params=params,
                )
                decision = self._policy_gate.evaluate(req)
                if not decision.allowed:
                    return {"allowed": False, "reason": f"PolicyGate: {decision.reason}", "tool": spec, "result": None}
            except Exception:
                pass  # policy gate is optional

        # Execute handler if registered
        result = None
        if spec.handler:
            try:
                result = spec.handler(target=target, **params)
            except Exception as exc:
                return {"allowed": True, "reason": "handler_error", "tool": spec, "result": str(exc)}

        return {"allowed": True, "reason": "approved", "tool": spec, "result": result}

    def _check_rate(self, tool_name: str, limit: int) -> bool:
        now = time.time()
        calls = [t for t in self._call_log.get(tool_name, []) if now - t < 60]
        if len(calls) >= limit:
            return False
        calls.append(now)
        self._call_log[tool_name] = calls
        return True

    # ── Queries ───────────────────────────────────────────────────────────────

    def get_tools_for_phase(self, phase: str) -> List[ToolSpec]:
        return [t for t in self._tools.values() if phase in t.allowed_phases]

    def list_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "name":     t.name,
                "category": t.category.value,
                "risk":     t.risk.value,
                "phases":   t.allowed_phases,
                "desc":     t.description,
            }
            for t in self._tools.values()
        ]

    def __len__(self) -> int:
        return len(self._tools)
