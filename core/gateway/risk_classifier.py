"""
Risk Classifier for Governed Tool Execution (CyberStrikeAI-Inspired)
Classifies tool commands, arguments, and HTTP requests into strict Risk Tiers (0 to 4).
Instantly intercepts and flags destructive, system-wiping, or DoS payloads.
"""
import re
import logging
from typing import Tuple, List

from core.gateway.schemas import RiskTier, ActionProposal

log = logging.getLogger("core.gateway.risk_classifier")


class RiskClassifier:
    """
    مصنف المخاطر الأمني:
    يقوم بتحليل وفحص مقترح الأداة والأوامر المصاحبة وتحديد درجة الخطورة
    ويكشف الأوامر التدميرية والتخريبية فوراً لمنع تشغيلها نهائياً
    """

    # Destructive SQL patterns
    _DESTRUCTIVE_SQL = [
        re.compile(r"\bDROP\s+(DATABASE|SCHEMA|TABLE|VIEW|PROCEDURE)\b", re.I),
        re.compile(r"\bTRUNCATE\s+(TABLE\s+)?[\w`\"\[\]]+", re.I),
        re.compile(r"\bDELETE\s+FROM\s+[\w`\"\[\]]+\s*(;|\Z)", re.I),  # DELETE without WHERE
        re.compile(r"\bALTER\s+TABLE\s+[\w`\"\[\]]+\s+DROP\b", re.I),
    ]

    # Destructive OS/Shell commands
    _DESTRUCTIVE_OS = [
        re.compile(r"\brm\s+(-[a-zA-Z]*[rfRF][a-zA-Z]*\s+)(/|\*|\.\.|~)", re.I),
        re.compile(r"\bmkfs(\.\w+)?\b", re.I),
        re.compile(r"\bdd\s+if=", re.I),
        re.compile(r"\bformat\s+[a-zA-Z]:", re.I),
        re.compile(r"\b(shutdown|reboot|init\s+0|halt|poweroff)\b", re.I),
        re.compile(r":\(\)\s*\{\s*:\|:&\s*\}\s*;\s*:", re.I),  # Fork bomb
        re.compile(r"\bchmod\s+(-R\s+)?777\s+/\b", re.I),
        re.compile(r">\s*/dev/sd[a-z]", re.I),
    ]

    # Severe Denial-of-Service / Exhaustion
    _DESTRUCTIVE_DOS = [
        re.compile(r"(--dos|--flood)\b", re.I),
        re.compile(r"\bbenchmark\s*\(\s*\d{7,}", re.I),
        re.compile(r"\b(pg_)?sleep\s*\(\s*([6-9]\d{2,}|\d{4,})\s*\)", re.I),  # Sleeps > 600s
    ]

    # Passive tools list
    _PASSIVE_TOOLS = {"whois", "dig", "nslookup", "host", "whatweb"}

    # Recon tools list
    _RECON_TOOLS = {
        "nmap", "masscan", "rustscan", "subfinder", "amass",
        "theharvester", "assetfinder", "katana", "httpx", "wafw00f"
    }

    # Probing / Fuzzing tools list
    _PROBE_TOOLS = {
        "ffuf", "sqlmap", "arjun", "dirsearch", "gobuster",
        "dalfox", "nikto", "wpscan", "smartpoc"
    }

    def classify_proposal(self, proposal: ActionProposal) -> Tuple[RiskTier, str]:
        """
        تصنيف المقترح وإرجاع (RiskTier, reason)
        """
        tool = proposal.tool_name.strip().lower()
        args = proposal.command_args or ""
        text_to_scan = f"{tool} {args} {proposal.target} {proposal.rationale}".strip()

        # 1. Check for Destructive flags or patterns (TIER 4)
        if proposal.is_destructive:
            return RiskTier.TIER_4_PROHIBITED_DESTRUCTIVE, "Action explicitly flagged as destructive by caller."

        for pattern in self._DESTRUCTIVE_SQL:
            if pattern.search(text_to_scan):
                matched = pattern.pattern
                log.critical(f"[RiskClassifier] BLOCKED Destructive SQL pattern detected: {matched}")
                return RiskTier.TIER_4_PROHIBITED_DESTRUCTIVE, f"Detected destructive SQL pattern: {matched}"

        for pattern in self._DESTRUCTIVE_OS:
            if pattern.search(text_to_scan):
                matched = pattern.pattern
                log.critical(f"[RiskClassifier] BLOCKED Destructive OS command detected: {matched}")
                return RiskTier.TIER_4_PROHIBITED_DESTRUCTIVE, f"Detected destructive system command: {matched}"

        for pattern in self._DESTRUCTIVE_DOS:
            if pattern.search(text_to_scan):
                matched = pattern.pattern
                log.critical(f"[RiskClassifier] BLOCKED Denial of Service pattern detected: {matched}")
                return RiskTier.TIER_4_PROHIBITED_DESTRUCTIVE, f"Detected denial-of-service / resource exhaustion pattern: {matched}"

        # 2. Check for High-Risk Exploits (TIER 3)
        if proposal.action_type.upper() in ["EXPLOIT", "EXPLOIT_POC"] or any(
            flag in args.lower() for flag in ["--os-shell", "--sql-shell", "--priv-esc", "--upload", "--os-pwn"]
        ):
            return RiskTier.TIER_3_EXPLOIT_POC, "Active PoC exploit or command shell execution requested."

        # 3. Check for Probing / Injection Testing (TIER 2)
        if tool in self._PROBE_TOOLS or proposal.action_type.upper() in ["SMART_POC", "INJECTION_TEST", "FUZZ"]:
            return RiskTier.TIER_2_PROBE, f"Active parameter probe or fuzzing tool '{tool}'."

        # 4. Check for Active Recon (TIER 1)
        if tool in self._RECON_TOOLS or proposal.action_type.upper() in ["PORT_SCAN", "CRAWL", "RECON"]:
            return RiskTier.TIER_1_RECON_ACTIVE, f"Network/web active reconnaissance tool '{tool}'."

        # 5. Check for Passive inspection (TIER 0)
        if tool in self._PASSIVE_TOOLS or proposal.action_type.upper() in ["PASSIVE_ANALYSIS", "DNS", "WHOIS"]:
            return RiskTier.TIER_0_PASSIVE, "Passive read-only inspection."

        # Default fallback: treat unknown tool as TIER 2 Probe for safety
        return RiskTier.TIER_2_PROBE, f"Standard probe classification for '{tool}'."
