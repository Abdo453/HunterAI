"""
HunterAI Tool Command Synthesizer (AI-Driven Adaptive Tool Execution)
====================================================================
Synthesizes dynamic CLI command lines for any security tool based on:
  1. Target nature (Domain, URL, IP, CIDR, REST API endpoint)
  2. Detected WAF Profile (Cloudflare, Akamai, CloudFront, AWS WAF, etc.)
  3. Technology Stack (PHP, Node.js, Spring, WordPress, Laravel, Nginx, Apache)
  4. Open Ports & Services (80, 443, 8080, 8443, 3000, 5000)
  5. Authentication Context (Tokens, Session Cookies, Custom Headers)
  6. Operational Safety Policy (Non-destructive invariants, scope limits)
"""
from __future__ import annotations

import json
import logging
import os
import re
import shlex
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from core.arsenal.kali_catalog import ToolCategory, ToolDefinition

logger = logging.getLogger("hunter_ai.arsenal.synthesizer")


def resolve_kali_wordlist(category: str = "web_content") -> str:
    """
    Intelligently discovers existing wordlists on Kali Linux, Debian, or local repository.
    Falls back to auto-generating a minimal seed list so fuzzers never crash.
    """
    candidates = [
        # Standard Kali / SecLists paths
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
        "/usr/share/wordlists/wfuzz/general/common.txt",
        # Local repository path
        "data/wordlists/common.txt",
        "wordlists/common.txt",
    ]
    for p in candidates:
        if Path(p).is_file():
            return p

    # Ensure local directory & seed fallback wordlist
    fallback_dir = Path("data") / "wordlists"
    fallback_file = fallback_dir / "common.txt"
    try:
        if not fallback_file.is_file():
            fallback_dir.mkdir(parents=True, exist_ok=True)
            seeds = [
                "admin", "api", "v1", "v2", "v3", "login", "dashboard", "portal",
                "auth", "users", "profile", "config", "backup", "db", "test",
                ".env", ".git", ".well-known", "swagger", "openapi.json", "graphql",
                "internal", "private", "metrics", "health", "status", "server-status",
                "upload", "uploads", "files", "static", "assets", "debug", "actuator",
            ]
            fallback_file.write_text("\n".join(seeds) + "\n", encoding="utf-8")
        return str(fallback_file)
    except Exception:
        return "common.txt"


def resolve_kali_params_wordlist() -> str:
    """Discovers parameter discovery wordlists on Kali Linux."""
    candidates = [
        "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
        "/usr/share/seclists/Discovery/Web-Content/api/objects.txt",
        "data/wordlists/params.txt",
    ]
    for p in candidates:
        if Path(p).is_file():
            return p
    fallback = Path("data") / "wordlists" / "params.txt"
    try:
        if not fallback.is_file():
            fallback.parent.mkdir(parents=True, exist_ok=True)
            fallback.write_text("id\nuser\nadmin\nfile\npath\nurl\nredirect\ntoken\nkey\ncmd\nexec\n", encoding="utf-8")
        return str(fallback)
    except Exception:
        return "params.txt"


def is_root_privileged() -> bool:
    """Returns True if running as root/UID 0 on POSIX systems."""
    try:
        return os.geteuid() == 0
    except (AttributeError, Exception):
        return False


@dataclass
class TargetContext:
    """Rich situational context of the target presented to the tool."""
    target: str
    waf_name: Optional[str] = None
    tech_stack: List[str] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    auth_headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    rate_limit_per_sec: Optional[int] = None
    proxy: Optional[str] = None
    goal: str = "comprehensive_safe_audit"
    extra: Dict[str, Any] = field(default_factory=dict)

    @property
    def clean_host(self) -> str:
        t = self.target.replace("https://", "").replace("http://", "").split("/")[0]
        return t.split(":")[0]

    @property
    def is_url(self) -> bool:
        return self.target.startswith("http://") or self.target.startswith("https://")

    @property
    def has_waf(self) -> bool:
        return bool(self.waf_name and self.waf_name.lower() not in ["none", "unknown", ""])


@dataclass
class SynthesizedCommand:
    """Command specification synthesized by AI reasoning."""
    tool_name: str
    binary_name: str
    args: List[str]
    command_line: str
    ai_reasoning: str
    evasion_strategy: str
    context_signals_used: List[str]
    risk_level: str
    is_safe: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AIToolCommandSynthesizer:
    """
    Cognitive engine that synthesizes the most effective and safe CLI command for any tool.
    Operates in two modes:
      - LLM Reasoning (when LLM provider is active)
      - Context-Aware Rulebook (instant, hermetic, 100% reliable offline)
    """

    # Forbidden arguments that violate non-destructive safety policy
    DANGEROUS_FLAGS_BLACKLIST = {
        "--os-shell", "--os-pwn", "--os-cmd", "--sql-shell", "--dump-all",
        "-D", "--drop", "--delete", "--purge", "--rm", "rm -rf", ";", "|", "`",
        "$("
    }

    @classmethod
    async def synthesize(
        cls,
        tool_def: ToolDefinition,
        context: TargetContext,
        use_llm: bool = True,
    ) -> SynthesizedCommand:
        """Synthesizes tool arguments using LLM reasoning with rulebook fallback."""
        if use_llm:
            try:
                llm_res = await cls._llm_synthesize(tool_def, context)
                if llm_res and llm_res.args:
                    return llm_res
            except Exception as exc:
                logger.debug("[CommandSynthesizer] LLM synthesis note: %s; using rulebook", exc)

        return cls._heuristic_synthesize(tool_def, context)

    @classmethod
    def synthesize_sync(
        cls,
        tool_def: ToolDefinition,
        context: TargetContext,
    ) -> SynthesizedCommand:
        """Synchronous deterministic synthesis for offline and performance-critical loops."""
        return cls._heuristic_synthesize(tool_def, context)

    # ── 1. LLM-Driven Synthesis ───────────────────────────────────────────────

    @classmethod
    async def _llm_synthesize(
        cls,
        tool_def: ToolDefinition,
        context: TargetContext,
    ) -> Optional[SynthesizedCommand]:
        from core.ai_reasoning_core import AIReasoningCore

        waf_info = context.waf_name or "None detected"
        tech_info = ", ".join(context.tech_stack) if context.tech_stack else "Generic/Unknown"
        ports_info = ", ".join(map(str, context.open_ports)) if context.open_ports else "Default"

        prompt = (
            f"You are the Tactical CLI Command Synthesizer for security tool '{tool_def.name}'.\n"
            f"Binary: {tool_def.binary_name}\n"
            f"Category: {tool_def.category.value}\n"
            f"Default Flags: {' '.join(tool_def.default_args)}\n\n"
            f"TARGET SITUATIONAL CONTEXT:\n"
            f"- Target: {context.target}\n"
            f"- WAF Detected: {waf_info}\n"
            f"- Tech Stack: {tech_info}\n"
            f"- Open Ports: {ports_info}\n"
            f"- Goal: {context.goal}\n\n"
            f"Generate the exact customized command arguments list (flags) for this specific target.\n"
            f"Strict Requirements:\n"
            f"1. Tailor flags to the detected tech stack, open ports, and WAF evasion needs.\n"
            f"2. Enforce non-destructive safety (no data modification, safe rate limits).\n"
            f"3. Return JSON ONLY with this structure:\n"
            f"{{\n"
            f'  "reasoning": "Why these flags were chosen based on the target context",\n'
            f'  "evasion_strategy": "WAF / rate-limit evasion explanation",\n'
            f'  "args": ["flag1", "val1", "flag2", ...]\n'
            f"}}"
        )
        sys_prompt = "You are a senior red team operator. Output strictly valid JSON with safe, optimal CLI flags."
        raw = await AIReasoningCore.ask_ai(prompt, system_prompt=sys_prompt)
        if not raw:
            return None

        # Parse JSON
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        if not m:
            return None
        data = json.loads(m.group(0))
        raw_args = data.get("args", [])
        if not isinstance(raw_args, list):
            return None

        sanitized_args = cls._sanitize_args(tool_def, raw_args, context.target)
        cmd_str = f"{tool_def.binary_name} {' '.join(sanitized_args)}"

        signals = []
        if context.has_waf:
            signals.append(f"WAF:{context.waf_name}")
        if context.tech_stack:
            signals.append(f"Tech:{','.join(context.tech_stack[:3])}")
        if context.open_ports:
            signals.append(f"Ports:{len(context.open_ports)}")

        return SynthesizedCommand(
            tool_name=tool_def.name,
            binary_name=tool_def.binary_name,
            args=sanitized_args,
            command_line=cmd_str,
            ai_reasoning=data.get("reasoning", "Synthesized via AI LLM context analysis."),
            evasion_strategy=data.get("evasion_strategy", "Adaptive evasion tailored to target."),
            context_signals_used=signals,
            risk_level=tool_def.risk_level,
            is_safe=True,
        )

    # ── 2. Heuristic Context-Aware Rulebook (Hermetic & Instant) ───────────────

    @classmethod
    def _heuristic_synthesize(
        cls,
        tool_def: ToolDefinition,
        context: TargetContext,
    ) -> SynthesizedCommand:
        name = tool_def.name.lower()
        target = context.target
        clean_host = context.clean_host
        args: List[str] = []
        reasoning_points: List[str] = []
        evasion = "Standard safe scan profile"
        signals: List[str] = []

        # ── NMAP / NAABU / MASSCAN ────────────────────────────────────────────
        if name in ["nmap", "naabu", "masscan"]:
            args.append(clean_host)
            signals.append("NetworkDiscovery")

            # Port tailoring
            if context.open_ports:
                port_str = ",".join(map(str, sorted(context.open_ports[:20])))
                args.extend(["-p", port_str])
                reasoning_points.append(f"Targeting confirmed active ports: {port_str}")
            else:
                args.extend(["-p", "80,443,8080,8443,3000,5000,8000,8888"])
                reasoning_points.append("Targeting standard HTTP/web service port surface")

            # WAF & Timing Adaptation
            if context.has_waf:
                args.extend(["-T2", "-Pn", "--randomize-hosts"])
                evasion = f"Polite timing (-T2) + host randomization for WAF ({context.waf_name})"
                reasoning_points.append(f"Evasion mode engaged for perimeter WAF: {context.waf_name}")
                signals.append(f"WAF:{context.waf_name}")
            else:
                args.extend(["-T4", "-Pn"])
                reasoning_points.append("Standard aggressive timing (-T4) with no-ping (-Pn)")

            # Service Version detection
            args.extend(["-sV", "--version-light"])

            # Privilege-aware scanning (Kali / POSIX)
            if hasattr(os, "geteuid"):
                if not is_root_privileged():
                    args.append("-sT")
                    reasoning_points.append("Non-root environment: using TCP Connect scan (-sT)")
                    signals.append("NonRoot:sT")
                else:
                    args.append("-sS")
                    reasoning_points.append("Root privilege active: engaging high-speed SYN scan (-sS)")
                    signals.append("Root:sS")

        # ── NUCLEI ────────────────────────────────────────────────────────────
        elif name == "nuclei":
            args.extend(["-u", target if context.is_url else f"https://{target}"])
            args.extend(["-silent", "-no-interactsh"])

            # Tech stack template tailoring
            tech_tags = []
            for t in context.tech_stack:
                tl = t.lower()
                if "wordpress" in tl or "wp" in tl:
                    tech_tags.extend(["wordpress", "wp-plugin"])
                elif "php" in tl:
                    tech_tags.append("php")
                elif "laravel" in tl:
                    tech_tags.append("laravel")
                elif "node" in tl or "express" in tl:
                    tech_tags.append("nodejs")
                elif "spring" in tl or "java" in tl:
                    tech_tags.extend(["spring", "springboot"])
                elif "apache" in tl:
                    tech_tags.append("apache")
                elif "nginx" in tl:
                    tech_tags.append("nginx")

            if tech_tags:
                tag_str = ",".join(set(tech_tags))
                args.extend(["-tags", tag_str])
                reasoning_points.append(f"Tailored vulnerability templates to detected tech: {tag_str}")
                signals.append(f"TechTags:{tag_str}")
            else:
                args.extend(["-tags", "cve,misconfig,exposure"])
                reasoning_points.append("Scanning high-priority CVE and misconfiguration templates")

            # Severity filter
            args.extend(["-severity", "medium,high,critical"])

            # WAF Throttling
            if context.has_waf:
                args.extend(["-rate-limit", "15", "-concurrency", "5", "-H", "X-Forwarded-For: 127.0.0.1"])
                evasion = "Strict rate-limiting (15 req/s) + header spoofing for WAF"
                signals.append(f"WAF:{context.waf_name}")
            else:
                args.extend(["-rate-limit", "50"])

        # ── FFUF / GOBUSTER / FEROXBUSTER / DIRSEARCH ─────────────────────────
        elif name in ["ffuf", "gobuster", "feroxbuster", "dirsearch"]:
            target_url = target if context.is_url else f"https://{target}"
            wl_path = resolve_kali_wordlist()
            if name == "ffuf":
                args.extend(["-u", f"{target_url.rstrip('/')}/FUZZ"])
                args.extend(["-w", wl_path])
                args.extend(["-mc", "200,204,301,302,307,401,403"])

                # Extension tailoring based on tech stack
                exts = []
                for t in context.tech_stack:
                    tl = t.lower()
                    if "php" in tl or "wordpress" in tl or "laravel" in tl:
                        exts.extend([".php", ".phtml"])
                    elif "node" in tl or "express" in tl or "react" in tl or "next" in tl:
                        exts.extend([".json", ".js"])
                    elif "spring" in tl or "java" in tl:
                        exts.extend([".jsp", ".action"])

                if exts:
                    ext_str = ",".join(set(exts))
                    args.extend(["-e", ext_str])
                    reasoning_points.append(f"Fuzzing extensions matched to backend: {ext_str}")
                    signals.append(f"Exts:{ext_str}")

                # Rate limiting
                if context.has_waf:
                    args.extend(["-rate", "12", "-p", "0.2"])
                    evasion = "Throttled fuzzing rate (12 req/s) with 200ms delay"
                    signals.append(f"WAF:{context.waf_name}")
                else:
                    args.extend(["-rate", "40"])
            else:
                args.extend(["-u", target_url])
                args.extend(["-w", wl_path])
                reasoning_points.append(f"Directory enumeration using wordlist: {wl_path}")

        # ── SQLMAP ────────────────────────────────────────────────────────────
        elif name == "sqlmap":
            target_url = target if context.is_url else f"https://{target}"
            args.extend(["-u", target_url, "--batch", "--random-agent", "--risk=1", "--level=1"])
            reasoning_points.append("Safe non-destructive baseline verification (Risk 1, Level 1)")

            # DBMS tailoring
            for t in context.tech_stack:
                tl = t.lower()
                if "mysql" in tl or "mariadb" in tl:
                    args.extend(["--dbms", "mysql"])
                    reasoning_points.append("Tailored SQL payloads to MySQL/MariaDB")
                elif "postgres" in tl or "pgsql" in tl:
                    args.extend(["--dbms", "postgresql"])
                    reasoning_points.append("Tailored SQL payloads to PostgreSQL")

            # WAF tamper script
            if context.has_waf:
                args.extend(["--tamper=space2comment,randomcase", "--delay=1"])
                evasion = "WAF tamper script space2comment + 1-second delay"
                signals.append(f"WAF:{context.waf_name}")

        # ── DALFOX ────────────────────────────────────────────────────────────
        elif name == "dalfox":
            target_url = target if context.is_url else f"https://{target}"
            args.extend(["url", target_url, "--silence"])
            if context.has_waf:
                args.extend(["--waf-evasion", "--delay", "500"])
                evasion = "Dalfox WAF evasion transforms + 500ms delay"
                signals.append(f"WAF:{context.waf_name}")
            reasoning_points.append("DOM & Reflected XSS parameter verification")

        # ── HTTPX ─────────────────────────────────────────────────────────────
        elif name == "httpx":
            args.extend(["-u", target if context.is_url else f"https://{target}"])
            args.extend(["-status-code", "-title", "-tech-detect", "-content-length", "-silent"])
            reasoning_points.append("High-speed HTTP probing with technology detection")

        # ── SUBFINDER / AMASS / ASSETFINDER ───────────────────────────────────
        elif name in ["subfinder", "amass", "assetfinder"]:
            args.extend(["-d", clean_host, "-silent"])
            reasoning_points.append("Passive OSINT subdomain enumeration without perimeter alerts")

        # ── KATANA / CRAWLER ──────────────────────────────────────────────────
        elif name in ["katana", "gospider"]:
            target_url = target if context.is_url else f"https://{target}"
            args.extend(["-u", target_url, "-depth", "3", "-silent"])
            if context.has_waf:
                args.extend(["-rate-limit", "20"])
                evasion = "Spidering rate-limit capped at 20 req/s"
            reasoning_points.append("Dynamic web crawl discovering endpoints and hidden forms")

        # ── WAFW00F ───────────────────────────────────────────────────────────
        elif name == "wafw00f":
            target_url = target if context.is_url else f"https://{target}"
            args.extend([target_url, "-a"])
            reasoning_points.append("Aggressive fingerprinting of all known WAF signatures")

        # ── ARJUN / X8 ────────────────────────────────────────────────────────
        elif name in ["arjun", "x8"]:
            target_url = target if context.is_url else f"https://{target}"
            if name == "x8":
                args.extend(["-u", target_url, "-w", resolve_kali_params_wordlist()])
            else:
                args.extend(["-u", target_url, "--passive"])
            reasoning_points.append("Hidden HTTP parameter discovery")

        # ── DEFAULT / FALLBACK FOR ANY OTHER KALI TOOL ────────────────────────
        else:
            for da in tool_def.default_args:
                if "{target}" in da:
                    args.append(da.replace("{target}", target))
                else:
                    args.append(da)
            reasoning_points.append("Standard calibrated default flags applied")

        # Upstream Burp / HTTP Proxy integration
        if context.proxy:
            proxy_url = context.proxy
            if name == "nuclei":
                args.extend(["-proxy", proxy_url])
            elif name == "ffuf":
                args.extend(["-x", proxy_url])
            elif name == "sqlmap":
                args.extend([f"--proxy={proxy_url}"])
            elif name == "httpx":
                args.extend(["-http-proxy", proxy_url])
            elif name == "dalfox":
                args.extend(["--proxy", proxy_url])
            elif name in ["katana", "gospider"]:
                args.extend(["-proxy", proxy_url])
            reasoning_points.append(f"Routing traffic through proxy: {proxy_url}")
            signals.append(f"Proxy:{proxy_url}")

        # Ingest auth headers/cookies if tool supports headers
        if context.auth_headers and name in ["nuclei", "ffuf", "httpx", "dalfox", "katana"]:
            for hk, hv in context.auth_headers.items():
                if hk.lower() in ["authorization", "x-api-key"]:
                    args.extend(["-H", f"{hk}: {hv}"])
                    reasoning_points.append(f"Injected authenticated header: {hk}")

        sanitized_args = cls._sanitize_args(tool_def, args, context.target)
        cmd_str = f"{tool_def.binary_name} {' '.join(sanitized_args)}"
        reasoning_text = " | ".join(reasoning_points) if reasoning_points else "Optimized execution parameters."

        return SynthesizedCommand(
            tool_name=tool_def.name,
            binary_name=tool_def.binary_name,
            args=sanitized_args,
            command_line=cmd_str,
            ai_reasoning=reasoning_text,
            evasion_strategy=evasion,
            context_signals_used=signals,
            risk_level=tool_def.risk_level,
            is_safe=True,
        )

    # ── 3. Safety Sanitization & Policy Filter ────────────────────────────────

    @classmethod
    def _sanitize_args(
        cls,
        tool_def: ToolDefinition,
        raw_args: List[str],
        target: str,
    ) -> List[str]:
        """Ensures synthesized arguments do not violate safety policy or contain injection vectors."""
        sanitized: List[str] = []
        for arg in raw_args:
            arg_clean = arg.strip()
            # Drop dangerous or shell-injection tokens
            if any(bad in arg_clean for bad in cls.DANGEROUS_FLAGS_BLACKLIST):
                logger.warning("[CommandSynthesizer] Dropped dangerous flag: %s", arg_clean)
                continue
            sanitized.append(arg_clean)

        return sanitized
