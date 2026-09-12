"""
HunterAI Local Triad Autonomous Agent
======================================
Autonomous Offensive Security & Attack Surface Agent powered EXCLUSIVELY by:
1. WhiteRabbitNeo / Llama-3.1-WhiteRabbitNeo-2-8B (Master Offensive Strategist & Reasoning)
2. xploiter/pentester (Rapid Recon Scout, Triage & Fast Pentesting Assistant)
3. Qwen 2.5 Coder 14B (Code Intelligence, JavaScript Analysis, Parsers & Automation)

100% Local Inference via Ollama (Zero External Cloud Dependencies / Fully Air-Gapped)
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import urllib.request
from typing import Any, Dict, List, Optional

logger = logging.getLogger("hunter_ai.local_triad")

MODEL_OFFENSIVE = "WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest"
MODEL_RECON = "xploiter/pentester:latest"
MODEL_CODE = "qwen2.5-coder:14b"


class LocalTriadAgent:
    """
    Orchestrates the 3-Model Local Triad:
    - Delegates Recon and asset triage to xploiter
    - Delegates Code, JS and AST auditing to Qwen Coder
    - Delegates Exploit reasoning, WAF evasion and Verification to WhiteRabbitNeo
    """

    def __init__(self, ollama_host: Optional[str] = None):
        raw = (ollama_host or os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")).strip().rstrip("/")
        if not raw.startswith("http://") and not raw.startswith("https://"):
            raw = f"http://{raw}"
        raw = raw.replace("://0.0.0.0:", "://127.0.0.1:")
        self.ollama_host = raw

    async def _query_ollama(
        self,
        model: str,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.2,
        timeout: int = 300
    ) -> str:
        """Direct, reliable HTTP query to local Ollama instance"""
        url = f"{self.ollama_host}/api/chat"
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "stream": False,
            "keep_alive": "5m",  # Keep resident for 5 minutes during active workflow
            "options": {
                "temperature": temperature,
                "num_ctx": 4096
            }
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})

        loop = asyncio.get_running_loop()

        def _do_request():
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    res = json.loads(resp.read().decode("utf-8"))
                    return res.get("message", {}).get("content", "").strip()
            except Exception as e:
                logger.error(f"Error querying local model '{model}': {e}")
                return ""

        return await loop.run_in_executor(None, _do_request)

    # ── 1. RECON & FAST TRIAGE SPECIALIST (xploiter/pentester) ─────────────────
    async def triage_recon_assets(self, target: str, subdomains: List[str], ports: List[str], endpoints: List[str]) -> Dict[str, Any]:
        """
        Uses xploiter/pentester to quickly prioritize live assets and surface high-risk targets.
        """
        system = (
            "You are xploiter/pentester, an elite reconnaissance triage specialist and bug bounty assistant. "
            "Analyze discovered assets, filter noise, identify high-priority attack surfaces (APIs, admin portals, auth, uploads), "
            "and suggest quick next-step testing actions. Be concise, actionable, and structured."
        )
        user = f"""Target: {target}
Subdomains ({len(subdomains)}):
{json.dumps(subdomains[:30], indent=2)}

Open Ports ({len(ports)}):
{json.dumps(ports[:20], indent=2)}

Discovered Endpoints ({len(endpoints)}):
{json.dumps(endpoints[:30], indent=2)}

TASK:
1. Identify the TOP 3 most critical targets.
2. Flag suspicious parameters or sensitive paths.
3. List 3 immediate testing steps.
"""
        raw_response = await self._query_ollama(MODEL_RECON, system, user, temperature=0.2)
        return {
            "specialist": "xploiter/pentester",
            "model": MODEL_RECON,
            "analysis": raw_response or "Rapid triage completed."
        }

    # ── 2. CODE AUDITING & JAVASCRIPT SPECIALIST (Qwen 2.5 Coder 14B) ──────────
    async def audit_code_or_javascript(self, js_url: str, code_content: str) -> Dict[str, Any]:
        """
        Uses Qwen 2.5 Coder 14B to deobfuscate, extract endpoints, regex patterns, and secret keys from JS or source code.
        """
        system = (
            "You are Qwen 2.5 Coder 14B, a premier security code auditor and AST analysis expert. "
            "Analyze client-side JavaScript, backend code snippets, or API schemas. "
            "Extract hidden routes, internal endpoints, hardcoded credentials/tokens, and parameter names. "
            "Output clear code snippets and reproduction curls where relevant."
        )
        snippet = code_content[:4000]
        user = f"""Source / File URL: {js_url}

Code Content:
```javascript
{snippet}
```

TASK:
1. Extract any hidden or unlinked API endpoints and URLs.
2. Identify exposed keys, secrets, JWTs, or credentials.
3. Identify dynamic query/body parameters.
4. Provide a structured summary of findings.
"""
        raw_response = await self._query_ollama(MODEL_CODE, system, user, temperature=0.1)
        return {
            "specialist": "Qwen 2.5 Coder 14B",
            "model": MODEL_CODE,
            "analysis": raw_response or "Code audit completed."
        }

    # ── 3. MASTER OFFENSIVE STRATEGIST (WhiteRabbitNeo 8B) ────────────────────
    async def formulate_offensive_strategy(
        self,
        target_url: str,
        param_name: str,
        vuln_type: str,
        context: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Uses WhiteRabbitNeo to design bypass techniques, payload variations, and verification logic.
        """
        system = (
            "You are WhiteRabbitNeo, the master offensive security strategist and expert penetration tester. "
            "Your objective is high-precision vulnerability verification, WAF bypass formulation, and mathematical proof of exploitability. "
            "Focus on non-destructive proofs (arithmetic checks, version extraction, canary reflection). "
            "Never generate destructive or data-wiping commands."
        )
        user = f"""Target URL: {target_url}
Parameter: {param_name}
Vulnerability Class: {vuln_type}
Additional Context: {context or 'Web application endpoint'}

TASK:
1. Formulate 3 context-aware payload variations designed to bypass common WAF filters.
2. Provide a non-destructive verification proof technique (e.g. arithmetic $((41+1)) -> 42 or database @@version).
3. Draft the exact curl command for reproduction.
4. Assess the business impact and CVSS v3.1 vector.
"""
        raw_response = await self._query_ollama(MODEL_OFFENSIVE, system, user, temperature=0.2)
        return {
            "specialist": "WhiteRabbitNeo (8B)",
            "model": MODEL_OFFENSIVE,
            "analysis": raw_response or "Offensive strategy formulated."
        }

    # ── 4. DYNAMIC LOCAL ROUTER (TRIAD ROUTING) ────────────────────────────────
    async def process_prompt(self, user_prompt: str) -> Dict[str, Any]:
        """
        Intelligently routes the user prompt to the best specialist among the 3 local models:
        - Code / JS / Regex / Parser -> Qwen 2.5 Coder
        - Exploits / Bypass / Vulnerability / WAF -> WhiteRabbitNeo
        - Recon / Triage / Checklist / Fast assistant -> xploiter
        """
        low = user_prompt.lower()

        # Check Code & JS first
        if any(w in low for w in ["javascript", "js", "code", "regex", "parser", "ast", "deobfuscate", "function", "token", "secret"]):
            system = "You are Qwen 2.5 Coder 14B, specialized in security code analysis, AST parsing, and automation."
            resp = await self._query_ollama(MODEL_CODE, system, user_prompt, temperature=0.1)
            return {
                "assigned_model": MODEL_CODE,
                "role": "Code Intelligence & JS Auditor (Qwen 2.5 Coder 14B)",
                "response": resp
            }

        # Check Offensive Exploitation & Bypass
        if any(w in low for w in ["exploit", "sqli", "injection", "bypass", "waf", "rce", "ssrf", "xss", "payload", "verify", "cvss"]):
            system = "You are WhiteRabbitNeo, the master offensive security and pentest reasoning strategist."
            resp = await self._query_ollama(MODEL_OFFENSIVE, system, user_prompt, temperature=0.2)
            return {
                "assigned_model": MODEL_OFFENSIVE,
                "role": "Master Offensive Strategist (WhiteRabbitNeo 8B)",
                "response": resp
            }

        # Default to Recon / Pentest Assistant
        system = "You are xploiter/pentester, an ultra-fast security assistant for recon triage and penetration testing steps."
        resp = await self._query_ollama(MODEL_RECON, system, user_prompt, temperature=0.2)
        return {
            "assigned_model": MODEL_RECON,
            "role": "Recon Scout & Pentest Assistant (xploiter/pentester)",
            "response": resp
        }


# Global singleton instance
triad_agent = LocalTriadAgent()
