"""
HunterAI Web Scanners — Real Delegation to ``ABHToolBridge`` / ``bughunter.tools.*``
=====================================================================================
Replaces all legacy simulated scanner stubs with real delegation to
``hunter_ai.tools.abh_bridge.ABHToolBridge`` and ``bughunter.tools.*``.

Truthfulness invariant: NEVER fabricates findings when an external tool,
headless browser, or target is unavailable or denied by SSRF/scope policy.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from hunter_ai.tools.abh_bridge import ABHToolBridge


class CORSScanner:
    """CORS misconfiguration scanner delegated to ``bughunter.tools.cors_scanner``."""

    def scan(self, url: str, *, allow_loopback: bool = False) -> Dict[str, Any]:
        res = ABHToolBridge.scan_cors(url, allow_loopback=allow_loopback)
        findings = res.get("findings") or []
        return {
            "url": url,
            "status": res.get("status", "ERROR"),
            "vulnerable": len(findings) > 0,
            "issues": [f.get("title", "") for f in findings],
            "findings": findings,
            "error": res.get("error"),
        }


class CRLFScanner:
    """CRLF / response-splitting + host-header scanner delegated to ``bughunter.tools.crlf_scanner``."""

    def scan(self, url: str, host_header: bool = False, *, allow_loopback: bool = False) -> Dict[str, Any]:
        res = ABHToolBridge.scan_crlf(url, host_header=host_header, allow_loopback=allow_loopback)
        findings = res.get("findings") or []
        return {
            "url": url,
            "status": res.get("status", "ERROR"),
            "vulnerable": len(findings) > 0,
            "issues": [f.get("injection_type", "") for f in findings],
            "findings": findings,
            "error": res.get("error"),
        }


class NoSQLiScanner:
    """NoSQL injection scanner delegated to ``bughunter.tools.nosqli_scanner``."""

    def scan(
        self,
        url: str,
        user_field: str = "username",
        pass_field: str = "password",
        *,
        allow_loopback: bool = False,
    ) -> Dict[str, Any]:
        res = ABHToolBridge.scan_nosqli(
            url, user_field=user_field, pass_field=pass_field, allow_loopback=allow_loopback
        )
        findings = res.get("findings") or []
        return {
            "url": url,
            "status": res.get("status", "ERROR"),
            "vulnerable": len(findings) > 0,
            "issues": [f.get("vector", "") for f in findings],
            "findings": findings,
            "error": res.get("error"),
        }


class JWTScanner:
    """Offline JWT analyzer delegated to ``bughunter.tools.jwt_scanner``."""

    def scan(self, token: str, mode: str = "analyze") -> Dict[str, Any]:
        res = ABHToolBridge.analyze_jwt(token, mode=mode)
        issues = res.get("issues") or []
        return {
            "token": token[:20] + "...",
            "mode": mode,
            "status": res.get("status", "ERROR"),
            "header": res.get("header"),
            "payload": res.get("payload"),
            "vulnerable": any(
                str(i.get("severity", "")).lower() in ("critical", "high", "medium")
                for i in issues
            ),
            "issues": issues,
            "error": res.get("error"),
        }


class OOBListener:
    """Out-of-band payload generator & correlator delegated to ``bughunter.tools.oob_listener``."""

    def __init__(self, oob_domain: str = "interact.sh"):
        self.oob_domain = oob_domain
        self.payloads: List[Any] = []

    def generate_payloads(self, classes: Optional[List[str]] = None) -> List[str]:
        res = ABHToolBridge.generate_oob_payloads(self.oob_domain, classes=classes)
        raw = res.get("payloads") or []
        self.payloads = list(raw)
        formatted: List[str] = []
        for item in raw:
            if isinstance(item, dict):
                formatted.append(str(item.get("payload") or item.get("url") or item))
            else:
                formatted.append(str(item))
        return formatted

    def correlate(self, interactions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        from bughunter.tools import oob_listener
        if not isinstance(interactions, list):
            return []
        hits = oob_listener.correlate(interactions, self.payloads)
        return [dict(h.__dict__) if hasattr(h, "__dict__") else {"hit": h} for h in hits]


class SASTScanner:
    """Real Semgrep SAST scanner delegated to ``bughunter.tools.sast_scan`` (zero fake findings)."""

    def scan(self, path: str, configs: Optional[List[str]] = None) -> Dict[str, Any]:
        return ABHToolBridge.scan_sast(path, configs=configs)


class DOMXSSScanner:
    """Real headless Chromium DOM XSS verifier delegated to ``bughunter.tools.dom_xss_harness``."""

    def scan(self, url: str, *, allow_loopback: bool = False) -> Dict[str, Any]:
        return ABHToolBridge.scan_domxss(url, allow_loopback=allow_loopback)


class LLMRedTeamScanner:
    """Real LLM red-team probe runner delegated to ``bughunter.tools.llm_redteam``."""

    def scan(self, endpoint: str, *, field: str = "prompt", allow_loopback: bool = False) -> Dict[str, Any]:
        return ABHToolBridge.scan_llm_redteam(endpoint, field=field, allow_loopback=allow_loopback)


__all__ = [
    "CORSScanner",
    "CRLFScanner",
    "NoSQLiScanner",
    "JWTScanner",
    "OOBListener",
    "SASTScanner",
    "DOMXSSScanner",
    "LLMRedTeamScanner",
]
