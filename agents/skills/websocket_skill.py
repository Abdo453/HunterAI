"""
WebSocket Security Autonomous Skill
===================================
Audits WebSocket endpoints for Cross-Site WebSocket Hijacking (CSWSH) and handshake security.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
import httpx

from agents.skills.base_skill import BaseSkill, SkillResult
from core.protocols.websocket_agent import WebSocketSecurityAgent

log = logging.getLogger("hunter_ai.skills.websocket")


class WebSocketSkill(BaseSkill):
    name: str = "WebSocketSkill"
    vuln_type: str = "websocket"
    cwe: str = "CWE-1385"
    owasp_top10: str = "A01:2021 — Broken Access Control"
    default_severity: str = "High"

    async def run(self, target_url: str, param_name: str = "", **kwargs) -> SkillResult:
        logs = [f"[WS] Auditing WebSocket security on {target_url}"]
        target_domain = urlparse(target_url).hostname or "target.local"
        agent = WebSocketSecurityAgent(target_domain=target_domain)

        transport = None
        if self.proxy:
            try:
                transport = httpx.AsyncHTTPTransport(proxy=self.proxy, verify=False)
            except Exception:
                pass

        async with httpx.AsyncClient(transport=transport, timeout=self.timeout, verify=False) as client:
            for test_type, test_origin in agent.get_cswsh_test_origins()[:2]:
                headers = {
                    "Upgrade": "websocket",
                    "Connection": "Upgrade",
                    "Sec-WebSocket-Version": "13",
                    "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                    "Origin": test_origin
                }
                try:
                    r = await client.get(target_url, headers=headers)
                    if r.status_code == 101:
                        logs.append(f"[WS] Confirmed CSWSH! Handshake accepted HTTP 101 with untrusted origin: {test_origin}")
                        return SkillResult(
                            verified=True,
                            vuln_type="cswsh",
                            title=f"Cross-Site WebSocket Hijacking (CSWSH) via Origin '{test_origin}'",
                            severity="High",
                            endpoint=target_url,
                            param_name="Origin",
                            evidence=f"WebSocket handshake succeeded (HTTP 101) with untrusted Origin: {test_origin}",
                            payload_used=f"Origin: {test_origin}",
                            remediation="Validate the Origin header during the WebSocket handshake against a strict domain whitelist.",
                            confidence=0.95,
                            tool=self.name,
                            evidence_sources=[f"{self.name}/CSWSHOriginTest"],
                            cwe=self.cwe,
                            owasp_top10=self.owasp_top10,
                            logs=logs
                        )
                except Exception as e:
                    logs.append(f"[WS] Handshake test error for {test_origin}: {e}")

        logs.append("[WS] No WebSocket handshake vulnerabilities detected")
        return SkillResult(verified=False, vuln_type=self.vuln_type, endpoint=target_url,
                           param_name="Origin", tool=self.name, logs=logs)
