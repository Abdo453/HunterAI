"""
Cross-Origin Resource Sharing (CORS) Misconfiguration Skill
===========================================================
Audits CORS policies for arbitrary origin reflection and credential exposure.
Invariant:
  VULNERABLE IF AND ONLY IF (Origin reflected AND Access-Control-Allow-Credentials: true)
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
import httpx

from agents.skills.base_skill import BaseSkill, SkillResult

log = logging.getLogger("hunter_ai.skills.cors")


class CORSSkill(BaseSkill):
    name: str = "CORSSkill"
    vuln_type: str = "cors"
    cwe: str = "CWE-942"
    owasp_top10: str = "A01:2021 — Broken Access Control"
    default_severity: str = "Medium"

    EVIL_ORIGIN = "https://evil-attacker.local"

    async def run(self, target_url: str, param_name: str = "", **kwargs) -> SkillResult:
        logs = [f"[CORS] Auditing CORS policy on {target_url}"]
        transport = None
        if self.proxy:
            try:
                transport = httpx.AsyncHTTPTransport(proxy=self.proxy, verify=False)
            except Exception:
                pass

        async with httpx.AsyncClient(transport=transport, timeout=self.timeout, verify=False) as client:
            test_origins = [self.EVIL_ORIGIN, "null"]
            for test_orig in test_origins:
                try:
                    headers = {"Origin": test_orig}
                    resp = await client.get(target_url, headers=headers)
                    acao = resp.headers.get("access-control-allow-origin", "").strip()
                    acac = resp.headers.get("access-control-allow-credentials", "").strip().lower()

                    # Invariant: Origin reflected AND credentials allowed
                    if acao == test_orig and acac == "true":
                        logs.append(f"[CORS] Confirmed exploitable CORS! Origin '{test_orig}' reflected with credentials=true")
                        return SkillResult(
                            verified=True,
                            vuln_type=self.vuln_type,
                            title=f"Exploitable CORS Misconfiguration (Arbitrary Origin with Credentials)",
                            severity="High",
                            endpoint=target_url,
                            param_name="Origin",
                            evidence=f"Server responded with 'Access-Control-Allow-Origin: {acao}' and 'Access-Control-Allow-Credentials: true' to untrusted origin '{test_orig}'",
                            payload_used=f"Origin: {test_orig}",
                            remediation="Implement strict allowlist for Access-Control-Allow-Origin and avoid reflecting untrusted Origins when credentials are enabled.",
                            confidence=0.95,
                            tool=self.name,
                            evidence_sources=[f"{self.name}/OriginReflection"],
                            cwe=self.cwe,
                            owasp_top10=self.owasp_top10,
                            logs=logs
                        )
                    elif acao == "*":
                        logs.append("[CORS] Wildcard '*' allowed (without credentials)")
                except Exception as e:
                    logs.append(f"[CORS] Error probing origin '{test_orig}': {e}")

        logs.append("[CORS] No exploitable CORS misconfiguration detected")
        return SkillResult(verified=False, vuln_type=self.vuln_type, endpoint=target_url,
                           param_name="Origin", tool=self.name, logs=logs)
