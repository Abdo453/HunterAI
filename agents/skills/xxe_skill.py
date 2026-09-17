"""
XML External Entity (XXE) Injection Autonomous Skill
===================================================
Tests whether XML parsers resolve external entities or expand inline DTD entities.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
import httpx

from agents.skills.base_skill import BaseSkill, SkillResult

log = logging.getLogger("hunter_ai.skills.xxe")


class XXESkill(BaseSkill):
    name: str = "XXESkill"
    vuln_type: str = "xxe"
    cwe: str = "CWE-611"
    owasp_top10: str = "A05:2021 — Security Misconfiguration"
    default_severity: str = "High"

    CANARY_TOKEN = "HUNTER_XXE_EXPANSION_TOKEN_9921"

    XXE_PAYLOAD = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
  <!ENTITY xxe "{CANARY_TOKEN}">
]>
<root><data>&xxe;</data></root>"""

    async def run(self, target_url: str, param_name: str = "xml", **kwargs) -> SkillResult:
        logs = [f"[XXE] Auditing XML endpoint {target_url}"]
        transport = None
        if self.proxy:
            try:
                transport = httpx.AsyncHTTPTransport(proxy=self.proxy, verify=False)
            except Exception:
                pass

        async with httpx.AsyncClient(transport=transport, timeout=self.timeout, verify=False) as client:
            headers = {"Content-Type": "application/xml", "Accept": "application/xml, text/xml, */*"}
            try:
                # 1. Post directly as XML body
                r = await client.post(target_url, content=self.XXE_PAYLOAD, headers=headers)
                if self.CANARY_TOKEN in r.text:
                    logs.append(f"[XXE] Confirmed entity expansion: Canary token resolved in XML response")
                    return SkillResult(
                        verified=True,
                        vuln_type=self.vuln_type,
                        title=f"XML External Entity (XXE) Injection via Direct XML Body",
                        severity="High",
                        endpoint=target_url,
                        param_name=param_name,
                        evidence=f"Canary entity &xxe; was expanded by the server into '{self.CANARY_TOKEN}'",
                        payload_used=self.XXE_PAYLOAD,
                        remediation="Disable DTDs (doctypes) and external entity resolution in all XML parsers.",
                        confidence=0.95,
                        tool=self.name,
                        evidence_sources=[f"{self.name}/EntityExpansion"],
                        cwe=self.cwe,
                        owasp_top10=self.owasp_top10,
                        logs=logs
                    )

                # 2. Try parameter-encoded XML if param provided
                r_param = await client.post(target_url, data={param_name: self.XXE_PAYLOAD})
                if self.CANARY_TOKEN in r_param.text:
                    logs.append(f"[XXE] Confirmed entity expansion in parameter '{param_name}'")
                    return SkillResult(
                        verified=True,
                        vuln_type=self.vuln_type,
                        title=f"XML External Entity (XXE) Injection in parameter '{param_name}'",
                        severity="High",
                        endpoint=target_url,
                        param_name=param_name,
                        evidence=f"Canary entity resolved via form parameter '{param_name}'",
                        payload_used=self.XXE_PAYLOAD,
                        remediation="Disable DTD processing and external entity resolution in XML parsers.",
                        confidence=0.95,
                        tool=self.name,
                        evidence_sources=[f"{self.name}/ParamExpansion"],
                        cwe=self.cwe,
                        owasp_top10=self.owasp_top10,
                        logs=logs
                    )
            except Exception as e:
                logs.append(f"[XXE] Probe error: {e}")

        logs.append("[XXE] No XXE expansion observed")
        return SkillResult(verified=False, vuln_type=self.vuln_type, endpoint=target_url,
                           param_name=param_name, tool=self.name, logs=logs)
