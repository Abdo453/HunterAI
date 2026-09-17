"""
Server-Side Template Injection (SSTI) Autonomous Skill
======================================================
Tests whether dynamic template engines (Jinja2, Twig, Freemarker, Pebble, Mako, etc.)
evaluate expressions.
Enforces the fundamental security invariant:
  LITERAL REFLECTION != TEMPLATE EXECUTION
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import httpx

from agents.skills.base_skill import BaseSkill, SkillResult

log = logging.getLogger("hunter_ai.skills.ssti")


class SSTISkill(BaseSkill):
    name: str = "SSTISkill"
    vuln_type: str = "ssti"
    cwe: str = "CWE-1336"
    owasp_top10: str = "A03:2021 — Injection"
    default_severity: str = "High"

    PROBE_TRIADS = [
        ("{{53+19}}", "{{41+31}}", "72", "Jinja2/Twig"),
        ("${53+19}", "${41+31}", "72", "Java EL / Spring Expression"),
        ("<%= 53+19 %>", "<%= 41+31 %>", "72", "Ruby ERB / EJS"),
        ("#{53+19}", "#{41+31}", "72", "Ruby / SpEL"),
    ]

    async def run(self, target_url: str, param_name: str = "q", **kwargs) -> SkillResult:
        logs = [f"[SSTI] Auditing endpoint {target_url} parameter '{param_name}'"]
        transport = None
        if self.proxy:
            try:
                transport = httpx.AsyncHTTPTransport(proxy=self.proxy, verify=False)
            except Exception:
                pass

        async with httpx.AsyncClient(transport=transport, timeout=self.timeout, verify=False) as client:
            try:
                r_base = await client.get(target_url)
                base_text = r_base.text
            except Exception as e:
                logs.append(f"[SSTI] Baseline request failed: {e}")
                return SkillResult(verified=False, vuln_type=self.vuln_type, endpoint=target_url,
                                   param_name=param_name, tool=self.name, logs=logs)

            for e1_expr, e2_expr, expected_result, engine_name in self.PROBE_TRIADS:
                try:
                    u1 = self._inject_param(target_url, param_name, e1_expr)
                    r1 = await client.get(u1)
                    body1 = r1.text

                    if e1_expr in body1 and expected_result not in body1:
                        logs.append(f"[SSTI] Literal reflection trap detected for {e1_expr} -> NOT executed")
                        continue

                    if expected_result in body1 and e1_expr not in body1:
                        u2 = self._inject_param(target_url, param_name, e2_expr)
                        r2 = await client.get(u2)
                        body2 = r2.text

                        if expected_result in body2 and e2_expr not in body2:
                            logs.append(f"[SSTI] Confirmed! Both {e1_expr} and {e2_expr} evaluated to {expected_result} ({engine_name})")
                            evidence = f"Mathematical verification: {e1_expr} -> {expected_result} and {e2_expr} -> {expected_result} without literal reflection."
                            return SkillResult(
                                verified=True,
                                vuln_type=self.vuln_type,
                                title=f"Server-Side Template Injection (SSTI) in '{param_name}' ({engine_name})",
                                severity="Critical",
                                endpoint=target_url,
                                param_name=param_name,
                                evidence=evidence,
                                payload_used=e1_expr,
                                remediation="Disable template execution of user input or employ contextual escaping sandboxes.",
                                confidence=0.95,
                                tool=self.name,
                                evidence_sources=[f"{self.name}/{engine_name}"],
                                cwe=self.cwe,
                                owasp_top10=self.owasp_top10,
                                logs=logs
                            )
                except Exception as ex:
                    logs.append(f"[SSTI] Probe error for {e1_expr}: {ex}")

        logs.append(f"[SSTI] No template evaluation detected on '{param_name}'")
        return SkillResult(verified=False, vuln_type=self.vuln_type, endpoint=target_url,
                           param_name=param_name, tool=self.name, logs=logs)

    def _inject_param(self, url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [value]
        new_query = urlencode(qs, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
