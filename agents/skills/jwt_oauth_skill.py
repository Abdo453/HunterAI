"""
JWT & OAuth Security Autonomous Skill
====================================
Integrates JWTOAuthAuditor to audit JWT structure, signatures, and OAuth parameters.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs
import httpx

from agents.skills.base_skill import BaseSkill, SkillResult
from core.auth_engine.jwt_oauth_auditor import JWTOAuthAuditor

log = logging.getLogger("hunter_ai.skills.jwt_oauth")


class JWTOAuthSkill(BaseSkill):
    name: str = "JWTOAuthSkill"
    vuln_type: str = "jwt_oauth"
    cwe: str = "CWE-345"
    owasp_top10: str = "A07:2021 — Identification and Authentication Failures"
    default_severity: str = "High"

    async def run(self, target_url: str, param_name: str = "token", **kwargs) -> SkillResult:
        logs = [f"[JWT/OAuth] Auditing authentication on {target_url}"]
        auth_data = kwargs.get("auth", {})
        token = auth_data.get("token") or auth_data.get("bearer") or kwargs.get("token", "")

        # 1. Check URL parameters for OAuth parameters
        parsed = urlparse(target_url)
        qs = parse_qs(parsed.query)
        if "response_type" in qs or "redirect_uri" in qs or "client_id" in qs:
            oauth_issues = JWTOAuthAuditor.audit_oauth_authorize_params({k: v[0] for k, v in qs.items()})
            if oauth_issues:
                logs.append(f"[OAuth] Issues found: {oauth_issues}")
                return SkillResult(
                    verified=True,
                    vuln_type="oauth_misconfiguration",
                    title="OAuth 2.0 Authorization Parameter Misconfiguration",
                    severity="Medium",
                    endpoint=target_url,
                    param_name="state",
                    evidence="; ".join(oauth_issues),
                    payload_used="OAuth parameter audit",
                    remediation="Mandate robust unpredictable 'state' parameter and enforce strict non-wildcard redirect_uri validation.",
                    confidence=0.90,
                    tool=self.name,
                    evidence_sources=[f"{self.name}/OAuthAuditor"],
                    cwe="CWE-384",
                    owasp_top10=self.owasp_top10,
                    logs=logs
                )

        # 2. Check JWT Token if present
        if token:
            jwt_issues, jwt_data = JWTOAuthAuditor.audit_jwt(token)
            if jwt_issues:
                logs.append(f"[JWT] Issues found: {jwt_issues}")
                return SkillResult(
                    verified=True,
                    vuln_type="jwt_vulnerability",
                    title="JSON Web Token (JWT) Security Flaw Detected",
                    severity="High",
                    endpoint=target_url,
                    param_name=param_name,
                    evidence="; ".join(jwt_issues),
                    payload_used=token[:30] + "...",
                    remediation="Enforce cryptographic signature validation, reject 'alg: none', and mandate 'exp' expiration claim.",
                    confidence=0.95,
                    tool=self.name,
                    evidence_sources=[f"{self.name}/JWTAuditor"],
                    cwe=self.cwe,
                    owasp_top10=self.owasp_top10,
                    logs=logs
                )

        logs.append("[JWT/OAuth] No JWT or OAuth flaws detected")
        return SkillResult(verified=False, vuln_type=self.vuln_type, endpoint=target_url,
                           param_name=param_name, tool=self.name, logs=logs)
