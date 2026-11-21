"""
HunterAI Privilege Escalation & Authorization Engine
====================================================
Detects:
1. BOLA / IDOR (Broken Object Level Authorization): User A accessing User B's resources
2. BFLA (Broken Function Level Authorization): Low-privilege user calling administrative endpoints
3. Mass Assignment: Injecting administrative properties (role, is_admin, verified, balance)
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

from core.business_logic.schemas import (
    BusinessActionType,
    BusinessInvariant,
    BusinessLogicViolationReport,
    BusinessResourceState,
)

logger = logging.getLogger("hunter_ai.privilege_escalation")

DANGEROUS_MASS_ASSIGNMENT_FIELDS = [
    {"role": "admin"},
    {"role": "administrator"},
    {"role_id": 1},
    {"is_admin": True},
    {"admin": True},
    {"is_superuser": True},
    {"permissions": ["*"]},
    {"verified": True},
    {"email_verified": True},
    {"balance": 999999},
    {"credit": 999999},
    {"tier": "vip"},
]


@dataclass
class AuthContext:
    user_id: str
    role: str = "user"
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)


@dataclass
class AuthTestVerdict:
    is_vulnerable: bool
    vulnerability_type: str  # "BOLA", "BFLA", "MASS_ASSIGNMENT"
    target_endpoint: str
    http_method: str
    tested_payload: Dict[str, Any]
    attacker_role: str
    status_code: int
    evidence: str
    violation_report: Optional[BusinessLogicViolationReport] = None


class PrivilegeEscalationEngine:
    """
    Evaluates multi-tenant boundaries and authorization controls across actors.
    """

    def __init__(self, timeout_secs: float = 10.0):
        self.timeout_secs = timeout_secs

    def test_bola_idor(
        self,
        endpoint_template: str,
        user_a: AuthContext,
        victim_b_id: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> AuthTestVerdict:
        """
        Tests if User A (attacker) can view or mutate victim User B's object.
        endpoint_template should contain '{id}' or '{user_id}'.
        """
        target_url = endpoint_template.replace("{id}", victim_b_id).replace("{user_id}", victim_b_id)
        req_headers = dict(headers or {})
        req_headers.update(user_a.headers)

        try:
            with httpx.Client(timeout=self.timeout_secs, verify=False, cookies=user_a.cookies) as client:
                resp = client.request(
                    method=method.upper(),
                    url=target_url,
                    headers=req_headers,
                    json=json_body,
                )
                status = resp.status_code
                body_sample = resp.text[:1000]

                # If attacker gets 200/201 and victim's identifier is in the response body
                is_vuln = status in [200, 201] and (victim_b_id in body_sample or len(body_sample) > 50)
                evidence = (
                    f"BOLA/IDOR Confirmed on {target_url}: User A ({user_a.user_id}) requested User B's resource "
                    f"and received HTTP {status} with body: {body_sample[:200]}"
                )

                violation = None
                if is_vuln:
                    violation = BusinessLogicViolationReport(
                        finding_id=f"BOLA-{uuid.uuid4().hex[:6].upper()}",
                        invariant_id="INV-07-OBJECT-AUTHORIZATION",
                        invariant_name="Broken Object Level Authorization (BOLA/IDOR)",
                        violating_action="CROSS_TENANT_RESOURCE_ACCESS",
                        initial_state="TENANT_RESTRICTED",
                        resulting_state="TENANT_EXPOSED",
                        payload_mutation={"attacker": user_a.user_id, "victim_id": victim_b_id, "endpoint": target_url},
                        security_impact=f"Unauthorized cross-tenant access to victim {victim_b_id}'s private records.",
                        evidence_proof=evidence,
                    )

                return AuthTestVerdict(
                    is_vulnerable=is_vuln,
                    vulnerability_type="BOLA",
                    target_endpoint=target_url,
                    http_method=method,
                    tested_payload={"victim_id": victim_b_id},
                    attacker_role=user_a.role,
                    status_code=status,
                    evidence=evidence,
                    violation_report=violation,
                )
        except Exception as exc:
            return AuthTestVerdict(
                is_vulnerable=False,
                vulnerability_type="BOLA",
                target_endpoint=target_url,
                http_method=method,
                tested_payload={"victim_id": victim_b_id},
                attacker_role=user_a.role,
                status_code=0,
                evidence=f"Request failed: {exc}",
            )

    def test_bfla_admin_function(
        self,
        admin_endpoint: str,
        user_a: AuthContext,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> AuthTestVerdict:
        """
        Tests if a low-privilege User A can invoke an administrative endpoint.
        """
        req_headers = dict(headers or {})
        req_headers.update(user_a.headers)

        try:
            with httpx.Client(timeout=self.timeout_secs, verify=False, cookies=user_a.cookies) as client:
                resp = client.request(
                    method=method.upper(),
                    url=admin_endpoint,
                    headers=req_headers,
                    json=json_body,
                )
                status = resp.status_code
                body_sample = resp.text[:1000]

                # Low-privilege user should get 401 Unauthorized or 403 Forbidden
                is_vuln = status in [200, 201, 204]
                evidence = (
                    f"BFLA Confirmed on {admin_endpoint}: Low-privilege user ({user_a.role}) "
                    f"called privileged function and received HTTP {status}."
                )

                violation = None
                if is_vuln:
                    violation = BusinessLogicViolationReport(
                        finding_id=f"BFLA-{uuid.uuid4().hex[:6].upper()}",
                        invariant_id="INV-08-FUNCTION-AUTHORIZATION",
                        invariant_name="Broken Function Level Authorization (BFLA)",
                        violating_action="PRIVILEGED_FUNCTION_INVOCATION",
                        initial_state="RESTRICTED_ADMIN_ENDPOINT",
                        resulting_state="UNRESTRICTED_ACCESS",
                        payload_mutation={"endpoint": admin_endpoint, "caller_role": user_a.role},
                        security_impact="Administrative action executed without appropriate administrative credentials.",
                        evidence_proof=evidence,
                    )

                return AuthTestVerdict(
                    is_vulnerable=is_vuln,
                    vulnerability_type="BFLA",
                    target_endpoint=admin_endpoint,
                    http_method=method,
                    tested_payload=json_body or {},
                    attacker_role=user_a.role,
                    status_code=status,
                    evidence=evidence,
                    violation_report=violation,
                )
        except Exception as exc:
            return AuthTestVerdict(
                is_vulnerable=False,
                vulnerability_type="BFLA",
                target_endpoint=admin_endpoint,
                http_method=method,
                tested_payload=json_body or {},
                attacker_role=user_a.role,
                status_code=0,
                evidence=f"Request failed: {exc}",
            )

    def test_mass_assignment(
        self,
        endpoint: str,
        user: AuthContext,
        base_payload: Dict[str, Any],
        method: str = "POST",
    ) -> List[AuthTestVerdict]:
        """
        Injects dangerous properties (roles, balance, verified status) into JSON payloads
        and evaluates whether the server accepts and applies them.
        """
        verdicts: List[AuthTestVerdict] = []
        req_headers = dict(user.headers)
        req_headers["Content-Type"] = "application/json"

        with httpx.Client(timeout=self.timeout_secs, verify=False, cookies=user.cookies) as client:
            for injection in DANGEROUS_MASS_ASSIGNMENT_FIELDS:
                mutated_payload = dict(base_payload)
                mutated_payload.update(injection)
                try:
                    resp = client.request(
                        method=method.upper(),
                        url=endpoint,
                        headers=req_headers,
                        json=mutated_payload,
                    )
                    status = resp.status_code
                    body_sample = resp.text[:1000]

                    # Check if server reflected or acknowledged the injected property
                    prop_key, prop_val = next(iter(injection.items()))
                    reflected = (
                        isinstance(prop_val, str) and prop_val in body_sample
                    ) or (
                        isinstance(prop_val, bool) and f'"{prop_key}":true' in body_sample.replace(" ", "").lower()
                    )

                    is_vuln = status in [200, 201] and reflected
                    if is_vuln:
                        evidence = (
                            f"Mass Assignment Confirmed on {endpoint}: Server accepted injected property {injection} "
                            f"and returned HTTP {status} with reflected property: {body_sample[:200]}"
                        )
                        violation = BusinessLogicViolationReport(
                            finding_id=f"MASS-{uuid.uuid4().hex[:6].upper()}",
                            invariant_id="INV-09-MASS-ASSIGNMENT",
                            invariant_name="Mass Assignment / Privilege Escalation",
                            violating_action="INJECT_PROTECTED_PROPERTY",
                            initial_state="USER_PRIVILEGE",
                            resulting_state="ELEVATED_PRIVILEGE",
                            payload_mutation=injection,
                            security_impact=f"Privilege escalation via unchecked mass assignment of {injection}.",
                            evidence_proof=evidence,
                        )
                        verdicts.append(
                            AuthTestVerdict(
                                is_vulnerable=True,
                                vulnerability_type="MASS_ASSIGNMENT",
                                target_endpoint=endpoint,
                                http_method=method,
                                tested_payload=mutated_payload,
                                attacker_role=user.role,
                                status_code=status,
                                evidence=evidence,
                                violation_report=violation,
                            )
                        )
                except Exception as exc:
                    logger.debug("Mass assignment test exception: %s", exc)

        return verdicts
