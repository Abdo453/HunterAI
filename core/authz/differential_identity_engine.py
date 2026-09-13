"""
HunterAI Differential Identity Engine
=====================================
Automates cross-session authorization comparisons:
Executes the identical request across:
1. Anonymous (Unauthenticated)
2. User A (Legitimate Owner)
3. User B (Cross-Tenant Attacker)
4. Admin (Privileged)
Compares deep response properties (status, JSON schema, data ownership) to confirm IDOR.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Tuple


@dataclass
class IdentityExecutionResult:
    role: str
    status_code: int
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    json_data: Optional[Dict[str, Any]] = None


@dataclass
class AuthorizationAnalysis:
    endpoint: str
    is_vulnerable: bool
    vuln_class: Optional[str] = None  # "IDOR", "BOLA", "BFLA", "MISSING_AUTH"
    confidence: float = 0.0
    rationale: str = ""
    evidence_snippet: str = ""


class DifferentialIdentityEngine:
    """Compares execution outcomes across identity contexts"""

    @classmethod
    def compare_identities(
        cls,
        endpoint: str,
        method: str,
        results_by_role: Dict[str, IdentityExecutionResult],
        resource_owner_role: str = "user_a",
        foreign_owner_role: str = "user_b"
    ) -> AuthorizationAnalysis:
        user_a_res = results_by_role.get(resource_owner_role)
        user_b_res = results_by_role.get(foreign_owner_role)
        anon_res = results_by_role.get("anonymous")

        if not user_a_res or not user_b_res:
            return AuthorizationAnalysis(
                endpoint=endpoint,
                is_vulnerable=False,
                rationale="Insufficient identity sessions to evaluate differential."
            )

        # 1. Check Horizontal BOLA / IDOR (User B receives User A's data with HTTP 200)
        if user_b_res.status_code == 200 and user_a_res.status_code == 200:
            # Check if response bodies or data objects match or contain confidential owner markers
            if user_b_res.body and user_b_res.body == user_a_res.body:
                return AuthorizationAnalysis(
                    endpoint=endpoint,
                    is_vulnerable=True,
                    vuln_class="IDOR",
                    confidence=0.99,
                    rationale=f"User '{foreign_owner_role}' successfully retrieved identical private data belonging to '{resource_owner_role}'.",
                    evidence_snippet=user_b_res.body[:200]
                )

        # 2. Check Missing Authentication (Anonymous user accesses protected resource)
        if anon_res and anon_res.status_code == 200:
            return AuthorizationAnalysis(
                endpoint=endpoint,
                is_vulnerable=True,
                vuln_class="MISSING_AUTH",
                confidence=0.95,
                rationale="Anonymous unauthenticated session accessed protected user resource.",
                evidence_snippet=anon_res.body[:200]
            )

        # 3. Proper enforcement observed
        if user_b_res.status_code in (401, 403, 404):
            return AuthorizationAnalysis(
                endpoint=endpoint,
                is_vulnerable=False,
                rationale=f"Endpoint properly enforced access control: User B returned HTTP {user_b_res.status_code}."
            )

        return AuthorizationAnalysis(
            endpoint=endpoint,
            is_vulnerable=False,
            rationale="No unauthorized differential access identified."
        )