"""
HunterAI Differential Authentication Testing Engine
===================================================
Compares response states across Anonymous, Authenticated, and Expired contexts.
Enforces the Inviolable Rule:
  200 OK + generic public data != Vulnerability
  Only 200 OK + sensitive private user/tenant data == Confirmed Auth Bypass
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from .schemas import DifferentialAuthResult

logger = logging.getLogger("hunter_ai.auth.differential_tester")


class AuthDifferentialTester:
    """Performs comparative cross-state evaluation between anonymous and authenticated sessions"""

    @classmethod
    def evaluate_access(
        cls,
        endpoint: str,
        method: str,
        anonymous_response: Dict[str, Any],
        authenticated_response: Dict[str, Any],
        sensitive_data_patterns: Optional[List[str]] = None
    ) -> DifferentialAuthResult:
        """
        Calculates differential outcome between unauthenticated and authenticated requests.
        """
        anon_status = anonymous_response.get("status_code", 200)
        auth_status = authenticated_response.get("status_code", 200)
        anon_body = str(anonymous_response.get("body", ""))
        auth_body = str(authenticated_response.get("body", ""))

        status_diverged = anon_status != auth_status
        length_delta = abs(len(auth_body) - len(anon_body))

        # Check for sensitive data leakage under anonymous session
        patterns = sensitive_data_patterns or ["email", "user_id", "billing", "token", "ssn", "secret", "private_key", "balance"]
        sensitive_leaked = False
        if anon_status == 200:
            for p in patterns:
                if p.lower() in anon_body.lower() and p.lower() in auth_body.lower():
                    sensitive_leaked = True
                    break

        # Decision Rule:
        # If anon receives 200 OK on a public page with NO sensitive leakage -> Safe Public Resource
        is_vuln = False
        rationale = ""
        if anon_status == 200 and sensitive_leaked:
            is_vuln = True
            rationale = f"Authentication Bypass Confirmed: Unauthenticated request to {method} {endpoint} returned HTTP 200 containing sensitive user data."
        elif anon_status in (401, 403) and auth_status == 200:
            rationale = f"Authentication Properly Enforced: Anonymous received HTTP {anon_status}, Authenticated received HTTP 200."
        elif anon_status == 200 and not sensitive_leaked:
            rationale = f"Safe Public Content: Anonymous received HTTP 200 but response contains only public/generic content."
        else:
            rationale = f"Consistent access control behavior observed across states."

        return DifferentialAuthResult(
            endpoint=endpoint,
            method=method,
            anonymous_status=anon_status,
            authenticated_status=auth_status,
            status_diverged=status_diverged,
            body_length_delta=length_delta,
            sensitive_data_leaked=sensitive_leaked,
            is_vulnerability=is_vuln,
            rationale=rationale,
        )
