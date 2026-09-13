"""
HunterAI Adaptive Risk-Based Test Selector
==========================================
Contextually selects and orders vulnerability tests based on endpoint semantics and target profile.
Rule:
- If endpoint is an Authentication endpoint (/login, /token, /oauth):
  Prioritizes Session Security, Rate-limiting/Brute-force, and Credential Timing.
  Suppresses Path Traversal and unrelated checks.
- If endpoint is GraphQL:
  Prioritizes Introspection, Batching DoS, Field Authorization.
- If endpoint is REST Data API (/users/{id}):
  Prioritizes BOLA/IDOR, SQL Injection, Privilege Escalation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Set


class TestCheckClass(str, Enum):
    SESSION_SECURITY = "SESSION_SECURITY"
    RATE_LIMIT_BRUTEFORCE = "RATE_LIMIT_BRUTEFORCE"
    CREDENTIAL_TIMING = "CREDENTIAL_TIMING"
    CSRF = "CSRF"
    BOLA_IDOR = "BOLA_IDOR"
    SQL_INJECTION = "SQL_INJECTION"
    GRAPHQL_INTROSPECTION = "GRAPHQL_INTROSPECTION"
    GRAPHQL_BATCHING_DOS = "GRAPHQL_BATCHING_DOS"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    XSS = "XSS"
    SSRF = "SSRF"


TestCheckClass.__test__ = False


@dataclass
class AdaptiveCheckPlan:
    endpoint: str
    method: str
    detected_semantic: str  # "AUTH_FLOW", "DATA_RESOURCE", "GRAPHQL", "STATIC_ASSET", "GENERIC_API"
    prioritized_checks: List[TestCheckClass] = field(default_factory=list)
    suppressed_checks: List[TestCheckClass] = field(default_factory=list)
    risk_weight: int = 5  # 1 (Highest) to 10 (Lowest)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "method": self.method,
            "semantic": self.detected_semantic,
            "risk_weight": self.risk_weight,
            "prioritized_checks": [c.value for c in self.prioritized_checks],
            "suppressed_checks": [c.value for c in self.suppressed_checks],
        }


class AdaptiveRiskSelector:
    """Selects targeted security test suites based on endpoint risk semantics"""

    AUTH_KEYWORDS = {"/login", "/auth", "/token", "/session", "/oauth", "/signin", "/sso", "/password"}
    RESOURCE_KEYWORDS = {"/users", "/accounts", "/orders", "/payments", "/documents", "/profiles", "/items"}
    GRAPHQL_KEYWORDS = {"/graphql", "/api/graphql", "/v1/graphql"}

    @classmethod
    def select_checks(
        cls,
        endpoint: str,
        method: str = "GET",
        headers: Dict[str, str] = None,
        profile_hint: str = "API"
    ) -> AdaptiveCheckPlan:
        low_ep = endpoint.lower()
        method_u = method.upper()

        # 1. GraphQL
        if any(k in low_ep for k in cls.GRAPHQL_KEYWORDS) or profile_hint.upper() == "GRAPHQL":
            return AdaptiveCheckPlan(
                endpoint=endpoint,
                method=method_u,
                detected_semantic="GRAPHQL",
                risk_weight=2,
                prioritized_checks=[
                    TestCheckClass.GRAPHQL_INTROSPECTION,
                    TestCheckClass.GRAPHQL_BATCHING_DOS,
                    TestCheckClass.BOLA_IDOR,
                ],
                suppressed_checks=[
                    TestCheckClass.PATH_TRAVERSAL,
                    TestCheckClass.CSRF,
                ]
            )

        # 2. Authentication Flow
        if any(k in low_ep for k in cls.AUTH_KEYWORDS):
            return AdaptiveCheckPlan(
                endpoint=endpoint,
                method=method_u,
                detected_semantic="AUTH_FLOW",
                risk_weight=1,  # Highest priority
                prioritized_checks=[
                    TestCheckClass.RATE_LIMIT_BRUTEFORCE,
                    TestCheckClass.SESSION_SECURITY,
                    TestCheckClass.CREDENTIAL_TIMING,
                    TestCheckClass.CSRF,
                ],
                suppressed_checks=[
                    TestCheckClass.PATH_TRAVERSAL,
                    TestCheckClass.GRAPHQL_INTROSPECTION,
                ]
            )

        # 3. Data / Resource REST Endpoint
        if any(k in low_ep for k in cls.RESOURCE_KEYWORDS) or "{" in low_ep or (low_ep.count("/") >= 3 and any(char.isdigit() for char in low_ep)):
            return AdaptiveCheckPlan(
                endpoint=endpoint,
                method=method_u,
                detected_semantic="DATA_RESOURCE",
                risk_weight=2,
                prioritized_checks=[
                    TestCheckClass.BOLA_IDOR,
                    TestCheckClass.SQL_INJECTION,
                    TestCheckClass.SSRF,
                ],
                suppressed_checks=[
                    TestCheckClass.GRAPHQL_INTROSPECTION,
                ]
            )

        # 4. Generic Web Route
        return AdaptiveCheckPlan(
            endpoint=endpoint,
            method=method_u,
            detected_semantic="GENERIC_API",
            risk_weight=4,
            prioritized_checks=[
                TestCheckClass.XSS,
                TestCheckClass.SQL_INJECTION,
                TestCheckClass.BOLA_IDOR,
            ],
            suppressed_checks=[]
        )
