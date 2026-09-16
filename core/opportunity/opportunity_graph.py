"""
HunterAI Semantic Parameter Analyzer & Attack Opportunity Graph
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from core.opportunity.schemas import (
    AttackOpportunity,
    SemanticParameterProfile,
    SemanticParameterRole,
)

logger = logging.getLogger("hunter_ai.opportunity_graph")


class SemanticParameterAnalyzer:
    """
    Classifies parameters based on naming patterns, data types, and operational context.
    Maps parameters to expected risk vectors.
    """

    ROLE_PATTERNS = {
        SemanticParameterRole.FINANCIAL_VALUE: [
            "price", "amount", "cost", "total", "subtotal", "discount", "balance", "fee", "tax", "rate", "quantity", "qty", "count"
        ],
        SemanticParameterRole.IDENTITY_REFERENCE: [
            "id", "user_id", "userid", "account_id", "tenant_id", "owner_id", "profile_id", "customer_id", "uuid"
        ],
        SemanticParameterRole.ROLE_FLAG: [
            "role", "is_admin", "isadmin", "admin", "verified", "is_staff", "privilege", "tier", "permission"
        ],
        SemanticParameterRole.STATE_TRANSITION: [
            "status", "state", "step", "phase", "action", "workflow", "stage"
        ],
        SemanticParameterRole.REDIRECT_TARGET: [
            "redirect", "return_url", "returnurl", "next", "callback", "url", "dest", "destination", "target"
        ],
        SemanticParameterRole.FILE_PATH: [
            "file", "path", "filename", "doc", "document", "image", "upload", "attachment"
        ],
        SemanticParameterRole.QUERY_FILTER: [
            "search", "q", "query", "filter", "find", "keyword", "sort", "order"
        ],
    }

    ROLE_HYPOTHESES = {
        SemanticParameterRole.FINANCIAL_VALUE: [
            "PRICE_TAMPERING", "NEGATIVE_QUANTITY", "CURRENCY_CONFUSION", "ROUNDING_EXPLOIT", "RACE_CONDITION"
        ],
        SemanticParameterRole.IDENTITY_REFERENCE: [
            "BOLA_IDOR", "HORIZONTAL_PRIVILEGE_ESCALATION", "CROSS_TENANT_ACCESS"
        ],
        SemanticParameterRole.ROLE_FLAG: [
            "MASS_ASSIGNMENT", "VERTICAL_PRIVILEGE_ESCALATION", "ROLE_CONFUSION"
        ],
        SemanticParameterRole.STATE_TRANSITION: [
            "WORKFLOW_STEP_SKIPPING", "ILLEGAL_STATE_JUMP", "STATE_CONFUSION"
        ],
        SemanticParameterRole.REDIRECT_TARGET: [
            "OPEN_REDIRECT", "SSRF", "OAUTH_REDIRECT_HIJACK"
        ],
        SemanticParameterRole.FILE_PATH: [
            "PATH_TRAVERSAL", "LOCAL_FILE_INCLUSION", "ARBITRARY_FILE_READ"
        ],
        SemanticParameterRole.QUERY_FILTER: [
            "SQL_INJECTION", "NOSQL_INJECTION", "REFLECTED_XSS"
        ],
    }

    @classmethod
    def analyze_parameter(cls, param_name: str) -> SemanticParameterProfile:
        lower_name = param_name.lower().replace("-", "_")
        tokens = [t for t in lower_name.split("_") if t]
        matched_role = None

        # 1. Exact token matching first (prevents 'count' matching 'account')
        for role, patterns in cls.ROLE_PATTERNS.items():
            if any(pat in tokens or pat == lower_name for pat in patterns):
                matched_role = role
                break

        # 2. Substring matching fallback (excluding short/deceptive patterns)
        if not matched_role:
            for role, patterns in cls.ROLE_PATTERNS.items():
                if any(pat in lower_name for pat in patterns if pat not in ("count", "rate", "doc", "q")):
                    matched_role = role
                    break

        if not matched_role:
            matched_role = SemanticParameterRole.QUERY_FILTER

        hypotheses = cls.ROLE_HYPOTHESES.get(matched_role, ["GENERIC_INPUT_VALIDATION"])
        state_impact = "financial_transaction" if matched_role == SemanticParameterRole.FINANCIAL_VALUE else "data_access"

        return SemanticParameterProfile(
            parameter_name=param_name,
            semantic_role=matched_role,
            state_impact=state_impact,
            risk_hypotheses=hypotheses
        )


class AttackOpportunityGraph:
    """
    Transforms the passive Attack Surface into a multi-vector Attack Opportunity Graph.
    One endpoint yields multiple distinct hypotheses to investigate.
    """

    def __init__(self):
        self._opportunities: List[AttackOpportunity] = []

    def derive_opportunities_for_endpoint(
        self,
        endpoint: str,
        method: str,
        parameters: List[str]
    ) -> List[AttackOpportunity]:
        """
        Dissects an endpoint and its parameters into concrete attack opportunities.
        """
        derived: List[AttackOpportunity] = []
        method_upper = method.upper()

        # 1. Parameter-specific opportunities
        for param in parameters:
            profile = SemanticParameterAnalyzer.analyze_parameter(param)
            for hyp in profile.risk_hypotheses:
                opp = AttackOpportunity(
                    opportunity_id=f"OPP-{uuid.uuid4().hex[:6].upper()}",
                    endpoint=endpoint,
                    method=method_upper,
                    vuln_vector=hyp,
                    target_parameter=param,
                    semantic_role=profile.semantic_role,
                    expected_information_gain=0.85 if "IDOR" in hyp or "TAMPERING" in hyp else 0.70,
                    test_priority="CRITICAL" if "TAMPERING" in hyp or "BOLA" in hyp else "HIGH",
                    rationale=f"Parameter '{param}' identified as {profile.semantic_role.value} -> test for {hyp}."
                )
                derived.append(opp)

        # 2. Method-based opportunities (e.g. PUT/POST without specific params -> test Mass Assignment)
        if method_upper in ("POST", "PUT", "PATCH") and not any("role" in p.lower() for p in parameters):
            derived.append(AttackOpportunity(
                opportunity_id=f"OPP-{uuid.uuid4().hex[:6].upper()}",
                endpoint=endpoint,
                method=method_upper,
                vuln_vector="MASS_ASSIGNMENT_PROBE",
                target_parameter="role/isAdmin",
                semantic_role=SemanticParameterRole.ROLE_FLAG,
                expected_information_gain=0.75,
                test_priority="HIGH",
                rationale=f"Mutating method {method_upper} on {endpoint} accepts body -> probe unadvertised role fields."
            ))

        # 3. Path-based IDOR opportunity if URL contains numeric or UUID path segment
        parts = [p for p in endpoint.split("/") if p]
        if any(p.isdigit() or len(p) > 20 for p in parts):
            derived.append(AttackOpportunity(
                opportunity_id=f"OPP-{uuid.uuid4().hex[:6].upper()}",
                endpoint=endpoint,
                method=method_upper,
                vuln_vector="BOLA_PATH_OBJECT_REFERENCE",
                target_parameter="path_resource_id",
                semantic_role=SemanticParameterRole.IDENTITY_REFERENCE,
                expected_information_gain=0.90,
                test_priority="CRITICAL",
                rationale=f"Endpoint path has object identifier segment -> test cross-tenant object substitution."
            ))

        self._opportunities.extend(derived)
        return derived

    def list_opportunities(self, min_priority: Optional[str] = None) -> List[AttackOpportunity]:
        if not min_priority:
            return list(self._opportunities)
        return [o for o in self._opportunities if o.test_priority == min_priority.upper()]
