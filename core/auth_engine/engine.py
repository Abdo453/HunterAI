"""
HunterAI Authentication Testing Engine Facade
=============================================
Orchestrates the entire authentication audit lifecycle:
Discovery -> State Machine -> Session Invalidation -> Differential Analysis -> Evidence Court.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

from .schemas import (
    AuthEndpointRecord,
    AuthEndpointType,
    AuthState,
    AuthTransitionTest,
    AuthVulnClass,
    DifferentialAuthResult,
    AuthFindingReport,
)
from .state_machine import AuthenticationStateMachine
from .discovery import AuthSurfaceDiscovery
from .session_lifecycle import SessionLifecycleAuditor
from .differential_tester import AuthDifferentialTester
from .credential_auditor import CredentialMatrixAuditor
from .jwt_oauth_auditor import JWTOAuthAuditor
from .auth_evidence_evaluator import AuthEvidenceEvaluator

logger = logging.getLogger("hunter_ai.auth.engine")


class AuthenticationTestingEngine:
    """Master orchestrator for authentication security reasoning and testing"""

    def __init__(self):
        self.state_machine = AuthenticationStateMachine()
        self.discovery = AuthSurfaceDiscovery()
        self.session_auditor = SessionLifecycleAuditor()
        self.differential_tester = AuthDifferentialTester()
        self.credential_auditor = CredentialMatrixAuditor()
        self.jwt_oauth_auditor = JWTOAuthAuditor()
        self.evaluator = AuthEvidenceEvaluator()
        self.findings: List[AuthFindingReport] = []

    def discover_endpoints(self, endpoints: List[Dict[str, Any]]) -> List[AuthEndpointRecord]:
        return self.discovery.discover_from_endpoints(endpoints)

    def audit_session_fixation(
        self,
        endpoint: str,
        pre_auth_cookies: Dict[str, str],
        post_auth_cookies: Dict[str, str]
    ) -> Optional[AuthFindingReport]:
        is_fixated, reason = self.session_auditor.evaluate_session_fixation(pre_auth_cookies, post_auth_cookies)
        if is_fixated:
            finding = self.evaluator.adjudicate_finding(
                vuln_class=AuthVulnClass.SESSION_FIXATION,
                endpoint=endpoint,
                title="Session Fixation (Missing Post-Authentication Token Rotation)",
                control_comparison="Pre-auth session cookie identical to post-auth session cookie",
                reproducible_proof=reason,
                impact="Session Hijacking via pre-seeded session token",
                remediation="Issue a fresh cryptographically random session token immediately upon successful login."
            )
            if finding:
                self.findings.append(finding)
                return finding
        return None

    def audit_logout_invalidation(
        self,
        logout_endpoint: str,
        protected_endpoint: str,
        post_logout_status: int,
        sensitive_data_leaked: bool
    ) -> Optional[AuthFindingReport]:
        is_reusable, reason = self.session_auditor.evaluate_logout_invalidation(
            post_logout_status=post_logout_status,
            sensitive_data_returned=sensitive_data_leaked
        )
        if is_reusable:
            finding = self.evaluator.adjudicate_finding(
                vuln_class=AuthVulnClass.POST_LOGOUT_SESSION_REUSE,
                endpoint=protected_endpoint,
                title="Post-Logout Session Reuse (Missing Server-Side Revocation)",
                control_comparison=f"Logged-out session accessed {protected_endpoint} returning HTTP 200 with sensitive data",
                reproducible_proof=reason,
                impact="Session retention after explicit user logout allows unauthorized access",
                remediation="Invalidate session identifier on the server database/cache upon logout request."
            )
            if finding:
                self.findings.append(finding)
                return finding
        return None

    def audit_differential_access(
        self,
        endpoint: str,
        method: str,
        anonymous_res: Dict[str, Any],
        authenticated_res: Dict[str, Any]
    ) -> Tuple[DifferentialAuthResult, Optional[AuthFindingReport]]:
        diff_res = self.differential_tester.evaluate_access(
            endpoint=endpoint,
            method=method,
            anonymous_response=anonymous_res,
            authenticated_response=authenticated_res
        )
        finding = None
        if diff_res.is_vulnerability:
            finding = self.evaluator.adjudicate_finding(
                vuln_class=AuthVulnClass.AUTH_BYPASS,
                endpoint=endpoint,
                title="Authentication Bypass (Unauthenticated Access to Protected User Resource)",
                control_comparison=f"Anonymous: HTTP {diff_res.anonymous_status} with user data | Authenticated: HTTP {diff_res.authenticated_status}",
                reproducible_proof=diff_res.rationale,
                impact="Complete unauthorized exposure of sensitive user data without credentials",
                remediation="Enforce mandatory server-side authentication middleware before routing to handler."
            )
            if finding:
                self.findings.append(finding)

        return diff_res, finding

    def audit_jwt_token(self, endpoint: str, token_str: str) -> List[AuthFindingReport]:
        issues, parsed = self.jwt_oauth_auditor.audit_jwt(token_str)
        reports = []
        for iss in issues:
            if "alg: none" in iss:
                f = self.evaluator.adjudicate_finding(
                    vuln_class=AuthVulnClass.JWT_NONE_ALGORITHM,
                    endpoint=endpoint,
                    title="JWT Algorithm 'none' Signature Verification Bypass",
                    control_comparison="Token accepted with alg: none header versus signed token",
                    reproducible_proof=iss,
                    impact="Arbitrary account impersonation via forged unsigned JWT",
                    remediation="Reject tokens with alg='none' or unsigned tokens in JWT verification middleware."
                )
                if f:
                    self.findings.append(f)
                    reports.append(f)
        return reports

    def format_terminal_dashboard(self) -> str:
        sep = "=" * 80
        lines = [
            sep,
            " 🔐 HunterAI Comprehensive Authentication Reasoning & Audit Dashboard",
            sep,
            f" Total Confirmed Findings Adjudicated: {len(self.findings)}",
            "-" * 80
        ]
        if not self.findings:
            lines.append(" ✅ All authentication invariants satisfied (Zero confirmed bypasses).")
        else:
            for f in self.findings:
                lines.append(f" • [{f.finding_id}] {f.title} (Level: E{int(f.evidence_level)})")
                lines.append(f"   Endpoint:    {f.endpoint}")
                lines.append(f"   Comparison:  {f.control_comparison}")
                lines.append(f"   Proof:       {f.reproducible_proof}")
                lines.append(f"   Fix:         {f.remediation}\n")
        lines.append(sep)
        return "\n".join(lines)
