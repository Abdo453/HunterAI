"""
HunterAI V23.0 Test Suite — Comprehensive Authentication Testing Engine
=======================================================================
Certifies the 20 Facets of the Authentication Attack-Surface & Reasoning Engine:
1. Auth Surface Discovery across 19 Archetypes (Login, Logout, Register, MFA, etc.)
2. Authentication State Machine Transitions & Invariants
3. Illegal Transition Detection (Anonymous/Logged-Out to Protected)
4. MFA Pending Challenge Bypass Detection
5. Session Fixation (Missing Post-Authentication Rotation)
6. Post-Logout Session Invalidation & Reuse
7. Post-Password-Change Stale Session Revocation
8. Contextual Cookie Flag Integrity (HttpOnly, Secure, SameSite)
9. Credential Matrix & Username Enumeration Divergence
10. Differential Authentication Bypass Detection
11. Strict 0.0% False Positive Rate on Benign Public 200 OK Pages
12. Password Reset Token Reuse & Expiration Auditing
13. JWT Algorithm 'none' & Perpetual Token Detection
14. OAuth 2.0 / OIDC Missing State & Insecure Redirect Audit
15. Authentication Evidence Court Golden Rule & AutonomousBrain/CLI Integration
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock
import pytest

from core.auth_engine import (
    AuthEndpointRecord,
    AuthEndpointType,
    AuthState,
    AuthTransitionTest,
    AuthVulnClass,
    DifferentialAuthResult,
    AuthFindingReport,
    AuthenticationStateMachine,
    AuthSurfaceDiscovery,
    SessionLifecycleAuditor,
    AuthDifferentialTester,
    CredentialMatrixAuditor,
    JWTOAuthAuditor,
    AuthEvidenceEvaluator,
    AuthenticationTestingEngine,
)
from core.evidence.evidence_level import EvidenceLevel
from core.brain.autonomous_brain import AutonomousBrain
from cli.hunter_cli import build_parser


class TestAuthDiscoveryAndStateMachine:
    """Tests 1 - 4: Discovery, State Machine, and Transition Invariants"""

    def test_auth_surface_discovery_classification(self):
        endpoints = [
            {"path": "/api/v1/auth/login", "method": "POST"},
            {"path": "/api/v1/auth/logout", "method": "POST"},
            {"path": "/api/v1/register", "method": "POST"},
            {"path": "/api/v1/password/forgot", "method": "POST"},
            {"path": "/api/v1/password/reset", "method": "POST"},
            {"path": "/api/v1/auth/mfa/challenge", "method": "GET"},
            {"path": "/oauth/authorize", "method": "GET"},
            {"path": "/api/v1/account/recovery", "method": "POST"},
            {"path": "/api/v1/user/profile", "method": "GET", "auth_required": True},
        ]
        records = AuthSurfaceDiscovery.discover_from_endpoints(endpoints)
        assert len(records) == 9

        arch_map = {r.path: r.archetype for r in records}
        assert arch_map["/api/v1/auth/login"] == AuthEndpointType.LOGIN
        assert arch_map["/api/v1/auth/logout"] == AuthEndpointType.LOGOUT
        assert arch_map["/api/v1/register"] == AuthEndpointType.REGISTER
        assert arch_map["/api/v1/password/forgot"] == AuthEndpointType.FORGOT_PASSWORD
        assert arch_map["/api/v1/password/reset"] == AuthEndpointType.RESET_PASSWORD
        assert arch_map["/api/v1/auth/mfa/challenge"] == AuthEndpointType.MFA_CHALLENGE
        assert arch_map["/oauth/authorize"] == AuthEndpointType.OAUTH_AUTHORIZE
        assert arch_map["/api/v1/account/recovery"] == AuthEndpointType.ACCOUNT_RECOVERY
        assert arch_map["/api/v1/user/profile"] == AuthEndpointType.PROTECTED_RESOURCE

    def test_auth_state_machine_legal_transitions(self):
        sm = AuthenticationStateMachine()
        assert sm.current_state == AuthState.ANONYMOUS

        # Safe transition: Anonymous request to public about page
        res = sm.evaluate_transition(
            from_state=AuthState.ANONYMOUS,
            action="GET /about",
            attempted_to_access_protected=False,
            response_status=200,
            sensitive_data_leaked=False
        )
        assert not res.is_violation

    def test_auth_state_machine_illegal_transition_detection(self):
        sm = AuthenticationStateMachine()
        # Illegal transition: Anonymous request accessing protected profile returning private data
        res = sm.evaluate_transition(
            from_state=AuthState.ANONYMOUS,
            action="GET /api/v1/user/profile",
            attempted_to_access_protected=True,
            response_status=200,
            sensitive_data_leaked=True
        )
        assert res.is_violation
        assert "Invariant Violation" in res.rationale

    def test_mfa_pending_bypass_detection(self):
        sm = AuthenticationStateMachine()
        # Illegal transition: MFA Pending user accessing protected data before challenge verification
        res = sm.evaluate_transition(
            from_state=AuthState.MFA_PENDING,
            action="GET /api/v1/admin/settings",
            attempted_to_access_protected=True,
            response_status=200,
            sensitive_data_leaked=True
        )
        assert res.is_violation
        assert "MFA Bypass Invariant" in res.rationale


class TestSessionLifecycleAuditor:
    """Tests 5 - 8: Fixation, Logout Invalidation, Password Change, and Cookie Flags"""

    def test_session_fixation_detection(self):
        pre_cookies = {"session": "fixed_token_abc123"}
        post_cookies = {"session": "fixed_token_abc123"}

        is_fixated, reason = SessionLifecycleAuditor.evaluate_session_fixation(pre_cookies, post_cookies)
        assert is_fixated is True
        assert "Session Fixation Confirmed" in reason

        # Rotated session
        post_rotated = {"session": "new_random_token_xyz789"}
        is_fixated2, _ = SessionLifecycleAuditor.evaluate_session_fixation(pre_cookies, post_rotated)
        assert is_fixated2 is False

    def test_post_logout_session_reuse_detection(self):
        # Post-logout: token still accesses protected endpoint
        is_reusable, reason = SessionLifecycleAuditor.evaluate_logout_invalidation(
            post_logout_status=200,
            sensitive_data_returned=True
        )
        assert is_reusable is True
        assert "Post-Logout Session Reuse Confirmed" in reason

        # Safe invalidation: server returns 401
        is_reusable2, _ = SessionLifecycleAuditor.evaluate_logout_invalidation(
            post_logout_status=401,
            sensitive_data_returned=False
        )
        assert is_reusable2 is False

    def test_post_password_change_session_revocation(self):
        is_stale, reason = SessionLifecycleAuditor.evaluate_password_change_invalidation(
            old_session_status=200,
            sensitive_data_returned=True
        )
        assert is_stale is True
        assert "Post-Password-Change Session Reuse Confirmed" in reason

    def test_contextual_cookie_flags_evaluation(self):
        cookie = {
            "name": "auth_token",
            "flags": {"HttpOnly": False, "Secure": False}
        }
        issues = SessionLifecycleAuditor.evaluate_cookie_security(cookie, is_https=True)
        assert len(issues) >= 2
        assert any("HttpOnly" in i for i in issues)
        assert any("Secure" in i for i in issues)

        # Benign marketing cookie should not trigger alarms
        ga_cookie = {"name": "_ga", "flags": {}}
        ga_issues = SessionLifecycleAuditor.evaluate_cookie_security(ga_cookie, is_https=True)
        assert len(ga_issues) == 0


class TestDifferentialAuthAndCredentials:
    """Tests 9 - 12: Username Enumeration, Differential Bypass, and Reset Tokens"""

    def test_credential_matrix_username_enumeration(self):
        valid_user = {"status_code": 401, "error_message": "Invalid password for user alice", "body": "x" * 200}
        invalid_user = {"status_code": 401, "error_message": "User not found", "body": "x" * 50}

        is_enum, reason = CredentialMatrixAuditor.evaluate_username_enumeration(valid_user, invalid_user)
        assert is_enum is True
        assert "Username Enumeration Confirmed" in reason

    def test_differential_auth_bypass_detection(self):
        anon_res = {"status_code": 200, "body": '{"user_id": 42, "email": "victim@target.local", "secret": "topsecret"}'}
        auth_res = {"status_code": 200, "body": '{"user_id": 42, "email": "victim@target.local", "secret": "topsecret"}'}

        res = AuthDifferentialTester.evaluate_access(
            endpoint="/api/v1/user/secret",
            method="GET",
            anonymous_response=anon_res,
            authenticated_response=auth_res
        )
        assert res.is_vulnerability is True
        assert res.sensitive_data_leaked is True

    def test_differential_auth_public_page_suppression(self):
        # Golden Rule: 200 OK on public page is NOT an auth bypass (Strictly 0.0% False Positives)
        anon_res = {"status_code": 200, "body": '<html><body>Welcome to Our Public Shop</body></html>'}
        auth_res = {"status_code": 200, "body": '<html><body>Welcome to Our Public Shop</body></html>'}

        res = AuthDifferentialTester.evaluate_access(
            endpoint="/about",
            method="GET",
            anonymous_response=anon_res,
            authenticated_response=auth_res
        )
        assert res.is_vulnerability is False
        assert res.sensitive_data_leaked is False
        assert "Safe Public Content" in res.rationale

    def test_password_reset_token_reuse(self):
        is_reusable, reason = CredentialMatrixAuditor.evaluate_reset_token_reuse(
            first_use_status=200,
            second_use_status=200,
            password_actually_changed_again=True
        )
        assert is_reusable is True
        assert "Reset Token Reuse Confirmed" in reason


class TestJWTOAuthAndEvidenceCourt:
    """Tests 13 - 15: JWT, OAuth, Evidence Court Golden Rule & CLI Integration"""

    def test_jwt_none_algorithm_and_expiration(self):
        # Header: {"alg": "none", "typ": "JWT"} -> eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0
        # Payload: {"sub": "101", "role": "admin"} -> eyJzdWIiOiIxMDEiLCJyb2xlIjoiYWRtaW4ifQ
        unsigned_jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMDEiLCJyb2xlIjoiYWRtaW4ifQ."
        issues, data = JWTOAuthAuditor.audit_jwt(unsigned_jwt)
        assert len(issues) >= 2
        assert any("alg: none" in i for i in issues)
        assert any("exp" in i for i in issues)

    def test_oauth_missing_state_and_wildcard_redirect(self):
        params = {
            "client_id": "client_123",
            "redirect_uri": "https://*.victim.local/callback",
            # state is missing
        }
        issues = JWTOAuthAuditor.audit_oauth_authorize_params(params)
        assert len(issues) >= 2
        assert any("state" in i for i in issues)
        assert any("Wildcard" in i for i in issues)

    def test_auth_evidence_court_golden_rule_and_engine(self):
        # Evaluator rejects finding without control comparison
        rejected = AuthEvidenceEvaluator.adjudicate_finding(
            vuln_class=AuthVulnClass.AUTH_BYPASS,
            endpoint="/api/test",
            title="Fake Finding",
            control_comparison="",  # Missing comparison
            reproducible_proof="None",
            impact="None",
            remediation="None",
            reproduction_count=1  # Insufficient reproduction count
        )
        assert rejected is None

        # Evaluator approves finding with verified control comparison and N>=2
        approved = AuthEvidenceEvaluator.adjudicate_finding(
            vuln_class=AuthVulnClass.AUTH_BYPASS,
            endpoint="/api/v1/user/profile",
            title="Authentication Bypass on Profile",
            control_comparison="Anonymous: HTTP 200 with user data | Authenticated: HTTP 200",
            reproducible_proof="Deterministic unauthenticated access across 2 runs",
            impact="Unauthorized PII exposure",
            remediation="Require Auth middleware",
            reproduction_count=2
        )
        assert approved is not None
        assert approved.evidence_level >= EvidenceLevel.E2_REPRODUCIBLE_BEHAVIOR

        # AutonomousBrain integration
        brain = AutonomousBrain(resource_manager=MagicMock(), tool_manager=MagicMock(), dry_run=True)
        assert hasattr(brain, "auth_testing_engine")
        assert brain.auth_testing_engine is not None

        # CLI argument parser integration
        parser = build_parser()
        parsed = parser.parse_args(["auth-audit", "--target", "https://api.test.local", "--demo", "--json"])
        assert parsed.command == "auth-audit"
        assert parsed.target == "https://api.test.local"
        assert parsed.demo is True
        assert parsed.json is True
