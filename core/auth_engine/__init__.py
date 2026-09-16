"""HunterAI Comprehensive Authentication Engine Package"""
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
from .engine import AuthenticationTestingEngine

__all__ = [
    "AuthEndpointRecord",
    "AuthEndpointType",
    "AuthState",
    "AuthTransitionTest",
    "AuthVulnClass",
    "DifferentialAuthResult",
    "AuthFindingReport",
    "AuthenticationStateMachine",
    "AuthSurfaceDiscovery",
    "SessionLifecycleAuditor",
    "AuthDifferentialTester",
    "CredentialMatrixAuditor",
    "JWTOAuthAuditor",
    "AuthEvidenceEvaluator",
    "AuthenticationTestingEngine",
]
