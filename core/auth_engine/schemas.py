"""
HunterAI Authentication Engine Schemas
======================================
Formal definitions for authentication archetypes, states, transition models,
and evidence-backed findings.
"""
from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from core.evidence.evidence_level import EvidenceLevel


class AuthEndpointType(str, Enum):
    LOGIN = "LOGIN"
    LOGOUT = "LOGOUT"
    REGISTER = "REGISTER"
    FORGOT_PASSWORD = "FORGOT_PASSWORD"
    RESET_PASSWORD = "RESET_PASSWORD"
    CHANGE_PASSWORD = "CHANGE_PASSWORD"
    EMAIL_VERIFY = "EMAIL_VERIFY"
    MFA_CHALLENGE = "MFA_CHALLENGE"
    MFA_VERIFY = "MFA_VERIFY"
    OTP_REQUEST = "OTP_REQUEST"
    OTP_VERIFY = "OTP_VERIFY"
    MAGIC_LINK = "MAGIC_LINK"
    OAUTH_AUTHORIZE = "OAUTH_AUTHORIZE"
    OAUTH_CALLBACK = "OAUTH_CALLBACK"
    SESSION_REFRESH = "SESSION_REFRESH"
    REMEMBER_ME = "REMEMBER_ME"
    ACCOUNT_RECOVERY = "ACCOUNT_RECOVERY"
    API_AUTH = "API_AUTH"
    PROTECTED_RESOURCE = "PROTECTED_RESOURCE"
    PUBLIC_RESOURCE = "PUBLIC_RESOURCE"


class AuthState(str, Enum):
    ANONYMOUS = "ANONYMOUS"
    REGISTERED = "REGISTERED"
    EMAIL_UNVERIFIED = "EMAIL_UNVERIFIED"
    AUTHENTICATED = "AUTHENTICATED"
    MFA_PENDING = "MFA_PENDING"
    MFA_VERIFIED = "MFA_VERIFIED"
    SESSION_REFRESHED = "SESSION_REFRESHED"
    LOGGED_OUT = "LOGGED_OUT"
    EXPIRED_SESSION = "EXPIRED_SESSION"


class AuthVulnClass(str, Enum):
    AUTH_BYPASS = "AUTH_BYPASS"
    SESSION_FIXATION = "SESSION_FIXATION"
    POST_LOGOUT_SESSION_REUSE = "POST_LOGOUT_SESSION_REUSE"
    POST_PASSWORD_CHANGE_SESSION_REUSE = "POST_PASSWORD_CHANGE_SESSION_REUSE"
    MFA_BYPASS = "MFA_BYPASS"
    USERNAME_ENUMERATION = "USERNAME_ENUMERATION"
    RESET_TOKEN_REUSE = "RESET_TOKEN_REUSE"
    RESET_TOKEN_NO_EXPIRY = "RESET_TOKEN_NO_EXPIRY"
    JWT_UNVERIFIED_SIGNATURE = "JWT_UNVERIFIED_SIGNATURE"
    JWT_NONE_ALGORITHM = "JWT_NONE_ALGORITHM"
    OAUTH_MISSING_STATE = "OAUTH_MISSING_STATE"
    OAUTH_WILDCARD_REDIRECT = "OAUTH_WILDCARD_REDIRECT"
    INSECURE_COOKIE_STORAGE = "INSECURE_COOKIE_STORAGE"


@dataclass
class AuthEndpointRecord:
    endpoint_id: str
    path: str
    method: str
    archetype: AuthEndpointType
    parameters: List[str] = field(default_factory=list)
    cookies_observed: List[str] = field(default_factory=list)
    headers_observed: List[str] = field(default_factory=list)
    requires_auth: bool = False
    source: str = "DISCOVERY"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["archetype"] = self.archetype.value
        return d


@dataclass
class AuthTransitionTest:
    initial_state: AuthState
    target_action: str
    observed_state: AuthState
    expected_safe_state: AuthState
    is_violation: bool
    rationale: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "initial_state": self.initial_state.value,
            "target_action": self.target_action,
            "observed_state": self.observed_state.value,
            "expected_safe_state": self.expected_safe_state.value,
            "is_violation": self.is_violation,
            "rationale": self.rationale,
        }


@dataclass
class DifferentialAuthResult:
    endpoint: str
    method: str
    anonymous_status: int
    authenticated_status: int
    status_diverged: bool
    body_length_delta: int
    sensitive_data_leaked: bool
    is_vulnerability: bool
    rationale: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AuthFindingReport:
    finding_id: str
    vuln_class: AuthVulnClass
    title: str
    endpoint: str
    evidence_level: EvidenceLevel
    control_comparison: str
    reproducible_proof: str
    impact: str
    remediation: str
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["vuln_class"] = self.vuln_class.value
        d["evidence_level"] = int(self.evidence_level)
        return d
