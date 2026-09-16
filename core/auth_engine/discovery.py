"""
HunterAI Authentication Surface Discovery
=========================================
Maps endpoints across 19 authentication archetypes from URLs,
OpenAPI specifications, and HTTP wire telemetry.
"""
from __future__ import annotations

import hashlib
import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from .schemas import AuthEndpointRecord, AuthEndpointType

logger = logging.getLogger("hunter_ai.auth.discovery")

_ARCHETYPE_PATTERNS = [
    (AuthEndpointType.LOGIN, re.compile(r"/(?:login|signin|authenticate|auth/token|oauth/token)", re.I)),
    (AuthEndpointType.LOGOUT, re.compile(r"/(?:logout|signout|invalidate)", re.I)),
    (AuthEndpointType.REGISTER, re.compile(r"/(?:register|signup|create-account|join)", re.I)),
    (AuthEndpointType.FORGOT_PASSWORD, re.compile(r"/(?:forgot-password|password/forgot|recover-password)", re.I)),
    (AuthEndpointType.RESET_PASSWORD, re.compile(r"/(?:reset-password|password/reset)", re.I)),
    (AuthEndpointType.CHANGE_PASSWORD, re.compile(r"/(?:change-password|password/change|update-password)", re.I)),
    (AuthEndpointType.EMAIL_VERIFY, re.compile(r"/(?:verify-email|email/verify|confirm-email)", re.I)),
    (AuthEndpointType.MFA_CHALLENGE, re.compile(r"/(?:mfa/challenge|2fa/challenge|auth/mfa)", re.I)),
    (AuthEndpointType.MFA_VERIFY, re.compile(r"/(?:mfa/verify|2fa/verify|mfa/check)", re.I)),
    (AuthEndpointType.OTP_REQUEST, re.compile(r"/(?:otp/request|otp/send|request-otp)", re.I)),
    (AuthEndpointType.OTP_VERIFY, re.compile(r"/(?:otp/verify|verify-otp)", re.I)),
    (AuthEndpointType.MAGIC_LINK, re.compile(r"/(?:magic-link|auth/magic)", re.I)),
    (AuthEndpointType.OAUTH_AUTHORIZE, re.compile(r"/(?:oauth/authorize|authorize|connect/authorize)", re.I)),
    (AuthEndpointType.OAUTH_CALLBACK, re.compile(r"/(?:oauth/callback|auth/callback|signin-oidc)", re.I)),
    (AuthEndpointType.SESSION_REFRESH, re.compile(r"/(?:auth/refresh|token/refresh|refresh-session)", re.I)),
    (AuthEndpointType.ACCOUNT_RECOVERY, re.compile(r"/(?:account/recovery|backup-code|recover)", re.I)),
    (AuthEndpointType.API_AUTH, re.compile(r"/(?:api/v[0-9]+/auth|api/keys|tokens)", re.I)),
]


class AuthSurfaceDiscovery:
    """Discovers and catalogs authentication endpoints across the attack surface"""

    @classmethod
    def classify_endpoint(
        cls,
        path: str,
        method: str = "GET",
        parameters: Optional[List[str]] = None,
        cookies: Optional[List[str]] = None,
        headers: Optional[List[str]] = None,
        auth_required: bool = False
    ) -> AuthEndpointRecord:
        """Classifies a path into an exact authentication archetype"""
        norm_path = urlparse(path).path or "/"
        method_upper = method.upper()

        archetype = AuthEndpointType.PROTECTED_RESOURCE if auth_required else AuthEndpointType.PUBLIC_RESOURCE

        for arch, pattern in _ARCHETYPE_PATTERNS:
            if pattern.search(norm_path):
                archetype = arch
                break

        ep_id = f"auth_{method_upper}_{hashlib.md5(norm_path.encode()).hexdigest()[:6]}"
        return AuthEndpointRecord(
            endpoint_id=ep_id,
            path=norm_path,
            method=method_upper,
            archetype=archetype,
            parameters=parameters or [],
            cookies_observed=cookies or [],
            headers_observed=headers or [],
            requires_auth=auth_required or (archetype in (AuthEndpointType.CHANGE_PASSWORD, AuthEndpointType.LOGOUT, AuthEndpointType.PROTECTED_RESOURCE))
        )

    @classmethod
    def discover_from_endpoints(cls, endpoints: List[Dict[str, Any]]) -> List[AuthEndpointRecord]:
        """Catalogs multiple endpoint definitions"""
        records = []
        for ep in endpoints:
            rec = cls.classify_endpoint(
                path=ep.get("path") or ep.get("endpoint") or "/",
                method=ep.get("method", "GET"),
                parameters=ep.get("parameters") or ep.get("params") or [],
                auth_required=ep.get("auth_required", False)
            )
            records.append(rec)
        return records
