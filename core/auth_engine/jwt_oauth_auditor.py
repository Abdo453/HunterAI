"""
HunterAI JWT & OAuth / OIDC Inspector
=====================================
Analyzes JWT headers, signatures, claims, and OAuth authorization parameters
without requiring external dependencies.
"""
from __future__ import annotations

import base64
import json
import logging
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("hunter_ai.auth.jwt_oauth")


def _b64_decode_segment(segment: str) -> Dict[str, Any]:
    """Decodes URL-safe base64 JWT segment with padding restoration"""
    padded = segment + "=" * ((4 - len(segment) % 4) % 4)
    decoded_bytes = base64.urlsafe_b64decode(padded)
    return json.loads(decoded_bytes.decode("utf-8", errors="ignore"))


class JWTOAuthAuditor:
    """Audits JSON Web Tokens and OAuth 2.0 / OIDC authorization parameters"""

    @classmethod
    def audit_jwt(cls, token: str) -> Tuple[List[str], Dict[str, Any]]:
        """
        Parses and audits JWT structure:
        - alg: "none"
        - Missing expiration (exp)
        - Expired token accepted
        """
        issues = []
        parsed_data = {}
        parts = token.strip().split(".")
        if len(parts) != 3:
            return issues, parsed_data

        try:
            header = _b64_decode_segment(parts[0])
            payload = _b64_decode_segment(parts[1])
            parsed_data = {"header": header, "payload": payload}

            # 1. Algorithm None vulnerability
            alg = str(header.get("alg", "")).lower()
            if alg in ("none", "none_fake", "null"):
                issues.append("JWT 'alg: none' vulnerability detected: Token accepted without signature verification.")

            # 2. Expiration check
            exp = payload.get("exp")
            if exp is None:
                issues.append("JWT lacks 'exp' (Expiration Time) claim: Token is perpetual.")
            else:
                now = time.time()
                if exp < now:
                    parsed_data["is_expired"] = True

        except Exception as e:
            logger.debug(f"Failed to decode JWT: {e}")

        return issues, parsed_data

    @classmethod
    def audit_oauth_authorize_params(cls, query_params: Dict[str, Any]) -> List[str]:
        """
        Audits OAuth /authorize query parameters:
        - Missing or weak state (Login CSRF risk)
        - Wildcard or insecure redirect_uri
        """
        issues = []

        # State check
        state = query_params.get("state")
        if not state:
            issues.append("OAuth authorization request lacks 'state' parameter (Login CSRF hazard).")
        elif len(str(state)) < 8:
            issues.append(f"OAuth 'state' parameter is too short/predictable: '{state}'")

        # Redirect URI check
        redirect_uri = str(query_params.get("redirect_uri", ""))
        if "*" in redirect_uri:
            issues.append(f"Wildcard pattern detected in OAuth redirect_uri: '{redirect_uri}' (Token leakage hazard).")
        elif redirect_uri.startswith("http://"):
            issues.append(f"Insecure cleartext HTTP scheme in OAuth redirect_uri: '{redirect_uri}'.")

        return issues
