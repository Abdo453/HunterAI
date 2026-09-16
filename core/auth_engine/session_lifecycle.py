"""
HunterAI Session Lifecycle & Invalidation Auditor
=================================================
Audits:
1. Session Fixation (pre-auth session token unchanged post-auth).
2. Post-Logout Invalidation (session token remains usable after logout).
3. Post-Password-Change Revocation (stale sessions stay active).
4. Contextual Cookie Flag Integrity (Secure, HttpOnly, SameSite).
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("hunter_ai.auth.session_lifecycle")


class SessionLifecycleAuditor:
    """Audits session token management and invalidation behavior"""

    @classmethod
    def evaluate_session_fixation(
        cls,
        pre_auth_cookies: Dict[str, str],
        post_auth_cookies: Dict[str, str],
        session_cookie_names: Optional[List[str]] = None
    ) -> Tuple[bool, str]:
        """
        Session Fixation Invariant:
        Post-authentication session token MUST be rotated to a new cryptographically secure token.
        """
        targets = session_cookie_names or ["session", "sessionid", "sid", "connect.sid", "PHPSESSID", "JSESSIONID", "token"]

        for target in targets:
            pre_val = pre_auth_cookies.get(target)
            post_val = post_auth_cookies.get(target)
            if pre_val and post_val:
                if pre_val == post_val:
                    return True, f"Session Fixation Confirmed: Cookie '{target}' retained identical value '{pre_val[:8]}...' post-authentication."

        return False, "Session properly rotated post-authentication."

    @classmethod
    def evaluate_logout_invalidation(
        cls,
        post_logout_status: int,
        sensitive_data_returned: bool,
        session_token_preview: str = ""
    ) -> Tuple[bool, str]:
        """
        Post-Logout Invalidation Invariant:
        Terminated session token MUST NOT access protected resources (must receive 401/403 or redirect to login).
        """
        if post_logout_status == 200 and sensitive_data_returned:
            return True, f"Post-Logout Session Reuse Confirmed: Terminated session token successfully accessed protected resource (HTTP 200)."
        return False, "Session successfully invalidated post-logout."

    @classmethod
    def evaluate_password_change_invalidation(
        cls,
        old_session_status: int,
        sensitive_data_returned: bool
    ) -> Tuple[bool, str]:
        """
        Password Change Revocation Invariant:
        When password is changed, existing concurrent sessions should be revoked.
        """
        if old_session_status == 200 and sensitive_data_returned:
            return True, "Post-Password-Change Session Reuse Confirmed: Pre-existing session remained valid after credential change."
        return False, "Pre-existing sessions properly invalidated upon password change."

    @classmethod
    def evaluate_cookie_security(
        cls,
        cookie_attributes: Dict[str, Any],
        is_https: bool = True
    ) -> List[str]:
        """
        Context-aware cookie flags audit:
        Flags missing HttpOnly, Secure, or SameSite only in sensitive security contexts.
        """
        issues = []
        name = cookie_attributes.get("name", "session")
        flags = cookie_attributes.get("flags", {})

        is_session = any(k in name.lower() for k in ("sess", "token", "auth", "jwt", "id"))
        if not is_session:
            return issues  # Do not spam for non-sensitive tracking cookies

        if not flags.get("HttpOnly", False):
            issues.append(f"Cookie '{name}' lacks HttpOnly flag (DOM XSS token theft hazard).")
        if is_https and not flags.get("Secure", False):
            issues.append(f"Cookie '{name}' lacks Secure flag on HTTPS endpoint (Cleartext wire transmission hazard).")
        if not flags.get("SameSite"):
            issues.append(f"Cookie '{name}' lacks SameSite attribute (Cross-site request submission hazard).")

        return issues
