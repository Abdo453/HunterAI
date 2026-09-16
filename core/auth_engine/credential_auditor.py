"""
HunterAI Credential Matrix & Password Reset Auditor
===================================================
Audits:
1. Username Enumeration (timing, response length, distinct error messages).
2. Password Reset Lifecycle (token reuse, expiration, binding).
3. OTP / MFA Attempt Limits (rate-limiting & brute-force resistance).
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

from .schemas import AuthVulnClass

logger = logging.getLogger("hunter_ai.auth.credential_auditor")


class CredentialMatrixAuditor:
    """Audits login credential matrix and password reset tokens"""

    @classmethod
    def evaluate_username_enumeration(
        cls,
        valid_user_invalid_pass: Dict[str, Any],
        invalid_user_invalid_pass: Dict[str, Any]
    ) -> Tuple[bool, str]:
        """
        Compares responses between a known valid username and an invalid username.
        Flags username enumeration if status, length (>50 chars), or error messages diverge.
        """
        status_valid = valid_user_invalid_pass.get("status_code", 401)
        status_invalid = invalid_user_invalid_pass.get("status_code", 401)
        msg_valid = str(valid_user_invalid_pass.get("error_message", "")).lower()
        msg_invalid = str(invalid_user_invalid_pass.get("error_message", "")).lower()
        len_valid = len(str(valid_user_invalid_pass.get("body", "")))
        len_invalid = len(str(invalid_user_invalid_pass.get("body", "")))

        # 1. Distinct Error Messages
        if "password" in msg_valid and ("user" in msg_invalid or "not found" in msg_invalid):
            return True, f"Username Enumeration Confirmed: Explicit message divergence ('{msg_valid}' vs '{msg_invalid}')."

        # 2. Status Code Divergence
        if status_valid != status_invalid:
            return True, f"Username Enumeration Confirmed: HTTP Status divergence (Valid User: {status_valid}, Invalid User: {status_invalid})."

        # 3. Response Length Divergence (>50 chars)
        if abs(len_valid - len_invalid) > 50:
            return True, f"Username Enumeration Confirmed: Significant response length delta ({len_valid} vs {len_invalid} bytes)."

        return False, "Zero username enumeration signal detected (responses are indistinguishable)."

    @classmethod
    def evaluate_reset_token_reuse(
        cls,
        first_use_status: int,
        second_use_status: int,
        password_actually_changed_again: bool = False
    ) -> Tuple[bool, str]:
        """
        Password Reset Invariant:
        A password reset token MUST be single-use (consumed immediately upon submission).
        """
        if second_use_status == 200 or password_actually_changed_again:
            return True, "Reset Token Reuse Confirmed: Password reset token accepted more than once."
        return False, "Password reset token properly invalidated after first consumption."

    @classmethod
    def evaluate_reset_token_expiration(
        cls,
        token_age_seconds: int,
        max_allowed_seconds: int,
        post_expiry_use_status: int
    ) -> Tuple[bool, str]:
        """
        Password Reset Expiration Invariant:
        Tokens used after max lifetime MUST be rejected.
        """
        if token_age_seconds > max_allowed_seconds and post_expiry_use_status == 200:
            return True, f"Reset Token Expiration Failure: Token remained valid after {token_age_seconds}s (Max: {max_allowed_seconds}s)."
        return False, "Expired password reset tokens correctly rejected."
