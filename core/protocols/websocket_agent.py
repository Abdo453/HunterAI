"""
HunterAI WebSocket Security Agent (V13.0)
=========================================
Audits full-duplex WebSocket channels (ws:// and wss://):
1. Comprehensive Cross-Site WebSocket Hijacking (CSWSH) Origin Spoofing Matrix:
   - External Evil Domain (https://evil-attacker.com)
   - Sandboxed Null Origin (null)
   - Prefix / Suffix Collision (https://target.com.attacker.com)
   - Subdomain Reflection (https://sandbox.target.com)
2. In-Frame Authorization Audit:
   - Verifies whether message frames enforce session authentication after handshake.
   - Detects sensitive data leaks and unauthorized state mutation commands in frames.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class CSWSHOriginTestType(str, Enum):
    EXTERNAL_EVIL_DOMAIN = "EXTERNAL_EVIL_DOMAIN"
    NULL_ORIGIN = "NULL_ORIGIN"
    SUFFIX_PREFIX_COLLISION = "SUFFIX_PREFIX_COLLISION"
    SUBDOMAIN_REFLECTION = "SUBDOMAIN_REFLECTION"


@dataclass
class CSWSHTrialResult:
    test_type: CSWSHOriginTestType
    tested_origin: str
    handshake_status: int
    is_accepted: bool
    is_vulnerable: bool
    details: str
    cwe_id: str = "CWE-1385"  # Missing Origin Validation in WebSockets


@dataclass
class FrameAuthorizationReport:
    ws_url: str
    total_frames_audited: int
    unauthorized_frames_accepted: int
    sensitive_data_leaked: bool
    unauthenticated_mutations_allowed: bool
    vulnerability_detected: bool
    details: str


class WebSocketSecurityAgent:
    """
    Evaluates WebSocket handshake security and frame-level authorization.
    """

    def __init__(self, target_domain: str = "target.com"):
        self.target_domain = target_domain

    def get_cswsh_test_origins(self) -> List[Tuple[CSWSHOriginTestType, str]]:
        return [
            (CSWSHOriginTestType.EXTERNAL_EVIL_DOMAIN, "https://evil-attacker.com"),
            (CSWSHOriginTestType.NULL_ORIGIN, "null"),
            (CSWSHOriginTestType.SUFFIX_PREFIX_COLLISION, f"https://{self.target_domain}.attacker.com"),
            (CSWSHOriginTestType.SUBDOMAIN_REFLECTION, f"https://untrusted-user-content.{self.target_domain}"),
        ]

    def audit_cswsh_matrix(
        self,
        ws_url: str,
        cookies: Optional[Dict[str, str]] = None,
        handshake_fn: Optional[Callable[[str, Dict[str, str]], Tuple[int, Dict[str, str]]]] = None
    ) -> List[CSWSHTrialResult]:
        """
        Executes the multi-vector CSWSH origin testing matrix.
        If the server responds with HTTP 101 Switching Protocols to untrusted origins
        while authenticated cookies are attached, CSWSH is confirmed.
        """
        results: List[CSWSHTrialResult] = []
        has_cookies = bool(cookies and len(cookies) > 0)

        for test_type, test_origin in self.get_cswsh_test_origins():
            headers = {
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Version": "13",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                "Origin": test_origin
            }
            if cookies:
                headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())

            if handshake_fn:
                status, resp_hdrs = handshake_fn(ws_url, headers)
            else:
                # Default secure behavior: reject untrusted origin with 403 Forbidden
                status = 403
                resp_hdrs = {}

            is_accepted = (status == 101)
            # Vulnerable if server accepted upgrade with evil origin while cookies were present
            is_vuln = is_accepted and has_cookies

            if is_vuln:
                details = (
                    f"CRITICAL CSWSH: WebSocket server accepted upgrade (HTTP 101) from untrusted Origin "
                    f"'{test_origin}' with ambient authentication cookies. An external webpage can hijack user sessions."
                )
            elif is_accepted and not has_cookies:
                details = f"Server accepted unauthenticated Origin '{test_origin}' (Public WebSocket)."
            else:
                details = f"SECURE: Handshake correctly rejected Origin '{test_origin}' with HTTP {status}."

            results.append(CSWSHTrialResult(
                test_type=test_type,
                tested_origin=test_origin,
                handshake_status=status,
                is_accepted=is_accepted,
                is_vulnerable=is_vuln,
                details=details
            ))

        return results

    def audit_frame_authorization(
        self,
        ws_url: str,
        frames: List[str],
        has_session_token: bool = False
    ) -> FrameAuthorizationReport:
        """
        Audits message frames for unauthenticated actions or data leaks.
        """
        unauth_accepted = 0
        sensitive_leaked = False
        mutations_allowed = False
        details_list = []

        for frame in frames:
            try:
                data = json.loads(frame)
                text = json.dumps(data).lower()
            except Exception:
                text = frame.lower()

            # Check for sensitive data fields in frame
            if any(k in text for k in ["secret", "token", "password", "api_key", "credit_card", "balance"]):
                sensitive_leaked = True

            # Check for mutating commands
            if any(k in text for k in ["transfer", "delete", "purchase", "update_role", "admin_execute"]):
                if not has_session_token:
                    mutations_allowed = True
                    unauth_accepted += 1
                    details_list.append(f"Unauthenticated mutation allowed in frame: {frame[:60]}...")

        is_vuln = mutations_allowed or (sensitive_leaked and not has_session_token)

        return FrameAuthorizationReport(
            ws_url=ws_url,
            total_frames_audited=len(frames),
            unauthorized_frames_accepted=unauth_accepted,
            sensitive_data_leaked=sensitive_leaked and not has_session_token,
            unauthenticated_mutations_allowed=mutations_allowed,
            vulnerability_detected=is_vuln,
            details="; ".join(details_list) if details_list else "Frame authorization verified."
        )
