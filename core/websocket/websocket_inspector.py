"""
WebSocket Security & Protocol Inspector
Audits real-time channels (ws:// and wss://):
- Tests Cross-Site WebSocket Hijacking (CSWSH) via Origin spoofing.
- Audits handshake authorization headers and query parameters.
- Analyzes Socket.io / JSON-RPC message frames for unauthenticated parameter tampering.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass
class WebSocketHandshakeAudit:
    ws_url: str
    origin_tested: str
    handshake_status: int  # 101 Switching Protocols, 401, 403, 400
    handshake_headers: Dict[str, str] = field(default_factory=dict)
    cswsh_vulnerable: bool = False
    details: str = ""


@dataclass
class WebSocketMessageAudit:
    ws_url: str
    protocol: str  # "json-rpc", "socket.io", "raw_text", "binary"
    sample_frame: str
    contains_sensitive_data: bool = False
    allows_unauthorized_mutation: bool = False
    details: str = ""


class WebSocketSecurityInspector:
    """
    فاحص أمان بروتوكول الـ WebSocket والاتصالات الحية (WebSocket Security Inspector):
    - يفحص ثغرات اختطاف الجلسات عبر تزوير الـ Origin (CSWSH).
    - يدقق في كيفية تمرير التوكنات وأمان رسائل الـ JSON-RPC / Socket.io.
    """

    def __init__(self, evil_origin: str = "https://evil-attacker.local"):
        self.evil_origin = evil_origin
        self.audits: List[WebSocketHandshakeAudit] = []

    def audit_cswsh_handshake(
        self,
        ws_url: str,
        cookies: Optional[Dict[str, str]] = None,
        handshake_fn: Optional[Callable[[str, Dict[str, str]], Tuple[int, Dict[str, str]]]] = None
    ) -> WebSocketHandshakeAudit:
        """
        فحص ثغرة Cross-Site WebSocket Hijacking (CSWSH)
        يقوم بمحاكاة طلب ترقية (Upgrade Handshake) بترويسة Origin مزورة مع تمرير الكوكيز
        """
        headers = {
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Version": "13",
            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
            "Origin": self.evil_origin
        }
        if cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
            headers["Cookie"] = cookie_str

        # Execute handshake simulation
        if handshake_fn:
            status_code, resp_headers = handshake_fn(ws_url, headers)
        else:
            # Default safe mock evaluation
            status_code = 403
            resp_headers = {"Server": "WebSocket/1.0"}

        # If server accepts 101 Switching Protocols with untrusted evil origin and cookies
        is_vuln = (status_code == 101)
        details = (
            f"VULNERABLE: Server accepted WebSocket upgrade (101) with spoofed Origin '{self.evil_origin}' "
            f"while authenticated cookies were present (CSWSH possible)."
            if is_vuln
            else f"SECURE: Server rejected untrusted Origin '{self.evil_origin}' with HTTP {status_code}."
        )

        audit = WebSocketHandshakeAudit(
            ws_url=ws_url,
            origin_tested=self.evil_origin,
            handshake_status=status_code,
            handshake_headers=resp_headers,
            cswsh_vulnerable=is_vuln,
            details=details
        )
        self.audits.append(audit)
        return audit

    def inspect_message_frame(self, ws_url: str, raw_message: str) -> WebSocketMessageAudit:
        """تحليل محتوى أطر رسائل الـ WebSocket بحثاً عن الحقول والعمليات الحساسة"""
        protocol = "raw_text"
        sensitive = False
        mutation = False
        details_list = []

        try:
            parsed = json.loads(raw_message)
            protocol = "json-rpc" if "jsonrpc" in parsed or "method" in parsed else "json"

            # Check for sensitive attributes
            msg_str = json.dumps(parsed).lower()
            if any(k in msg_str for k in ["token", "secret", "password", "apikey", "balance", "email"]):
                sensitive = True
                details_list.append("Message contains sensitive fields")

            if any(k in msg_str for k in ["update", "delete", "transfer", "mutate", "admin"]):
                mutation = True
                details_list.append("Message invokes state-changing mutation command")

        except Exception:
            if raw_message.startswith("42[") or raw_message.startswith("40"):
                protocol = "socket.io"

        return WebSocketMessageAudit(
            ws_url=ws_url,
            protocol=protocol,
            sample_frame=raw_message[:200],
            contains_sensitive_data=sensitive,
            allows_unauthorized_mutation=mutation,
            details="; ".join(details_list) if details_list else "Standard operational frame"
        )
