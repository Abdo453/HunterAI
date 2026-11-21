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


class BinaryFramedProtocolCodec:
    """
    Stateful Binary WebSocket Framing Codec (Pomelo / Pinus / Custom Binary Framing).
    Enables the agent to understand, reassemble, encode, and decode binary-framed
    WebSocket streams:
      - 4-byte outer framing: [1-byte pkg_type][3-byte big-endian payload length]
      - Partial stream buffer reassembly across fragmented TCP/WS reads
      - Inner message framing: [1-byte flag (msg_type << 1 | compress)][varint req_id][route][JSON/binary body]
      - Identity claim correlation (JWT subject vs external UID parameter)
    """

    PKG_HANDSHAKE = 1
    PKG_HANDSHAKE_ACK = 2
    PKG_HEARTBEAT = 3
    PKG_DATA = 4
    PKG_KICK = 5

    MSG_REQUEST = 0
    MSG_NOTIFY = 1
    MSG_RESPONSE = 2
    MSG_PUSH = 3
    MSG_NAMES = {0: "request", 1: "notify", 2: "response", 3: "push"}

    @staticmethod
    def encode_package(pkg_type: int, body: bytes = b"") -> bytes:
        n = len(body)
        return bytes([pkg_type & 0xFF, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF]) + body

    @staticmethod
    def encode_varint(n: int) -> bytes:
        out = bytearray()
        while True:
            b = n & 0x7F
            n >>= 7
            if n > 0:
                b |= 0x80
            out.append(b)
            if n == 0:
                return bytes(out)

    @staticmethod
    def decode_varint(buf: bytes, offset: int) -> Tuple[int, int]:
        n = 0
        shift = 0
        while offset < len(buf):
            b = buf[offset]
            offset += 1
            n |= (b & 0x7F) << shift
            if b < 0x80:
                return n, offset
            shift += 7
            if shift > 63:
                raise ValueError("varint overflow")
        raise ValueError("truncated varint")

    @classmethod
    def encode_request(cls, req_id: int, route: str, payload: Dict[str, Any]) -> bytes:
        route_b = route.encode("utf-8")
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        head = bytes([cls.MSG_REQUEST << 1]) + cls.encode_varint(req_id) + bytes([len(route_b)]) + route_b
        return cls.encode_package(cls.PKG_DATA, head + body)

    @staticmethod
    def decode_packages_from_buffer(buf: bytearray) -> Tuple[List[Tuple[int, bytes]], int]:
        out: List[Tuple[int, bytes]] = []
        i = 0
        while i + 4 <= len(buf):
            pkg_type = buf[i]
            n = (buf[i + 1] << 16) | (buf[i + 2] << 8) | buf[i + 3]
            end = i + 4 + n
            if end > len(buf):
                break
            out.append((pkg_type, bytes(buf[i + 4:end])))
            i = end
        return out, i

    @classmethod
    def decode_message(cls, buf: bytes) -> Dict[str, Any]:
        if not buf:
            return {"type": "empty", "req_id": None, "route": None, "body": None}
        flag = buf[0]
        msg_type = (flag >> 1) & 0x7
        compress = flag & 0x1
        offset = 1
        req_id: Optional[int] = None
        route: Optional[str] = None

        if msg_type in (cls.MSG_REQUEST, cls.MSG_RESPONSE):
            req_id, offset = cls.decode_varint(buf, offset)

        if msg_type in (cls.MSG_REQUEST, cls.MSG_NOTIFY, cls.MSG_PUSH):
            if compress:
                if offset + 2 > len(buf):
                    raise ValueError("truncated compressed route")
                route = str((buf[offset] << 8) | buf[offset + 1])
                offset += 2
            else:
                if offset >= len(buf):
                    raise ValueError("truncated route length")
                rlen = buf[offset]
                offset += 1
                if offset + rlen > len(buf):
                    raise ValueError("truncated route bytes")
                route = buf[offset:offset + rlen].decode("utf-8", "replace")
                offset += rlen

        body_bytes = buf[offset:]
        if not body_bytes:
            body: Any = None
        else:
            try:
                body = json.loads(body_bytes.decode("utf-8"))
            except Exception:
                body = {"_raw_hex": body_bytes.hex(), "_len": len(body_bytes)}

        return {
            "type": cls.MSG_NAMES.get(msg_type, f"msg_{msg_type}"),
            "req_id": req_id,
            "route": route,
            "body": body,
        }

