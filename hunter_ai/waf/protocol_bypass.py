"""
HunterAI WAF Protocol Bypass
=============================

تقنيات التجاوز عبر البروتوكولات البديلة (WebSocket و gRPC) التي قد لا
تفحصها الـ WAF التقليدية بنفس عمق طلبات HTTP العادية.

المصدر: أبحاث 2025-2026 حول ثغرات البروتوكولات البديلة في WAFs.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ProtocolBypassResult:
    target: str
    protocol: str  # "websocket" or "grpc"
    technique: str
    payload: str
    endpoint: str
    verified: bool = False
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "protocol": self.protocol,
            "technique": self.technique,
            "payload": self.payload,
            "endpoint": self.endpoint,
            "verified": self.verified,
            "timestamp": self.timestamp,
        }


class WebSocketBypass:
    """
    تجاوز الـ WAF عبر بروتوكول WebSocket.
    بعد ترقية الاتصال (Upgrade)، تتحول الرسائل إلى Frames وليس طلبات HTTP
    منفصلة، وكثير من WAFs لا تفحص محتواها بعمق كافٍ.
    """

    def __init__(self, safety_loop=None):
        self.safety_loop = safety_loop

    def generate_upgrade_request(
        self,
        target: str,
        path: str = "/ws",
        host: Optional[str] = None,
    ) -> Dict[str, str]:
        """
        يولد طلب ترقية WebSocket بسيط.
        """
        key = str(uuid.uuid4())
        headers = {
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": key,
            "Sec-WebSocket-Version": "13",
            "Host": host or target,
        }
        return {
            "method": "GET",
            "path": path,
            "headers": headers,
        }

    def craft_malicious_frame(
        self,
        payload: str,
        opcode: int = 1,  # text frame
    ) -> Dict[str, Any]:
        """
        يصنع إطار WebSocket يحمل حمولة خبيثة.
        """
        return {
            "opcode": opcode,
            "payload": payload,
            "masked": True,
            "note": "يُرسَل هذا الإطار بعد ترقية الاتصال بـ WebSocket",
        }

    def test_websocket(
        self,
        target: str,
        payload: str,
        path: str = "/ws",
    ) -> Dict[str, Any]:
        """
        يختبر تجاوز WAF عبر WebSocket مع فحص السلامة العصبية-الرمزية.
        """
        if self.safety_loop:
            check = self.safety_loop.check_command(
                command=f"waf-websocket-bypass:{path}",
                target=target,
                require_proof=False,
            )
            if check.verdict.value == "BLOCKED":
                return {
                    "status": "BLOCKED_BY_SAFETY",
                    "reason": check.reason,
                }

        upgrade = self.generate_upgrade_request(target, path)
        frame = self.craft_malicious_frame(payload)

        return {
            "status": "READY",
            "protocol": "websocket",
            "upgrade_request": upgrade,
            "malicious_frame": frame,
            "technique": "websocket_upgrade_bypass",
            "note": "يُستخدم بعد إنشاء اتصال WebSocket ناجح",
        }


class GrpcBypass:
    """
    تجاوز الـ WAF عبر بروتوكول gRPC (HTTP/2 Bidirectional Streaming).
    الرسائل داخل التدفق ليست طلبات HTTP فردية، وقد لا تفهم بعض WAFs
    تنسيق Protobuf بشكل كامل.
    """

    def __init__(self, safety_loop=None):
        self.safety_loop = safety_loop

    def craft_grpc_request(
        self,
        service: str,
        method: str,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        يصنع طلب gRPC مع حمولة مشفرة بـ Protobuf (تمثيل مبسط).
        """
        return {
            "service": service,
            "method": method,
            "content_type": "application/grpc+proto",
            "payload": payload,
            "encoding": "protobuf",
            "note": "الرسالة تُرسَل داخل تدفق gRPC، ليست طلب HTTP فردي",
        }

    def test_grpc(
        self,
        target: str,
        service: str,
        method: str,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        يختبر تجاوز WAF عبر gRPC مع فحص السلامة العصبية-الرمزية.
        """
        if self.safety_loop:
            check = self.safety_loop.check_command(
                command=f"waf-grpc-bypass:{service}.{method}",
                target=target,
                require_proof=False,
            )
            if check.verdict.value == "BLOCKED":
                return {
                    "status": "BLOCKED_BY_SAFETY",
                    "reason": check.reason,
                }

        grpc_req = self.craft_grpc_request(service, method, payload)

        return {
            "status": "READY",
            "protocol": "grpc",
            "grpc_request": grpc_req,
            "technique": "grpc_stream_bypass",
            "note": "يُستهدف نقاط نهاية gRPC على المنفذ 443 أو 80",
        }


class ProtocolBypassManager:
    """
    مدير تقنيات التجاوز عبر البروتوكولات البديلة.
    """

    def __init__(self, safety_loop=None):
        self.websocket = WebSocketBypass(safety_loop)
        self.grpc = GrpcBypass(safety_loop)
        self.safety_loop = safety_loop

    def test_all(
        self,
        target: str,
        payload: str,
        grpc_service: str = "UserService",
        grpc_method: str = "GetUser",
    ) -> Dict[str, Any]:
        """
        يختبر جميع تقنيات التجاوز عبر البروتوكولات.
        """
        results = {
            "target": target,
            "websocket": self.websocket.test_websocket(target, payload),
            "grpc": self.grpc.test_grpc(
                target, grpc_service, grpc_method, {"input": payload}
            ),
            "timestamp": time.time() if False else __import__("time").time(),
        }
        return results
