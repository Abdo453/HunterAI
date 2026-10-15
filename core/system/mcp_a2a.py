"""
HunterAI Model Context Protocol (MCP) & Agent-to-Agent (A2A) Client (Phase 12)
=============================================================================
Enables authenticated, tamper-evident Agent-to-Agent communication:
  1. Cryptographic message signing via HMAC-SHA256
  2. Strict authentication enforcement via verify_signature()
  3. Direct and routed message delivery between autonomous agents
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("hunter_ai.mcp_a2a")


class MCPMessageBus:
    """In-memory communication bus routing messages between MCP clients"""
    _instance: Optional[MCPMessageBus] = None

    def __init__(self):
        self._mailboxes: Dict[str, List[Dict[str, Any]]] = {}

    @classmethod
    def get_shared(cls) -> MCPMessageBus:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def deliver(self, recipient_id: str, message: Dict[str, Any]) -> None:
        if recipient_id not in self._mailboxes:
            self._mailboxes[recipient_id] = []
        self._mailboxes[recipient_id].append(message)

    def retrieve(self, recipient_id: str) -> Optional[Dict[str, Any]]:
        box = self._mailboxes.get(recipient_id)
        if box and len(box) > 0:
            return box.pop(0)
        return None

    def clear(self) -> None:
        self._mailboxes.clear()


class MCPClient:
    """
    Client for Agent-to-Agent communication over MCP.
    Enforces authentication and integrity via cryptographic signatures.
    """
    def __init__(
        self,
        agent_id: str,
        secret_key: str = "hunter_a2a_master_key",
        bus: Optional[MCPMessageBus] = None,
    ):
        self.agent_id = agent_id
        self.secret_key = secret_key.encode("utf-8")
        self.bus = bus or MCPMessageBus.get_shared()
        self.outbox: List[Dict[str, Any]] = []
        self.inbox: List[Dict[str, Any]] = []

    def _generate_signature(self, sender: str, recipient: str, timestamp: float, payload: Dict[str, Any]) -> str:
        serialized_payload = json.dumps(payload, sort_keys=True, default=str)
        canonical = f"{sender}|{recipient}|{timestamp:.4f}|{serialized_payload}"
        return hmac.new(self.secret_key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()

    def verify_signature(self, message: Dict[str, Any]) -> bool:
        """
        Validates cryptographic HMAC-SHA256 signature to enforce authenticity and non-repudiation.
        """
        sender = message.get("sender_id", "")
        recipient = message.get("recipient_id", "")
        timestamp = float(message.get("timestamp", 0.0))
        payload = message.get("payload", {})
        sig = message.get("signature", "")

        if not sig:
            logger.warning("Rejected unauthenticated message: missing signature")
            return False

        expected_sig = self._generate_signature(sender, recipient, timestamp, payload)
        is_valid = hmac.compare_digest(sig, expected_sig)
        if not is_valid:
            logger.warning("A2A signature verification failed for sender '%s'", sender)
        return is_valid

    def send_message(self, recipient_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Signs and dispatches an authenticated message to another agent.
        """
        now = time.time()
        msg_id = f"MSG-{uuid.uuid4().hex[:8].upper()}"
        signature = self._generate_signature(self.agent_id, recipient_id, now, payload)

        message = {
            "message_id": msg_id,
            "sender_id": self.agent_id,
            "recipient_id": recipient_id,
            "timestamp": now,
            "payload": payload,
            "signature": signature,
        }

        self.outbox.append(message)
        self.bus.deliver(recipient_id, message)
        logger.info("MCP message dispatched: %s -> %s (msg_id=%s)", self.agent_id, recipient_id, msg_id)
        return message

    def receive_message(self) -> Optional[Dict[str, Any]]:
        """
        Pulls next message from mailbox and validates cryptographic signature.
        Rejects tampered or unauthenticated messages.
        """
        raw_msg = self.bus.retrieve(self.agent_id)
        if not raw_msg:
            return None

        if not self.verify_signature(raw_msg):
            logger.error("Tampered message discarded in mailbox for %s: %s", self.agent_id, raw_msg.get("message_id"))
            return None

        self.inbox.append(raw_msg)
        return raw_msg
