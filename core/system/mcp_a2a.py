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
import math
import os
import secrets
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("hunter_ai.mcp_a2a")

A2A_SECRET_ENV = "HUNTER_A2A_SECRET"
DEFAULT_MAX_MESSAGE_AGE_SECONDS = 60.0


class MCPMessageBus:
    """In-memory communication bus routing messages between MCP clients"""
    _instance: Optional[MCPMessageBus] = None

    def __init__(self):
        self._mailboxes: Dict[str, List[Dict[str, Any]]] = {}
        # Ephemeral CSPRNG per-bus key when no explicit/env secret is configured
        self._ephemeral_key: bytes = secrets.token_bytes(32)

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
    Enforces authentication, freshness (60s age window), and nonce replay protection.
    """
    def __init__(
        self,
        agent_id: str,
        secret_key: Optional[str] = None,
        bus: Optional[MCPMessageBus] = None,
        max_age_seconds: float = DEFAULT_MAX_MESSAGE_AGE_SECONDS,
    ):
        self.agent_id = agent_id
        self.bus = bus or MCPMessageBus.get_shared()
        self.max_age_seconds = float(max_age_seconds)
        if secret_key is not None:
            if not str(secret_key).strip():
                raise ValueError("MCPClient secret_key must not be empty")
            self.secret_key = str(secret_key).encode("utf-8")
        else:
            env_secret = os.getenv(A2A_SECRET_ENV, "").strip()
            if env_secret:
                self.secret_key = env_secret.encode("utf-8")
            else:
                self.secret_key = self.bus._ephemeral_key
        self.outbox: List[Dict[str, Any]] = []
        self.inbox: List[Dict[str, Any]] = []
        self._seen_nonces: Dict[str, float] = {}

    def _prune_nonces(self, now: float) -> None:
        cutoff = now - max(self.max_age_seconds * 2.0, 120.0)
        expired = [n for n, ts in self._seen_nonces.items() if ts < cutoff]
        for n in expired:
            del self._seen_nonces[n]

    def _generate_signature(
        self,
        sender: str,
        recipient: str,
        timestamp: float,
        payload: Dict[str, Any],
        nonce: str = "",
    ) -> str:
        serialized_payload = json.dumps(payload, sort_keys=True, default=str)
        canonical = f"{sender}|{recipient}|{timestamp:.4f}|{nonce}|{serialized_payload}"
        return hmac.new(self.secret_key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()

    def verify_signature(self, message: Dict[str, Any]) -> bool:
        """
        Validates cryptographic HMAC-SHA256 signature, 60-second timestamp age window,
        and single-use nonce replay cache to enforce authenticity and replay protection.
        """
        if not isinstance(message, dict):
            return False

        sender = str(message.get("sender_id", ""))
        recipient = str(message.get("recipient_id", ""))
        payload = message.get("payload", {})
        sig = message.get("signature", "")
        nonce = message.get("nonce", "")

        if not sig or not isinstance(sig, str):
            logger.warning("Rejected unauthenticated message: missing signature")
            return False

        if not nonce or not isinstance(nonce, str):
            logger.warning("Rejected A2A message from '%s': missing replay nonce", sender)
            return False

        try:
            timestamp = float(message.get("timestamp"))
        except (TypeError, ValueError):
            logger.warning("Rejected A2A message from '%s': invalid timestamp", sender)
            return False

        if not math.isfinite(timestamp):
            logger.warning("Rejected A2A message from '%s': non-finite timestamp", sender)
            return False

        now = time.time()
        age = abs(now - timestamp)
        if age > self.max_age_seconds:
            logger.warning(
                "Rejected stale/future A2A message from '%s': age=%.2fs > %.2fs",
                sender, age, self.max_age_seconds,
            )
            return False

        self._prune_nonces(now)
        if nonce in self._seen_nonces:
            logger.warning("Rejected replayed A2A message from '%s': duplicate nonce '%s'", sender, nonce[:12])
            return False

        expected_sig = self._generate_signature(sender, recipient, timestamp, payload, nonce=nonce)
        is_valid = hmac.compare_digest(sig, expected_sig)
        if not is_valid:
            logger.warning("A2A signature verification failed for sender '%s'", sender)
            return False

        self._seen_nonces[nonce] = now
        return True

    def send_message(self, recipient_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Signs and dispatches an authenticated message with a CSPRNG replay nonce.
        """
        now = time.time()
        msg_id = f"MSG-{uuid.uuid4().hex[:8].upper()}"
        nonce = secrets.token_hex(16)
        signature = self._generate_signature(self.agent_id, recipient_id, now, payload, nonce=nonce)

        message = {
            "message_id": msg_id,
            "sender_id": self.agent_id,
            "recipient_id": recipient_id,
            "timestamp": now,
            "nonce": nonce,
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
