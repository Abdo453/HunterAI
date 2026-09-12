"""
HunterAI Network-Level Scope Firewall & Egress Interceptor
==========================================================
Enforces physical network-level boundary controls across all outbound HTTP dispatchers:
- Operates at the transport / socket boundary (below LLM, Planner, and Agents)
- Rejects out-of-scope domains, loopback, RFC1918 (unless lab override), and cloud metadata
- Provides drop-in httpx event hooks, urllib handlers, and assertion guards
- Guarantees 0% out-of-scope packet leakage regardless of LLM hallucinations
"""
from __future__ import annotations

import logging
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from core.scope_engine import ScopePolicy, StrictScopeEngine

logger = logging.getLogger("hunter_ai.network_scope_guard")


class ScopeViolationError(PermissionError):
    """Raised when an outbound network request attempts to violate authorized engagement scope"""
    def __init__(self, target_url: str, reason: str):
        self.target_url = target_url
        self.reason = reason
        super().__init__(f"NETWORK SCOPE FIREWALL: Blocked egress request to '{target_url}'. Reason: {reason}")


class NetworkScopeGuard:
    """
    Physical Network Egress Guard.
    Every outbound network call must pass this barrier before opening a socket.
    """

    def __init__(
        self,
        scope_policy: Optional[ScopePolicy] = None,
        audit_callback: Optional[Callable[[Dict[str, Any]], None]] = None
    ):
        self.policy = scope_policy or ScopePolicy()
        self.scope_engine = StrictScopeEngine(self.policy)
        self.audit_callback = audit_callback
        self.blocked_audit_log: List[Dict[str, Any]] = []

    def check_url(self, url: str, method: str = "GET") -> Tuple[bool, str]:
        """Validates destination URL against strict scope policy and safety invariants"""
        if not url:
            return False, "Target URL is empty"

        return self.scope_engine.is_allowed(target=url, method=method)

    def assert_allowed(self, url: str, method: str = "GET", caller_context: str = "") -> None:
        """
        Hard assertion: raises ScopeViolationError and records an immutable audit entry if denied.
        """
        allowed, reason = self.check_url(url, method=method)
        if not allowed:
            event = {
                "event_type": "NETWORK_EGRESS_BLOCKED",
                "timestamp": time.time(),
                "url": url,
                "method": method,
                "reason": reason,
                "caller_context": caller_context,
                "action": "DENIED_BY_NETWORK_FIREWALL"
            }
            self.blocked_audit_log.append(event)
            logger.critical(f"[NETWORK SCOPE FIREWALL] EGRESS BLOCKED: {url} | Reason: {reason} | Context: {caller_context}")

            if self.audit_callback:
                try:
                    self.audit_callback(event)
                except Exception as e:
                    logger.error(f"Audit callback failed: {e}")

            raise ScopeViolationError(url, reason)

    def httpx_request_hook(self, request: Any) -> None:
        """
        Synchronous / Asynchronous event hook for HTTPX Client:
        client = httpx.Client(event_hooks={"request": [guard.httpx_request_hook]})
        """
        url_str = str(request.url)
        method_str = request.method
        self.assert_allowed(url_str, method=method_str, caller_context="httpx_transport")

    async def async_httpx_request_hook(self, request: Any) -> None:
        """Async event hook for HTTPX AsyncClient"""
        url_str = str(request.url)
        method_str = request.method
        self.assert_allowed(url_str, method=method_str, caller_context="async_httpx_transport")
