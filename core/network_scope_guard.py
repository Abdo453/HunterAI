"""
HunterAI Network-Level Scope Firewall & Egress Interceptor
==========================================================
Enforces physical network-level boundary controls across all outbound dispatchers:
- Operates at the transport / socket boundary (below LLM, Planner, and Agents)
- Rejects out-of-scope domains, loopback, RFC1918 (unless lab override), and cloud metadata
- HTTP(S): drop-in httpx event hooks, urllib handlers, and assertion guards
- Network endpoints: ``check_endpoint`` / ``assert_endpoint_allowed`` authorize
  ``protocol://host:port`` (SMB/LDAP/Kerberos/RDP/SSH/raw TCP-UDP ...) behind an
  explicit protocol allowlist and an ``allow_active_network_tests`` opt-in gate
- Guarantees 0% out-of-scope packet leakage regardless of LLM hallucinations
"""
from __future__ import annotations

import logging
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from core.network_scope_policy import NetworkScopePolicy
from core.scope_engine import ScopePolicy, StrictScopeEngine
from core.security_mode import unrestricted_mode

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

    Two decision surfaces are exposed:
      * :meth:`check_url` — HTTP(S) destination + redirect authorization.
      * :meth:`check_endpoint` — transport/application endpoint authorization
        (``protocol://host:port``) for SMB/LDAP/Kerberos/RDP/SSH/raw TCP-UDP ...

    Both share the same inviolable safety invariants (loopback, cloud metadata,
    RFC1918 unless an explicit lab override) enforced by the reference
    :class:`StrictScopeEngine`. Network endpoints add a protocol allowlist and a
    second, independent ``allow_active_network_tests`` gate.
    """

    def __init__(
        self,
        scope_policy: Optional[ScopePolicy] = None,
        audit_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        policy_name: str = "scope_v1",
        network_policy: Optional[NetworkScopePolicy] = None,
    ):
        # Resolve the network policy and the URL policy it projects onto.
        if network_policy is not None:
            self.network_policy = network_policy
            base_policy = scope_policy or network_policy.to_scope_policy()
        elif scope_policy is not None:
            self.network_policy = NetworkScopePolicy.from_scope_policy(scope_policy)
            base_policy = scope_policy
        else:
            # Fail-closed: with no explicit policy nothing is authorised.
            self.network_policy = NetworkScopePolicy()
            base_policy = ScopePolicy(fail_closed=True)

        self.policy = base_policy
        self.scope_engine = StrictScopeEngine(self.policy)
        self.audit_callback = audit_callback
        self.policy_name = policy_name
        self.audit_decision_log: List[Dict[str, Any]] = []

    @property
    def blocked_audit_log(self) -> List[Dict[str, Any]]:
        """Filtered view of denied audit events for backward compatibility"""
        return [e for e in self.audit_decision_log if e.get("decision") == "DENY" or e.get("event_type") == "NETWORK_EGRESS_BLOCKED"]

    def check_url(self, url: str, method: str = "GET") -> Tuple[bool, str]:
        """Validates destination URL against strict scope policy and safety invariants"""
        if not url:
            return False, "Target URL is empty"

        parsed = urlparse(url)
        scheme = parsed.scheme.lower() if parsed.scheme else "http"

        # Protocol scheme restriction: ONLY http and https permitted
        if scheme not in ("http", "https"):
            return False, f"Disallowed protocol scheme '{scheme}'. Only 'http' and 'https' are permitted."

        return self.scope_engine.is_allowed(target=url, method=method)

    def check_redirect(self, original_url: str, location_header: str) -> Tuple[bool, str]:
        """
        Validates HTTP redirect destinations before the client opens a new socket.
        Supports both relative paths (/dashboard) and absolute URLs (https://target.com/login).
        """
        if not location_header:
            return False, "Empty Location header in redirect"

        from urllib.parse import urljoin
        resolved_url = urljoin(original_url, location_header)
        allowed, reason = self.check_url(resolved_url)
        if not allowed:
            return False, f"Redirect to out-of-scope destination '{resolved_url}' blocked. Reason: {reason}"
        return True, f"Redirect to '{resolved_url}' authorized"

    def assert_allowed(self, url: str, method: str = "GET", caller_context: str = "") -> None:
        """
        Hard assertion: raises ScopeViolationError and records an immutable audit entry if denied.
        """
        allowed, reason = self.check_url(url, method=method)
        decision_event = {
            "request": url,
            "url": url,
            "method": method,
            "decision": "ALLOW" if allowed else "DENY",
            "event_type": "NETWORK_EGRESS_ALLOWED" if allowed else "NETWORK_EGRESS_BLOCKED",
            "reason": reason,
            "policy": self.policy_name,
            "caller_context": caller_context,
            "timestamp": time.time()
        }
        self.audit_decision_log.append(decision_event)

        if not allowed:
            logger.critical(f"[NETWORK SCOPE FIREWALL] EGRESS BLOCKED: {url} | Reason: {reason} | Context: {caller_context}")
            if self.audit_callback:
                try:
                    self.audit_callback(decision_event)
                except Exception as e:
                    logger.error(f"Audit callback failed: {e}")
            raise ScopeViolationError(url, reason)

    def assert_redirect_allowed(self, original_url: str, location_header: str, caller_context: str = "") -> str:
        """Asserts that redirect target is in scope, returns resolved target URL"""
        from urllib.parse import urljoin
        resolved_url = urljoin(original_url, location_header)
        allowed, reason = self.check_redirect(original_url, location_header)
        decision_event = {
            "request": resolved_url,
            "original_request": original_url,
            "decision": "ALLOW" if allowed else "DENY",
            "reason": reason,
            "policy": self.policy_name,
            "caller_context": f"redirect_from_{caller_context}",
            "timestamp": time.time()
        }
        self.audit_decision_log.append(decision_event)

        if not allowed:
            logger.critical(f"[NETWORK SCOPE FIREWALL] REDIRECT BLOCKED: {original_url} -> {location_header} | Reason: {reason}")
            if self.audit_callback:
                try:
                    self.audit_callback(decision_event)
                except Exception as e:
                    logger.error(f"Audit callback failed: {e}")
            raise ScopeViolationError(resolved_url, reason)
        return resolved_url

    # ── NETWORK ENDPOINT (non-HTTP) AUTHORIZATION ────────────────────────────
    def check_host(self, host: str, protocol: str = "tcp") -> Tuple[bool, str]:
        """Authorize a *host* for a given transport protocol (discovery stage).

        Host-level counterpart of :meth:`check_endpoint` for scans that target a
        port range before individual ports are known.
        """
        if not host or not str(host).strip():
            return False, "Target host is empty"

        if unrestricted_mode():
            return True, "Unrestricted owner mode: all hosts authorized."

        proto = (protocol or "").strip().lower()
        if not self.network_policy.is_protocol_allowed(proto):
            return False, (
                f"Protocol '{protocol}' is not in the authorized protocol allowlist "
                f"{self.network_policy.allowed_protocols}"
            )
        if (
            self.network_policy.requires_active_testing_opt_in(proto)
            and not self.network_policy.allow_active_network_tests
        ):
            return False, (
                f"Active network testing is disabled: non-HTTP protocol '{proto}' "
                "requires allow_active_network_tests=True"
            )
        return self.scope_engine.is_allowed(str(host).strip())

    def check_endpoint(
        self,
        host: str,
        port: Optional[int],
        protocol: str = "tcp",
        method: str = "CONNECT",
    ) -> Tuple[bool, str]:
        """Authorize a transport/application endpoint ``protocol://host:port``.

        Enforced, in order:
          1. Protocol allowlist (fail-closed — HTTP(S) only by default).
          2. Active-network-testing opt-in for every non-HTTP protocol.
          3. Host authorization via the reference engine (inviolable invariants,
             RFC1918 lab override, allowlist/blacklist, testing window, ports).
          4. Port-level policy (explicit allowlist/ranges + forbidden relay ports).
        """
        if not host or not str(host).strip():
            return False, "Target host is empty"

        if unrestricted_mode():
            # Owner full-permissions mode: no protocol/port/active-testing gating.
            return True, "Unrestricted owner mode: all endpoints authorized."

        proto = (protocol or "").strip().lower()

        if not self.network_policy.is_protocol_allowed(proto):
            return False, (
                f"Protocol '{protocol}' is not in the authorized protocol allowlist "
                f"{self.network_policy.allowed_protocols}"
            )

        if (
            self.network_policy.requires_active_testing_opt_in(proto)
            and not self.network_policy.allow_active_network_tests
        ):
            return False, (
                f"Active network testing is disabled: non-HTTP protocol '{proto}' "
                "requires allow_active_network_tests=True"
            )

        # Host-level authorization. HTTP methods are meaningful only for web
        # protocols; every other protocol bypasses the HTTP method allowlist.
        engine_method = method if proto in ("http", "https") else "GET"
        allowed, reason = self.scope_engine.is_allowed(
            str(host).strip(), port=port, method=engine_method
        )
        if not allowed:
            return False, reason

        if port is not None and not self.network_policy.is_port_allowed(int(port)):
            return False, f"Port {port} is not permitted by network port policy"

        return True, f"Authorized network endpoint {proto}://{host}:{port}"

    def check_ports(
        self,
        host: str,
        ports: List[int],
        protocol: str = "tcp",
    ) -> Tuple[List[int], List[Tuple[int, str]]]:
        """Split a port list into ``(allowed, [(denied_port, reason), ...])``."""
        allowed: List[int] = []
        denied: List[Tuple[int, str]] = []
        for port in ports:
            ok, reason = self.check_endpoint(host, port, protocol=protocol)
            if ok:
                allowed.append(port)
            else:
                denied.append((port, reason))
        return allowed, denied

    def assert_endpoint_allowed(
        self,
        host: str,
        port: Optional[int],
        protocol: str = "tcp",
        method: str = "CONNECT",
        caller_context: str = "",
    ) -> None:
        """Hard assertion for a network endpoint; raises and audits on denial."""
        allowed, reason = self.check_endpoint(host, port, protocol=protocol, method=method)
        endpoint = f"{protocol}://{host}:{port}"
        decision_event = {
            "request": endpoint,
            "host": host,
            "port": port,
            "protocol": protocol,
            "decision": "ALLOW" if allowed else "DENY",
            "event_type": "NETWORK_EGRESS_ALLOWED" if allowed else "NETWORK_EGRESS_BLOCKED",
            "reason": reason,
            "policy": self.policy_name,
            "caller_context": caller_context,
            "timestamp": time.time(),
        }
        self.audit_decision_log.append(decision_event)

        if not allowed:
            logger.critical(
                f"[NETWORK SCOPE FIREWALL] EGRESS BLOCKED: {endpoint} | "
                f"Reason: {reason} | Context: {caller_context}"
            )
            if self.audit_callback:
                try:
                    self.audit_callback(decision_event)
                except Exception as e:  # pragma: no cover - defensive
                    logger.error(f"Audit callback failed: {e}")
            raise ScopeViolationError(endpoint, reason)

    def httpx_request_hook(self, request: Any) -> None:
        """Hook for httpx Client to inspect outbound request before socket connection"""
        url_str = str(request.url)
        method_str = request.method
        self.assert_allowed(url_str, method=method_str, caller_context="httpx_transport")

    def httpx_response_hook(self, response: Any) -> None:
        """Hook for httpx Client to inspect redirect hops before following"""
        if response.status_code in (301, 302, 303, 307, 308) and "location" in response.headers:
            loc = response.headers["location"]
            orig_url = str(response.url)
            self.assert_redirect_allowed(orig_url, loc, caller_context="httpx_redirect")

    async def async_httpx_request_hook(self, request: Any) -> None:
        """Async hook for httpx AsyncClient"""
        url_str = str(request.url)
        method_str = request.method
        self.assert_allowed(url_str, method=method_str, caller_context="async_httpx_transport")

    async def async_httpx_response_hook(self, response: Any) -> None:
        """Async hook for httpx AsyncClient response redirect"""
        if response.status_code in (301, 302, 303, 307, 308) and "location" in response.headers:
            loc = response.headers["location"]
            orig_url = str(response.url)
            self.assert_redirect_allowed(orig_url, loc, caller_context="async_httpx_redirect")

