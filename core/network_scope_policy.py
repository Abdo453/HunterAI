"""Network-Level Scope Policy — authorized IP/CIDR/Protocol/Port boundaries.

This module is the *network* counterpart of :class:`core.scope_engine.ScopePolicy`.
Where the URL scope policy authorizes ``http(s)`` destinations by host/path/method,
network penetration testing needs to authorize a *transport endpoint*
(``protocol://host:port``) before any socket is opened — SMB, LDAP, Kerberos,
RDP, SSH, raw TCP/UDP, ...

Design invariants (matching the rest of the platform):
  * **Fail-closed by default** — no allowlist means nothing is authorized.
  * **Explicit opt-in for active network testing** — a non-HTTP protocol is
    always denied unless ``allow_active_network_tests`` is set *and* the
    protocol is present in ``allowed_protocols``.
  * **Inviolable safety invariants are NOT re-implemented here** — loopback,
    link-local, cloud metadata and RFC1918 are enforced by the single reference
    engine (:class:`core.scope_engine.StrictScopeEngine`) that this policy feeds.

The policy deliberately stays a pure data object; all decision logic lives in
:class:`core.network_scope_guard.NetworkScopeGuard`.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

# Protocols authorized out of the box: nothing beyond ordinary web traffic.
DEFAULT_NETWORK_PROTOCOLS: List[str] = ["http", "https"]

# Ports blocked regardless of protocol: SMTP relay triggers.
DEFAULT_NETWORK_EXCLUDED_PORTS: List[int] = [25, 465, 587]

# Protocols treated as ordinary web traffic (never require the active-testing switch).
WEB_PROTOCOLS = {"http", "https"}


def _parse_port_range(spec: str) -> Optional[tuple]:
    """Parse ``"1-1024"`` (or a single ``"443"``) into an inclusive (lo, hi)."""
    if not spec:
        return None
    text = str(spec).strip()
    try:
        if "-" in text:
            lo_s, hi_s = text.split("-", 1)
            lo, hi = int(lo_s), int(hi_s)
            if lo > hi:
                lo, hi = hi, lo
            return lo, hi
        single = int(text)
        return single, single
    except (ValueError, TypeError):
        return None


class NetworkScopePolicy(BaseModel):
    """Declarative network scope policy (IP/CIDR/Protocol/Port)."""

    # ── Authorized destinations (same syntax the URL engine understands) ──────
    allowed_targets: List[str] = Field(default_factory=list)
    excluded_targets: List[str] = Field(default_factory=list)

    # ── Protocol authorization ───────────────────────────────────────────────
    allowed_protocols: List[str] = Field(
        default_factory=lambda: list(DEFAULT_NETWORK_PROTOCOLS)
    )
    # Second, independent gate: even an allowlisted non-HTTP protocol is denied
    # until the operator explicitly acknowledges active network testing.
    allow_active_network_tests: bool = False

    # ── Port authorization ───────────────────────────────────────────────────
    allowed_ports: List[int] = Field(default_factory=list)          # empty => any
    allowed_port_ranges: List[str] = Field(default_factory=list)    # e.g. ["1-1024"]
    excluded_ports: List[int] = Field(
        default_factory=lambda: list(DEFAULT_NETWORK_EXCLUDED_PORTS)
    )

    # ── Governance carried over from ScopePolicy ─────────────────────────────
    allowed_methods: List[str] = Field(
        default_factory=lambda: ["GET", "POST", "HEAD", "OPTIONS"]
    )
    allow_private_ips_override: bool = False  # Lab mode for RFC1918
    fail_closed: bool = True
    rate_limit_rps: float = 2.0
    max_concurrent_scans: int = 4
    testing_window: Optional[Dict[str, str]] = None  # {"start": "08:00", "end": "20:00"}

    model_config = {"extra": "ignore"}

    # Alias support mirroring ScopePolicy's back-compat constructor.
    def __init__(self, **data: Any):
        if "allowed_domains" in data and "allowed_targets" not in data:
            data["allowed_targets"] = data.pop("allowed_domains")
        if "excluded_domains" in data and "excluded_targets" not in data:
            data["excluded_targets"] = data.pop("excluded_domains")
        if "allow_private_networks" in data and "allow_private_ips_override" not in data:
            data["allow_private_ips_override"] = data.pop("allow_private_networks")
        super().__init__(**data)

    # ── Protocol / port decision helpers ─────────────────────────────────────
    def is_protocol_allowed(self, protocol: Optional[str]) -> bool:
        proto = (protocol or "").strip().lower()
        if not proto:
            return False
        return proto in {p.strip().lower() for p in self.allowed_protocols if p}

    def requires_active_testing_opt_in(self, protocol: Optional[str]) -> bool:
        proto = (protocol or "").strip().lower()
        return proto not in WEB_PROTOCOLS

    def is_port_allowed(self, port: Optional[int]) -> bool:
        if port is None:
            return True
        try:
            p = int(port)
        except (TypeError, ValueError):
            return False
        if p in set(self.excluded_ports):
            return False
        has_explicit_allowlist = bool(self.allowed_ports or self.allowed_port_ranges)
        if not has_explicit_allowlist:
            return True
        if p in set(self.allowed_ports):
            return True
        for spec in self.allowed_port_ranges:
            rng = _parse_port_range(spec)
            if rng and rng[0] <= p <= rng[1]:
                return True
        return False

    # ── Interop with the URL scope engine ────────────────────────────────────
    def to_scope_policy(self):
        """Project this policy onto the reference :class:`ScopePolicy`."""
        from core.scope_engine import ScopePolicy

        return ScopePolicy(
            allowed_targets=list(self.allowed_targets),
            excluded_targets=list(self.excluded_targets),
            excluded_ports=list(self.excluded_ports),
            allowed_methods=list(self.allowed_methods),
            allow_private_ips_override=self.allow_private_ips_override,
            rate_limit_rps=self.rate_limit_rps,
            testing_window=self.testing_window,
            fail_closed=self.fail_closed,
        )

    @classmethod
    def from_scope_policy(cls, policy: Any) -> "NetworkScopePolicy":
        """Derive a network policy from an existing URL :class:`ScopePolicy`.

        The resulting policy keeps the URL authorization surface intact but adds
        the network-specific defaults: HTTP-only protocols and no active testing.
        """
        if policy is None:
            return cls()
        if isinstance(policy, cls):
            return policy
        return cls(
            allowed_targets=list(getattr(policy, "allowed_targets", []) or []),
            excluded_targets=list(getattr(policy, "excluded_targets", []) or []),
            excluded_ports=list(
                getattr(policy, "excluded_ports", DEFAULT_NETWORK_EXCLUDED_PORTS)
                or DEFAULT_NETWORK_EXCLUDED_PORTS
            ),
            allowed_methods=list(
                getattr(policy, "allowed_methods", ["GET", "POST", "HEAD", "OPTIONS"])
            ),
            allow_private_ips_override=bool(
                getattr(policy, "allow_private_ips_override", False)
            ),
            fail_closed=bool(getattr(policy, "fail_closed", False)),
            rate_limit_rps=float(getattr(policy, "rate_limit_rps", 2.0) or 2.0),
            testing_window=getattr(policy, "testing_window", None),
        )

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()
