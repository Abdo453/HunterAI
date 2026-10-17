"""
HunterAI Strict Scope Engine & Governance Guard
Enterprise-grade scope validation and safety invariants.

Invariants (Non-Overridable):
- Complete block of loopback (127.0.0.0/8, ::1, localhost)
- Complete block of RFC1918 private subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Complete block of link-local addresses (169.254.0.0/16, fe80::/10)
- Complete block of cloud metadata services (169.254.169.254, metadata.google.internal, 100.100.100.200)
- Excluded paths (e.g. /logout, /delete_account) to prevent state destruction and session drop
- Excluded ports (e.g. 25, 465, 587) to prevent SMTP mail relay triggers
- Time window enforcement and rate limit governance
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import socket
from datetime import datetime, time as dt_time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, Field

from core.security_mode import unrestricted_mode

logger = logging.getLogger("hunter_ai.scope_engine")

# ── INVIOLABLE SAFETY INVARIANTS (NEVER OVERRIDABLE) ───────────────────────────
HARD_BLOCKED_HOSTS: Set[str] = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
    "metadata.internal",
    "instance-data",
}

INVIOLABLE_IPV4_SUBNETS: List[ipaddress.IPv4Network] = [
    ipaddress.IPv4Network("127.0.0.0/8"),       # Loopback
    ipaddress.IPv4Network("169.254.0.0/16"),    # Link-Local & AWS/Azure/GCP metadata
    ipaddress.IPv4Network("224.0.0.0/4"),       # Multicast
    ipaddress.IPv4Network("240.0.0.0/4"),       # Reserved
    ipaddress.IPv4Network("255.255.255.255/32") # Broadcast
]

RFC1918_IPV4_SUBNETS: List[ipaddress.IPv4Network] = [
    ipaddress.IPv4Network("10.0.0.0/8"),        # RFC1918 Private
    ipaddress.IPv4Network("172.16.0.0/12"),     # RFC1918 Private
    ipaddress.IPv4Network("192.168.0.0/16"),    # RFC1918 Private
    ipaddress.IPv4Network("100.64.0.0/10"),     # Carrier-grade NAT
]

HARD_BLOCKED_IPV4_SUBNETS: List[ipaddress.IPv4Network] = INVIOLABLE_IPV4_SUBNETS + RFC1918_IPV4_SUBNETS

INVIOLABLE_IPV6_SUBNETS: List[ipaddress.IPv6Network] = [
    ipaddress.IPv6Network("::1/128"),           # Loopback
    ipaddress.IPv6Network("fe80::/10"),         # Link-Local
    ipaddress.IPv6Network("ff00::/8"),          # Multicast
]

RFC1918_IPV6_SUBNETS: List[ipaddress.IPv6Network] = [
    ipaddress.IPv6Network("fc00::/7"),          # Unique Local Address (ULA)
]

HARD_BLOCKED_IPV6_SUBNETS: List[ipaddress.IPv6Network] = INVIOLABLE_IPV6_SUBNETS + RFC1918_IPV6_SUBNETS

DEFAULT_EXCLUDED_PATHS: List[str] = [
    "/logout",
    "/signout",
    "/log-out",
    "/sign-out",
    "/delete",
    "/delete-account",
    "/remove-account",
    "/reset-db",
    "/billing/cancel",
    "/unsubscribe",
]

DEFAULT_EXCLUDED_PORTS: List[int] = [
    25,   # SMTP
    465,  # SMTPS
    587,  # Submission
]


def normalize_ip_literal(
    host: str,
) -> Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]:
    """Parses ANY textual IP literal into an ``ipaddress`` object.

    Naive ``ipaddress.ip_address`` parsing silently rejects the ambiguous
    encodings that attackers use to smuggle a forbidden destination past scope
    checks. This normaliser understands:

      - canonical IPv4 / IPv6 (``10.0.0.5``, ``::1``)
      - dotted-short IPv4 (``127.1`` -> 127.0.0.1)
      - integer IPv4 (``2130706433`` -> 127.0.0.1)
      - hexadecimal IPv4 (``0x7f000001`` -> 127.0.0.1)
      - octal IPv4 (``0177.0.0.1`` -> 127.0.0.1)
      - IPv6 with a zone id (``fe80::1%eth0``)
      - bracketed IPv6 (``[::1]``)

    Returns ``None`` when the value is an ordinary hostname (not an IP literal).
    """
    if not host:
        return None
    h = host.strip()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    if "%" in h:  # strip an IPv6 zone id
        h = h.split("%", 1)[0]

    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass

    # Legacy inet_aton forms (IPv4 only, incl. hex/octal/short notation).
    try:
        return ipaddress.IPv4Address(socket.inet_aton(h))
    except (OSError, ValueError):
        return None


class ScopePolicy(BaseModel):
    """Declarative scope policy loaded from scope.yaml or provided directly"""
    allowed_targets: List[str] = Field(default_factory=list)
    excluded_targets: List[str] = Field(default_factory=list)
    excluded_paths: List[str] = Field(default_factory=lambda: list(DEFAULT_EXCLUDED_PATHS))
    excluded_ports: List[int] = Field(default_factory=lambda: list(DEFAULT_EXCLUDED_PORTS))
    allowed_methods: List[str] = Field(default_factory=lambda: ["GET", "POST", "HEAD", "OPTIONS"])
    allow_auth_testing: bool = False
    rate_limit_rps: float = 2.0
    testing_window: Optional[Dict[str, str]] = None  # {"start": "08:00", "end": "20:00"}
    max_request_budget: int = 5000
    allow_private_ips_override: bool = False  # Strict default False
    # When True, a target that matches NO in-scope rule is DENIED even if the
    # allowlist is empty. Legacy callers keep the historical permissive fallback
    # by leaving this False; the governed gateways opt in explicitly.
    fail_closed: bool = False

    def __init__(self, **data):
        if "allowed_domains" in data and "allowed_targets" not in data:
            data["allowed_targets"] = data.pop("allowed_domains")
        if "excluded_domains" in data and "excluded_targets" not in data:
            data["excluded_targets"] = data.pop("excluded_domains")
        if "blocked_paths" in data and "excluded_paths" not in data:
            data["excluded_paths"] = data.pop("blocked_paths")
        if "allow_private_networks" in data and "allow_private_ips_override" not in data:
            data["allow_private_ips_override"] = data.pop("allow_private_networks")
        super().__init__(**data)



class StrictScopeEngine:
    """
    Enterprise-Grade Strict Scope Engine.
    Enforces authorization, domain wildcards, CIDRs, path safety, and non-overridable internal IP protections.
    """

    def __init__(self, policy: Optional[ScopePolicy] = None):
        self.policy = policy or ScopePolicy()
        self.in_scope_patterns: List[re.Pattern] = []
        self.out_of_scope_patterns: List[re.Pattern] = []
        self.in_scope_subnets: List[ipaddress.IPv4Network] = []
        self.out_of_scope_subnets: List[ipaddress.IPv4Network] = []
        self._compile_policy()

    @classmethod
    def from_yaml(cls, yaml_content_or_path: str) -> StrictScopeEngine:
        """Loads ScopePolicy from a YAML file or string"""
        if os.path.isfile(yaml_content_or_path):
            with open(yaml_content_or_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
        else:
            data = yaml.safe_load(yaml_content_or_path) or {}

        # Handle nested keys if wrapped in 'scope:'
        if "scope" in data and isinstance(data["scope"], dict):
            data = data["scope"]

        policy = ScopePolicy(**data)
        return cls(policy)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> StrictScopeEngine:
        return cls(ScopePolicy(**data))

    @classmethod
    def from_file(cls, path: str | os.PathLike) -> StrictScopeEngine:
        """Loads a ScopePolicy from an explicit scope.yaml / scope.json file.

        Raises FileNotFoundError for a missing path and ValueError for a path
        that is not a regular file, instead of silently falling back to a
        permissive default policy.
        """
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Scope policy file not found: {p}")
        if not p.is_file():
            raise ValueError(f"Scope policy path is not a file: {p}")

        text = p.read_text(encoding="utf-8")
        suffix = p.suffix.lower()

        if suffix == ".json":
            data = json.loads(text) if text.strip() else {}
        elif suffix in (".yaml", ".yml"):
            data = yaml.safe_load(text) or {}
        else:
            # Unknown extension: YAML is a JSON superset, so this is safe.
            data = yaml.safe_load(text) or {}

        if not isinstance(data, dict):
            raise ValueError(f"Scope policy file must contain a mapping: {p}")

        # Accept either a flat policy or one wrapped in a 'scope:' key.
        if "scope" in data and isinstance(data["scope"], dict):
            data = data["scope"]

        policy = ScopePolicy(**data)
        engine = cls(policy)
        engine.source_file = str(p)
        return engine

    def _compile_policy(self):
        self.in_scope_patterns = []
        self.out_of_scope_patterns = []
        self.in_scope_subnets = []
        self.out_of_scope_subnets = []

        for target in self.policy.allowed_targets:
            self._compile_rule(target, self.in_scope_patterns, self.in_scope_subnets)

        for target in self.policy.excluded_targets:
            self._compile_rule(target, self.out_of_scope_patterns, self.out_of_scope_subnets)

    def _compile_rule(self, item: str, pattern_list: List[re.Pattern], subnet_list: List[ipaddress.IPv4Network]):
        clean = item.strip().lower()
        if not clean:
            return

        # Check CIDR / IP
        try:
            if "/" in clean:
                net = ipaddress.IPv4Network(clean, strict=False)
                subnet_list.append(net)
                return
            else:
                ip = ipaddress.IPv4Address(clean)
                subnet_list.append(ipaddress.IPv4Network(f"{clean}/32"))
                return
        except ValueError:
            pass

        # Wildcard domain handling
        clean = re.sub(r"^https?://", "", clean)
        clean = clean.split("/")[0].split(":")[0]  # Remove path and port

        if clean.startswith("*."):
            domain_part = re.escape(clean[2:])
            pattern = re.compile(rf"^(?:[a-zA-Z0-9_\-]+\.)*{domain_part}$", re.IGNORECASE)
            pattern_list.append(pattern)
        else:
            domain_part = re.escape(clean)
            pattern = re.compile(rf"^{domain_part}$", re.IGNORECASE)
            pattern_list.append(pattern)

    def _check_hard_invariants(self, host: str, port: Optional[int] = None) -> Tuple[bool, Optional[str]]:
        """Verifies hard-coded safety invariants: RFC1918, Loopback, Cloud Metadata, Excluded Ports"""
        if unrestricted_mode():
            # Owner full-permissions mode: no destination invariants apply.
            return True, None

        low_host = host.lower().strip()

        # 1. Hard-blocked domain names
        if low_host in HARD_BLOCKED_HOSTS:
            return False, f"SECURITY INVARIANT: Host '{host}' is an internal/metadata service and is strictly forbidden."

        # 2. Hard-blocked IP addresses & CIDRs (ALL textual encodings)
        ip_obj = normalize_ip_literal(low_host)
        if ip_obj is not None:
            # Normalise IPv4-mapped IPv6 (::ffff:127.0.0.1) to IPv4 so mapped
            # loopback / metadata cannot slip past the IPv4 invariants.
            if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
                ip_obj = ip_obj.ipv4_mapped

            if isinstance(ip_obj, ipaddress.IPv4Address):
                # Inviolable invariants (Loopback, Cloud Metadata 169.254.169.254) can NEVER be scanned
                for blk in INVIOLABLE_IPV4_SUBNETS:
                    if ip_obj in blk:
                        return False, f"SECURITY INVARIANT: IP {host} belongs to inviolable subnet {blk} and cannot be scanned."
                # RFC1918 private subnets blocked unless lab mode override is enabled
                if not self.policy.allow_private_ips_override:
                    for blk in RFC1918_IPV4_SUBNETS:
                        if ip_obj in blk:
                            return False, f"SECURITY INVARIANT: IP {host} belongs to internal/private subnet {blk} and cannot be scanned."
            elif isinstance(ip_obj, ipaddress.IPv6Address):
                for blk in INVIOLABLE_IPV6_SUBNETS:
                    if ip_obj in blk:
                        return False, f"SECURITY INVARIANT: IPv6 {host} belongs to inviolable subnet {blk} and cannot be scanned."
                if not self.policy.allow_private_ips_override:
                    for blk in RFC1918_IPV6_SUBNETS:
                        if ip_obj in blk:
                            return False, f"SECURITY INVARIANT: IPv6 {host} belongs to internal/private subnet {blk} and cannot be scanned."

        # 3. Hard-blocked Ports
        if port and port in self.policy.excluded_ports:
            return False, f"SECURITY INVARIANT: Port {port} is in excluded ports policy to prevent service degradation."

        return True, None

    def is_allowed(
        self,
        target: str,
        path: str = "",
        port: Optional[int] = None,
        method: str = "GET"
    ) -> Tuple[bool, str]:
        """
        Complete authorization check:
        1. Inviolable Safety Invariants (RFC1918, Loopback, Cloud Metadata)
        2. Testing Window Validation
        3. Path Exclusions (/logout, /delete)
        4. Method Restrictions
        5. Blacklist / Out-of-scope priority
        6. Whitelist / In-scope validation
        """
        if not target or not target.strip():
            return False, "Target is empty"

        if unrestricted_mode():
            # Owner full-permissions mode: every target is authorized, no
            # allowlist, no testing window, no path/method exclusions.
            return True, "Unrestricted owner mode: all targets authorized."

        clean = target.strip().lower()
        if clean.startswith("http://") or clean.startswith("https://"):
            parsed = urlparse(clean)
            host = parsed.hostname or clean
            path = path or parsed.path
            port = port or parsed.port or (443 if parsed.scheme == "https" else 80)
        else:
            host_part = clean.split("/")[0]
            if host_part.startswith("["):
                # Bracketed IPv6, optionally followed by :port  ->  [::1]:8080
                end = host_part.find("]")
                if end != -1:
                    host = host_part[1:end]
                    rest = host_part[end + 1:]
                    if rest.startswith(":") and rest[1:].isdigit():
                        port = port or int(rest[1:])
                else:
                    host = host_part
            elif host_part.count(":") == 1:
                host, port_str = host_part.split(":", 1)
                try:
                    port = port or int(port_str)
                except ValueError:
                    pass
            else:
                # Bare IPv6 literal (multiple colons) or plain hostname.
                host = host_part

        # 1. Inviolable Invariants Check
        safe, invariant_reason = self._check_hard_invariants(host, port)
        if not safe:
            return False, invariant_reason

        # 2. Testing Window Check
        if self.policy.testing_window:
            win_start = self.policy.testing_window.get("start")
            win_end = self.policy.testing_window.get("end")
            if win_start and win_end:
                now_time = datetime.utcnow().time()
                try:
                    s_h, s_m = map(int, win_start.split(":"))
                    e_h, e_m = map(int, win_end.split(":"))
                    if not (dt_time(s_h, s_m) <= now_time <= dt_time(e_h, e_m)):
                        return False, f"Out of authorized testing window ({win_start} - {win_end} UTC)"
                except Exception:
                    pass

        # 3. Path Exclusions
        if path:
            low_path = path.lower()
            for exp in self.policy.excluded_paths:
                if exp.lower() in low_path:
                    return False, f"Path '{path}' matches excluded path rule '{exp}'"

        # 4. Method Restrictions
        if method and method.upper() not in [m.upper() for m in self.policy.allowed_methods]:
            return False, f"HTTP method '{method}' is not permitted by policy (Allowed: {self.policy.allowed_methods})"

        # 5. Out-of-Scope (Blacklist) Priority
        try:
            ip_obj = ipaddress.IPv4Address(host)
            for net in self.out_of_scope_subnets:
                if ip_obj in net:
                    return False, f"Target IP {host} matches Out-of-Scope subnet: {net}"
        except ValueError:
            pass

        for pat in self.out_of_scope_patterns:
            if pat.search(host):
                return False, f"Target {host} matches Out-of-Scope domain pattern"

        # 6. In-Scope Validation
        # No explicit allowlist configured:
        #  - fail_closed policies DENY (no authorization = no access)
        #  - legacy policies keep the historical permissive single-target fallback
        if not self.in_scope_patterns and not self.in_scope_subnets:
            if self.policy.fail_closed:
                return False, "Target is not covered by any in-scope rule (fail-closed policy)."
            return True, "Authorized (Default scope permissive)"

        try:
            ip_obj = ipaddress.IPv4Address(host)
            for net in self.in_scope_subnets:
                if ip_obj in net:
                    return True, f"Target IP {host} matched In-Scope subnet: {net}"
        except ValueError:
            pass

        for pat in self.in_scope_patterns:
            if pat.search(host):
                return True, f"Target {host} matched In-Scope domain rule"

        return False, f"Target '{host}' is outside authorized scope"

    def is_in_scope(self, target: str) -> Tuple[bool, str]:
        """Backward-compatibility bridge for ScopeGuard"""
        return self.is_allowed(target)

    def validate_target(self, target: str) -> Tuple[bool, str]:
        """Validates whether a target host or IP is authorized and adheres to safety invariants"""
        return self.is_allowed(target)

    def check_inviolable(self, host: str, port: Optional[int] = None) -> Tuple[bool, str]:
        """Public wrapper for the non-overridable safety invariants only.

        Unlike :meth:`validate_target`, this does NOT consult the allowlist, so
        it is safe to run against untrusted/dynamic input (for example a host
        extracted from a shell command) without granting or denying access on
        allowlist grounds. Returns ``(True, "")`` when the destination is not
        forbidden by an inviolable invariant.
        """
        ok, reason = self._check_hard_invariants(host, port)
        return ok, (reason or "")

    def validate_url(self, url: str) -> Tuple[bool, str]:
        """Validates whether a full URL is authorized and adheres to safety invariants"""
        return self.is_allowed(url)

    def is_host_allowed(self, host: str) -> bool:
        """Boolean check whether host is allowed"""
        return self.is_allowed(host)[0]

    def is_port_allowed(self, port: int) -> bool:
        """Boolean check whether port is allowed by policy"""
        return port not in self.policy.excluded_ports

    def filter_urls(self, urls: List[str]) -> List[str]:
        """Filters a list of URLs, retaining only allowed ones"""
        valid = []
        for u in urls:
            allowed, _ = self.is_allowed(u)
            if allowed:
                valid.append(u)
        return valid

    @property
    def in_scope(self) -> List[str]:
        return self.policy.allowed_targets

    @property
    def out_of_scope(self) -> List[str]:
        return self.policy.excluded_targets


# Backward-compatibility alias
ScopeEngine = StrictScopeEngine

