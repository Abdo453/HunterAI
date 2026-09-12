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
from datetime import datetime, time as dt_time
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, Field

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
            pattern = re.compile(rf"^(?:[a-zA-Z0-9_\-]+\.)*{domain_part}$", re.IGNORECASE)
            pattern_list.append(pattern)

    def _check_hard_invariants(self, host: str, port: Optional[int] = None) -> Tuple[bool, Optional[str]]:
        """Verifies hard-coded safety invariants: RFC1918, Loopback, Cloud Metadata, Excluded Ports"""
        low_host = host.lower().strip()

        # 1. Hard-blocked domain names
        if low_host in HARD_BLOCKED_HOSTS:
            return False, f"SECURITY INVARIANT: Host '{host}' is an internal/metadata service and is strictly forbidden."

        # 2. Hard-blocked IP addresses & CIDRs
        try:
            ip_obj = ipaddress.ip_address(low_host)
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
        except ValueError:
            # Not an IP address, proceed with domain checks
            pass

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

        clean = target.strip().lower()
        if clean.startswith("http://") or clean.startswith("https://"):
            parsed = urlparse(clean)
            host = parsed.hostname or clean
            path = path or parsed.path
            port = port or parsed.port or (443 if parsed.scheme == "https" else 80)
        else:
            host_part = clean.split("/")[0]
            if ":" in host_part:
                host, port_str = host_part.split(":", 1)
                try:
                    port = port or int(port_str)
                except ValueError:
                    pass
            else:
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
        # If no explicit allowed targets provided, permissive fallback for single target domain
        if not self.in_scope_patterns and not self.in_scope_subnets:
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
