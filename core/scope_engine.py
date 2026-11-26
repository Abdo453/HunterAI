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
import posixpath
import re
import socket
from datetime import datetime, time as dt_time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import unquote, urlparse

try:
    import yaml
except ImportError:
    from ruamel.yaml import YAML
    class _YamlShim:
        @staticmethod
        def safe_load(stream):
            return YAML(typ="safe").load(stream)
    yaml = _YamlShim()
from pydantic import BaseModel, Field

from core.security_mode import unrestricted_mode

logger = logging.getLogger("hunter_ai.scope_engine")

# ── INVIOLABLE SAFETY INVARIANTS (NEVER OVERRIDABLE) ───────────────────────────
HARD_BLOCKED_HOSTS: Set[str] = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
    "metadata.internal",
    "metadata.azure.com",
    "metadata.tencentyun.com",
    "metadata.aliyun.com",
    "local-metadata",
    "instance-data",
}

INVIOLABLE_IPV4_SUBNETS: List[ipaddress.IPv4Network] = [
    ipaddress.IPv4Network("0.0.0.0/8"),         # Unspecified / current network
    ipaddress.IPv4Network("127.0.0.0/8"),       # Loopback
    ipaddress.IPv4Network("169.254.0.0/16"),    # Link-Local & AWS/Azure/GCP metadata
    ipaddress.IPv4Network("100.100.100.200/32"),# Alibaba Cloud metadata
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

_IPV4_MAPPED_IPV6 = ipaddress.IPv6Network("::ffff:0:0/96")
_NAT64_WELL_KNOWN_IPV6 = ipaddress.IPv6Network("64:ff9b::/96")
_NAT64_LOCAL_IPV6 = ipaddress.IPv6Network("64:ff9b:1::/48")
_AWS_IMDS_IPV6 = ipaddress.IPv6Network("fd00:ec2::254/128")

INVIOLABLE_IPV6_SUBNETS: List[ipaddress.IPv6Network] = [
    ipaddress.IPv6Network("::/128"),            # Unspecified
    ipaddress.IPv6Network("::1/128"),           # Loopback
    _IPV4_MAPPED_IPV6,                          # IPv4-mapped IPv6
    _NAT64_WELL_KNOWN_IPV6,                     # NAT64 well-known prefix
    _NAT64_LOCAL_IPV6,                          # NAT64 local-use prefix
    _AWS_IMDS_IPV6,                             # AWS IPv6 IMDS
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

_METADATA_HOST_IPS: Set[str] = {
    "100.100.100.200",
    "fd00:ec2::254",
}

_DISALLOWED_URL_SCHEME_PREFIX_RE = re.compile(
    r"^[a-zA-Z][a-zA-Z0-9+.-]*:(?!\d+(?:[/?#]|$))"
)


def _normalize_url_path(raw_path: str) -> str:
    """Decode percent-encoded segments and normalize dot-segments safely."""
    if not raw_path:
        return "/"
    cur = raw_path
    for _ in range(2):
        dec = unquote(cur)
        if dec == cur:
            break
        cur = dec
    cur = cur.replace("\\", "/")
    while cur.startswith("//"):
        cur = cur[1:]
    norm = posixpath.normpath(cur)
    if not norm.startswith("/"):
        norm = "/" + norm
    return norm


def _parse_legacy_ipv4_part(part: str) -> Optional[int]:
    """Parse one IPv4 component in decimal, octal (0...), or hex (0x...) form."""
    if not part:
        return None
    low = part.lower()
    try:
        if low.startswith("0x"):
            if len(low) <= 2:
                return None
            return int(low, 16)
        if len(low) > 1 and low.startswith("0"):
            if not all(ch in "01234567" for ch in low):
                return None
            return int(low, 8)
        if not low.isdigit():
            return None
        return int(low, 10)
    except ValueError:
        return None


def _parse_legacy_ipv4(host: str) -> Optional[ipaddress.IPv4Address]:
    """Portable parser for non-canonical IPv4 literals (integer/octal/hex/short)."""
    parts = host.split(".")
    if not (1 <= len(parts) <= 4):
        return None
    nums: List[int] = []
    for p in parts:
        val = _parse_legacy_ipv4_part(p)
        if val is None or val < 0:
            return None
        nums.append(val)

    if len(nums) == 1:
        if nums[0] > 0xFFFFFFFF:
            return None
        addr_int = nums[0]
    elif len(nums) == 2:
        if nums[0] > 0xFF or nums[1] > 0xFFFFFF:
            return None
        addr_int = (nums[0] << 24) | nums[1]
    elif len(nums) == 3:
        if nums[0] > 0xFF or nums[1] > 0xFF or nums[2] > 0xFFFF:
            return None
        addr_int = (nums[0] << 24) | (nums[1] << 16) | nums[2]
    else:
        if any(n > 0xFF for n in nums):
            return None
        addr_int = (nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]
    return ipaddress.IPv4Address(addr_int)


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

    legacy = _parse_legacy_ipv4(h)
    if legacy is not None:
        return legacy

    # Fallback to platform inet_aton for any remaining legacy IPv4 forms.
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
            if str(ip_obj).lower() in _METADATA_HOST_IPS:
                return False, f"SECURITY INVARIANT: IP {host} is a cloud metadata address ({ip_obj}) and cannot be scanned."

            if isinstance(ip_obj, ipaddress.IPv6Address):
                # Block IPv4-mapped IPv6 (::ffff:0:0/96) and NAT64 (64:ff9b::/96) unconditionally
                if ip_obj in _IPV4_MAPPED_IPV6:
                    mapped = ip_obj.ipv4_mapped
                    return False, f"SECURITY INVARIANT: IPv6 {host} belongs to inviolable IPv4-mapped subnet ::ffff:0:0/96 (mapped IPv4: {mapped})."
                if ip_obj in _NAT64_WELL_KNOWN_IPV6 or ip_obj in _NAT64_LOCAL_IPV6:
                    return False, f"SECURITY INVARIANT: IPv6 {host} belongs to inviolable NAT64 subnet 64:ff9b::/96 and cannot be scanned."
                if ip_obj in _AWS_IMDS_IPV6:
                    return False, f"SECURITY INVARIANT: IPv6 {host} is AWS IMDS metadata address fd00:ec2::254 and cannot be scanned."
                for blk in INVIOLABLE_IPV6_SUBNETS:
                    if ip_obj in blk:
                        return False, f"SECURITY INVARIANT: IPv6 {host} belongs to inviolable subnet {blk} and cannot be scanned."
                if not self.policy.allow_private_ips_override:
                    for blk in RFC1918_IPV6_SUBNETS:
                        if ip_obj in blk:
                            return False, f"SECURITY INVARIANT: IPv6 {host} belongs to internal/private subnet {blk} and cannot be scanned."
            elif isinstance(ip_obj, ipaddress.IPv4Address):
                # Inviolable invariants (Loopback, Cloud Metadata 169.254.169.254 / 100.100.100.200) can NEVER be scanned
                for blk in INVIOLABLE_IPV4_SUBNETS:
                    if ip_obj in blk:
                        return False, f"SECURITY INVARIANT: IP {host} belongs to inviolable subnet {blk} and cannot be scanned."
                # RFC1918 private subnets blocked unless lab mode override is enabled
                if not self.policy.allow_private_ips_override:
                    for blk in RFC1918_IPV4_SUBNETS:
                        if ip_obj in blk:
                            return False, f"SECURITY INVARIANT: IP {host} belongs to internal/private subnet {blk} and cannot be scanned."

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
            if not path and "/" in clean:
                sub = "/" + clean.split("/", 1)[1]
                path = sub.split("?", 1)[0].split("#", 1)[0]

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

        # 3. Path Exclusions (normalized to defeat %encoding and dot-segment traversal)
        if path:
            low_raw = path.lower()
            norm_path = _normalize_url_path(path).lower()
            for exp in self.policy.excluded_paths:
                exp_low = exp.lower()
                exp_norm = _normalize_url_path(exp).lower()
                if exp_low in low_raw or exp_norm in norm_path:
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


_UNSPECIFIED_IPV4 = ipaddress.IPv4Network("0.0.0.0/8")
_LOOPBACK_IPV4 = ipaddress.IPv4Network("127.0.0.0/8")
_LINK_LOCAL_IPV4 = ipaddress.IPv4Network("169.254.0.0/16")
_UNSPECIFIED_IPV6 = ipaddress.IPv6Network("::/128")
_LOOPBACK_IPV6 = ipaddress.IPv6Network("::1/128")
_LINK_LOCAL_IPV6 = ipaddress.IPv6Network("fe80::/10")


def _extract_authority_host(authority: str) -> str:
    """Extract the bare hostname/IP literal from a netloc or host[:port] string."""
    clean = authority.strip().lower()
    if "@" in clean:
        clean = clean.rsplit("@", 1)[1]
    if clean.startswith("["):
        end = clean.find("]")
        if end != -1:
            return clean[1:end].rstrip(".")
        return clean.rstrip(".")
    if clean.count(":") == 1:
        host_part, port_part = clean.split(":", 1)
        if port_part.isdigit():
            return host_part.rstrip(".")
    return clean.rstrip(".")


def _compile_url_scope_rules(
    items: Optional[List[str]],
) -> Tuple[List[re.Pattern], List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]]:
    """Compile domain regexes and IPv4/IPv6 subnets from target rule strings."""
    patterns: List[re.Pattern] = []
    subnets: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
    if not items:
        return patterns, subnets

    for item in items:
        clean = (item or "").strip().lower()
        if not clean:
            continue
        clean = re.sub(r"^https?://", "", clean)
        clean = clean.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if "@" in clean:
            clean = clean.rsplit("@", 1)[1]

        # Accept explicit CIDR notation directly (IPv4 or IPv6) before port stripping.
        try:
            net = ipaddress.ip_network(clean.strip("[]"), strict=False)
            subnets.append(net)
            continue
        except ValueError:
            pass

        host_part = _extract_authority_host(clean)
        if not host_part:
            continue

        ip_obj = normalize_ip_literal(host_part)
        if ip_obj is not None:
            if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
                ip_obj = ip_obj.ipv4_mapped
            prefix = 32 if isinstance(ip_obj, ipaddress.IPv4Address) else 128
            subnets.append(ipaddress.ip_network(f"{ip_obj}/{prefix}", strict=False))
            continue

        if host_part.startswith("*."):
            domain_part = re.escape(host_part[2:])
            patterns.append(re.compile(rf"^(?:[a-zA-Z0-9_\-]+\.)*{domain_part}$", re.IGNORECASE))
        else:
            patterns.append(re.compile(rf"^{re.escape(host_part)}$", re.IGNORECASE))

    return patterns, subnets


def _host_matches_compiled_rules(
    host: str,
    ip_obj: Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]],
    patterns: List[re.Pattern],
    subnets: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]],
) -> bool:
    """Return True if *host* or its parsed IP matches any compiled rule."""
    if ip_obj is not None:
        norm_ip = ip_obj.ipv4_mapped if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None else ip_obj
        for net in subnets:
            if norm_ip.version == net.version and norm_ip in net:
                return True
    for pat in patterns:
        if pat.search(host):
            return True
    return False


def _is_loopback_ip(ip_obj: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> bool:
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
        ip_obj = ip_obj.ipv4_mapped
    return bool(ip_obj.is_loopback or (isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj in _LOOPBACK_IPV4))


def _check_resolved_ip_safety(
    ip_obj: Union[ipaddress.IPv4Address, ipaddress.IPv6Address],
    label: str,
    allow_loopback: bool,
    allow_private: bool = False,
) -> Tuple[bool, Optional[str]]:
    """Enforce SSRF & inviolable subnet checks on a literal or DNS-resolved IP."""
    if isinstance(ip_obj, ipaddress.IPv6Address):
        if ip_obj in _IPV4_MAPPED_IPV6:
            mapped = ip_obj.ipv4_mapped
            return (
                False,
                f"SECURITY INVARIANT: {label} belongs to blocked IPv4-mapped IPv6 subnet ::ffff:0:0/96 (mapped: {mapped})",
            )
        if ip_obj in _NAT64_WELL_KNOWN_IPV6 or ip_obj in _NAT64_LOCAL_IPV6:
            return (
                False,
                f"SECURITY INVARIANT: {label} belongs to blocked NAT64 IPv6 subnet 64:ff9b::/96",
            )
        if ip_obj in _AWS_IMDS_IPV6 or str(ip_obj).lower() in _METADATA_HOST_IPS:
            return False, f"SECURITY INVARIANT: {label} resolves to cloud metadata IP {ip_obj}"
        if ip_obj in _LINK_LOCAL_IPV6:
            return False, f"SECURITY INVARIANT: {label} belongs to non-overridable IPv6 link-local subnet {_LINK_LOCAL_IPV6}"
        if ip_obj in _UNSPECIFIED_IPV6:
            return False, f"SECURITY INVARIANT: {label} belongs to unspecified IPv6 address {_UNSPECIFIED_IPV6}"
        if ip_obj in _LOOPBACK_IPV6:
            if allow_loopback:
                return True, None
            return False, f"SECURITY INVARIANT: {label} belongs to IPv6 loopback subnet {_LOOPBACK_IPV6}"
        for blk in INVIOLABLE_IPV6_SUBNETS:
            if ip_obj in blk:
                return False, f"SECURITY INVARIANT: {label} belongs to inviolable IPv6 subnet {blk}"
        if not allow_private:
            for blk in RFC1918_IPV6_SUBNETS:
                if ip_obj in blk:
                    return False, f"SECURITY INVARIANT: {label} belongs to internal/private IPv6 subnet {blk}"
        return True, None

    if str(ip_obj).lower() in _METADATA_HOST_IPS:
        return False, f"SECURITY INVARIANT: {label} resolves to cloud metadata IP {ip_obj}"
    if ip_obj in _LINK_LOCAL_IPV4:
        return False, f"SECURITY INVARIANT: {label} belongs to non-overridable link-local/metadata subnet {_LINK_LOCAL_IPV4}"
    if ip_obj in _UNSPECIFIED_IPV4:
        return False, f"SECURITY INVARIANT: {label} belongs to unspecified subnet {_UNSPECIFIED_IPV4}"
    if ip_obj in _LOOPBACK_IPV4:
        if allow_loopback:
            return True, None
        return False, f"SECURITY INVARIANT: {label} belongs to loopback subnet {_LOOPBACK_IPV4}"
    for blk in INVIOLABLE_IPV4_SUBNETS:
        if ip_obj in blk:
            return False, f"SECURITY INVARIANT: {label} belongs to inviolable subnet {blk}"
    if not allow_private:
        for blk in RFC1918_IPV4_SUBNETS:
            if ip_obj in blk:
                return False, f"SECURITY INVARIANT: {label} belongs to internal/private subnet {blk}"
    return True, None


class SSRFBlockedError(ValueError):
    """Raised when a target host or any resolved A/AAAA record violates SSRF invariants."""


def resolve_and_pin_host(
    host: str,
    port: Optional[int] = None,
    *,
    allow_loopback: bool = False,
    allow_private: bool = False,
) -> str:
    """Resolve ``host`` (A and AAAA), verify EVERY returned IP against SSRF blocks, and return a pinned IP.

    Prevents DNS rebinding and dual-stack SSRF bypasses by validating every
    returned A/AAAA record before the caller connects to the pinned IP.
    Raises :class:`SSRFBlockedError` (a ``ValueError`` subclass) when the host
    cannot be resolved or any resolved IP is private, loopback (unless explicitly
    permitted), link-local, metadata, IPv4-mapped IPv6, or NAT64.
    """
    raw = (host or "").strip()
    if not raw:
        raise SSRFBlockedError("Host is empty")

    if "://" in raw:
        parsed = urlparse(raw)
        clean_host = (parsed.hostname or "").strip().lower().rstrip(".")
        port = port or parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    else:
        clean_host = _extract_authority_host(raw)

    if not clean_host:
        raise SSRFBlockedError(f"Could not extract hostname from {host!r}")

    if clean_host in {
        "metadata.google.internal",
        "metadata.internal",
        "metadata.azure.com",
        "metadata.tencentyun.com",
        "metadata.aliyun.com",
        "local-metadata",
        "instance-data",
    }:
        raise SSRFBlockedError(f"SECURITY INVARIANT: Host '{clean_host}' is a blocked cloud metadata host")

    if clean_host in {"localhost", "localhost.localdomain"} and not allow_loopback:
        raise SSRFBlockedError(f"SECURITY INVARIANT: Host '{clean_host}' is a blocked loopback host")

    # Direct IP literal (canonical, integer, octal, hex, IPv6, IPv4-mapped, NAT64)
    literal_ip = normalize_ip_literal(clean_host)
    if literal_ip is not None:
        safe, reason = _check_resolved_ip_safety(
            literal_ip,
            f"Target IP {clean_host}",
            allow_loopback=allow_loopback,
            allow_private=allow_private,
        )
        if not safe:
            raise SSRFBlockedError(reason or f"Target IP {clean_host} is blocked")
        return str(literal_ip)

    check_port = port or 443
    try:
        addr_infos = socket.getaddrinfo(clean_host, check_port)
    except (socket.gaierror, OSError) as exc:
        raise SSRFBlockedError(f"DNS resolution failed for host '{clean_host}': {exc}") from exc

    verified_ips: List[str] = []
    for info in addr_infos:
        if not info or len(info) < 5 or not info[4]:
            continue
        resolved_str = str(info[4][0])
        resolved_ip = normalize_ip_literal(resolved_str)
        if resolved_ip is None:
            raise SSRFBlockedError(f"DNS returned unparseable address {resolved_str!r} for '{clean_host}'")
        safe, reason = _check_resolved_ip_safety(
            resolved_ip,
            f"Resolved host {clean_host} ({resolved_ip})",
            allow_loopback=allow_loopback,
            allow_private=allow_private,
        )
        if not safe:
            raise SSRFBlockedError(reason or f"Resolved IP {resolved_ip} for '{clean_host}' is blocked")
        canonical = str(resolved_ip)
        if canonical not in verified_ips:
            verified_ips.append(canonical)

    if not verified_ips:
        raise SSRFBlockedError(f"DNS resolution returned no addresses for '{clean_host}'")

    return verified_ips[0]


def validate_http_url_target(
    url: str,
    in_scope: Optional[List[str]] = None,
    out_of_scope: Optional[List[str]] = None,
    allow_loopback: bool = False,
    resolve_dns: bool = True,
    fail_closed: bool = False,
    excluded_paths: Optional[List[str]] = None,
    excluded_ports: Optional[List[int]] = None,
) -> Tuple[bool, str]:
    """Validate an outbound HTTP(S) target URL for SSRF and scope boundaries.

    Enforces strict checks regardless of CLI ``unrestricted_mode()``:
      1. Only ``http://`` and ``https://`` schemes (blocks ``file://``, ``gopher://``, etc.).
      2. Non-overridable blocking of ``169.254.0.0/16``, ``fe80::/10``, metadata
         hosts/IPs, ``0.0.0.0/8``, multicast/reserved, and RFC1918/CGNAT/ULA subnets.
      3. Blocks loopback unless BOTH ``allow_loopback=True`` AND the host matches
         an explicit loopback entry in ``in_scope``.
      4. Evaluates ``out_of_scope`` before ``in_scope`` (with IPv4/IPv6 CIDR support).
      5. When ``resolve_dns=True``, resolves hostnames via ``socket.getaddrinfo``
         and rejects if any returned IP falls into an inviolable or internal subnet.
    """
    raw = (url or "").strip()
    if not raw:
        return False, "URL target is empty"
    if any(ord(ch) < 32 or ch.isspace() for ch in raw):
        return False, "URL target contains whitespace or control characters"
    if raw.startswith("//"):
        return False, "Blocked scheme-relative URL"

    lower_raw = raw.lower()
    if lower_raw.startswith(("http://", "https://")):
        candidate = raw
    elif "://" in raw:
        scheme = raw.split("://", 1)[0].lower()
        return False, f"Blocked non-HTTP(S) URL scheme '{scheme}://'"
    elif _DISALLOWED_URL_SCHEME_PREFIX_RE.match(raw):
        scheme = raw.split(":", 1)[0].lower()
        return False, f"Blocked non-HTTP(S) URL scheme '{scheme}:'"
    else:
        candidate = f"http://{raw}"

    parsed = urlparse(candidate)
    scheme = (parsed.scheme or "").lower()
    if scheme not in {"http", "https"}:
        return False, f"Blocked non-HTTP(S) URL scheme '{scheme}'"
    if "\\" in (parsed.netloc or ""):
        return False, "URL target contains disallowed backslash in authority"

    try:
        port = parsed.port
    except ValueError:
        return False, "URL target specifies an invalid port"

    raw_host = parsed.hostname
    if not raw_host:
        return False, "URL target has no valid hostname"
    host = raw_host.strip().lower().rstrip(".")
    if not host:
        return False, "URL target has empty hostname"

    effective_excluded_ports = DEFAULT_EXCLUDED_PORTS if excluded_ports is None else excluded_ports
    if port is not None and port in effective_excluded_ports:
        return False, f"SECURITY INVARIANT: Port {port} is in excluded ports policy"

    if excluded_paths:
        raw_path = parsed.path or "/"
        norm_path = _normalize_url_path(raw_path).lower()
        for exp in excluded_paths:
            exp_norm = _normalize_url_path(exp).lower()
            if exp.lower() in raw_path.lower() or exp_norm in norm_path:
                return False, f"Path '{raw_path}' matches excluded path rule '{exp}'"

    # Check non-overridable cloud metadata hostnames before scope matching.
    if host in {
        "metadata.google.internal",
        "metadata.internal",
        "metadata.azure.com",
        "metadata.tencentyun.com",
        "metadata.aliyun.com",
        "local-metadata",
        "instance-data",
    }:
        return False, f"SECURITY INVARIANT: Host '{host}' is a non-overridable metadata host"

    in_patterns, in_subnets = _compile_url_scope_rules(in_scope)
    out_patterns, out_subnets = _compile_url_scope_rules(out_of_scope)
    ip_obj = normalize_ip_literal(host)

    # 1. Explicit out-of-scope rules take priority over allowlists.
    if _host_matches_compiled_rules(host, ip_obj, out_patterns, out_subnets):
        return False, f"Target '{host}' matches out-of-scope rule"

    # 2. Check explicit allowlist membership (when configured or fail-closed).
    has_allowlist = bool(in_patterns or in_subnets)
    in_scope_match = _host_matches_compiled_rules(host, ip_obj, in_patterns, in_subnets)
    if has_allowlist and not in_scope_match:
        return False, f"Target '{host}' is outside authorized scope"
    if not has_allowlist and fail_closed:
        return False, "Target is not covered by any in-scope rule (fail-closed policy)"

    # 3. Loopback is allowed ONLY when caller opts in AND the host itself is
    #    explicitly named in in_scope (prevents DNS rebinding to localhost).
    host_is_explicit_loopback = (
        host in {"localhost", "localhost.localdomain"}
        or (ip_obj is not None and _is_loopback_ip(ip_obj))
    )
    loopback_explicitly_permitted = bool(
        allow_loopback and has_allowlist and in_scope_match and host_is_explicit_loopback
    )

    if host in {"localhost", "localhost.localdomain"} and not loopback_explicitly_permitted:
        return False, f"SECURITY INVARIANT: Host '{host}' is a blocked loopback host"

    # 4. Validate literal IP addresses (all textual forms: int, hex, octal, IPv6-mapped).
    if ip_obj is not None:
        safe, reason = _check_resolved_ip_safety(
            ip_obj, f"Target IP {host}", allow_loopback=loopback_explicitly_permitted
        )
        if not safe:
            return False, reason or f"Target IP {host} is blocked by security invariant"

    # 5. Resolve DNS hostnames and enforce invariants on every returned IP.
    elif resolve_dns:
        check_port = port or (443 if scheme == "https" else 80)
        try:
            addr_infos = socket.getaddrinfo(host, check_port)
        except (socket.gaierror, OSError):
            addr_infos = []

        for info in addr_infos:
            if not info or len(info) < 5 or not info[4]:
                continue
            resolved_str = str(info[4][0])
            resolved_ip = normalize_ip_literal(resolved_str)
            if resolved_ip is None:
                continue
            safe, reason = _check_resolved_ip_safety(
                resolved_ip,
                f"Resolved host {host} ({resolved_ip})",
                allow_loopback=loopback_explicitly_permitted,
            )
            if not safe:
                return False, reason or f"Resolved IP {resolved_ip} for {host} is blocked"

    return True, f"Validated target '{host}'"


