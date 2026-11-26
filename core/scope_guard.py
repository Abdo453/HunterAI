"""
Scope Guard & Safety Enforcer
نظام التحقق من النطاق وقواعد الاشتباك — يمنع فحص أي أهداف خارج الـ Scope المصرح به
"""
import re
import ipaddress
from urllib.parse import urlparse
from typing import List, Dict, Tuple, Optional, Union

from core.scope_engine import ScopePolicy, StrictScopeEngine, normalize_ip_literal
from core.security_mode import unrestricted_mode

# Single reference engine, used ONLY for the non-overridable safety invariants
# (loopback / cloud metadata / RFC1918). This is what unifies every legacy scope
# guard onto one authority instead of each re-implementing its own (weaker) rules.
_INVARIANT_ENGINE = StrictScopeEngine(ScopePolicy(allowed_targets=[], fail_closed=True))
_LINK_LOCAL_V4 = ipaddress.IPv4Network("169.254.0.0/16")
_IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


class ScopeGuard:
    """
    حارس النطاق الأمني:
    - يتحقق من النطاقات المسموحة (In-Scope)
    - يحظر النطاقات المستثناة (Out-of-Scope)
    - يدعم Wildcards (*.example.com) و CIDR IPv4/IPv6 ranges
    """

    def __init__(
        self,
        in_scope: Optional[List[str]] = None,
        out_of_scope: Optional[List[str]] = None,
        fail_closed: bool = False,
    ):
        self.in_scope_raw = in_scope or []
        self.out_of_scope_raw = out_of_scope or []
        self.fail_closed = bool(fail_closed)

        self.in_scope_patterns: List[re.Pattern] = []
        self.out_of_scope_patterns: List[re.Pattern] = []
        self.in_scope_subnets: List[_IPNetwork] = []
        self.out_of_scope_subnets: List[_IPNetwork] = []

        self._compile_rules()

    @property
    def in_scope(self) -> List[str]:
        return self.in_scope_raw

    @property
    def out_of_scope(self) -> List[str]:
        return self.out_of_scope_raw

    def _compile_rules(self):
        """تحويل القواعد إلى تعابير نمطية وشبكات IP"""
        self.in_scope_patterns = []
        self.out_of_scope_patterns = []
        self.in_scope_subnets = []
        self.out_of_scope_subnets = []

        for item in self.in_scope_raw:
            self._add_rule(item, self.in_scope_patterns, self.in_scope_subnets)

        for item in self.out_of_scope_raw:
            self._add_rule(item, self.out_of_scope_patterns, self.out_of_scope_subnets)

    @staticmethod
    def _extract_host(target: str) -> str:
        clean = target.strip().lower()
        if clean.startswith(("http://", "https://")):
            parsed = urlparse(clean)
            return (parsed.hostname or clean).lower()
        host_part = clean.split("/", 1)[0]
        if host_part.startswith("["):
            end = host_part.find("]")
            if end != -1:
                return host_part[1:end]
            return host_part.lstrip("[")
        if host_part.count(":") == 1:
            return host_part.split(":", 1)[0]
        return host_part

    def _add_rule(self, item: str, patterns_list: list, subnets_list: list):
        clean = item.strip().lower()
        if not clean:
            return

        # Check IPv4/IPv6 CIDR or IP literal before URL/port stripping
        ip_candidate = clean
        if clean.startswith(("http://", "https://")):
            parsed = urlparse(clean)
            ip_candidate = (parsed.hostname or "").strip().lower()
        elif clean.startswith("["):
            end = clean.find("]")
            if end != -1:
                ip_candidate = clean[1:end]

        if ip_candidate:
            try:
                net = ipaddress.ip_network(ip_candidate, strict=False)
                subnets_list.append(net)
                return
            except ValueError:
                pass

        # Wildcard domain handling (e.g. *, *.example.com or example.com)
        clean = re.sub(r"^https?://", "", clean)
        clean = clean.split("/")[0].split(":")[0]  # remove path and port
        if not clean:
            return

        if clean == "*":
            patterns_list.append(re.compile(r"^.*$", re.IGNORECASE))
        elif clean.startswith("*."):
            domain_part = re.escape(clean[2:])
            # Matches sub.example.com or example.com
            pattern = re.compile(rf"^(?:[a-zA-Z0-9_\-]+\.)*{domain_part}$", re.IGNORECASE)
            patterns_list.append(pattern)
        else:
            domain_part = re.escape(clean)
            # Matches exact domain or any subdomain
            pattern = re.compile(rf"^(?:[a-zA-Z0-9_\-]+\.)*{domain_part}$", re.IGNORECASE)
            patterns_list.append(pattern)

    def _is_explicit_ip_allowlist(self, host: str) -> bool:
        """True when the host is an explicit literal-IP in_scope entry.

        This preserves deliberate lab engagements (e.g. in_scope=["127.0.0.1"])
        without weakening the invariant for every other target.
        """
        target_ip = normalize_ip_literal(host)
        if target_ip is None:
            return False
        return any(normalize_ip_literal(item) == target_ip for item in self.in_scope_raw)

    def is_in_scope(self, target: str) -> Tuple[bool, str]:
        """
        التحقق مما إذا كان الهدف مسموحاً به في الـ Scope
        إرجاع: (is_allowed: bool, reason: str)
        """
        if not target or not target.strip():
            return False, "Target is empty"

        if unrestricted_mode():
            return True, "Unrestricted owner mode: all targets authorized."

        host = self._extract_host(target)
        if not host:
            return False, "Target host is empty"

        # 0. Link-local / cloud metadata (169.254.0.0/16) is NEVER overridable,
        #    even when placed explicitly in in_scope_raw.
        target_ip = normalize_ip_literal(host)
        if target_ip is not None:
            norm_ip = (
                target_ip.ipv4_mapped
                if isinstance(target_ip, ipaddress.IPv6Address) and target_ip.ipv4_mapped is not None
                else target_ip
            )
            if isinstance(norm_ip, ipaddress.IPv4Address) and norm_ip in _LINK_LOCAL_V4:
                return (
                    False,
                    f"SECURITY INVARIANT: IP {host} belongs to inviolable subnet {_LINK_LOCAL_V4} and cannot be scanned.",
                )

        #    Other safety invariants (loopback / RFC1918) via the reference engine.
        #    An EXPLICIT literal-IP entry in in_scope acts as a deliberate lab override.
        if not self._is_explicit_ip_allowlist(host):
            inv_ok, inv_reason = _INVARIANT_ENGINE.check_inviolable(host)
            if not inv_ok:
                return False, inv_reason

        # 1. فحص إذا كان في الـ Out-of-Scope أولاً (Blacklist Priority)
        if target_ip is not None:
            candidates = [target_ip]
            if isinstance(target_ip, ipaddress.IPv6Address) and target_ip.ipv4_mapped is not None:
                candidates.append(target_ip.ipv4_mapped)
            for cand in candidates:
                for net in self.out_of_scope_subnets:
                    if cand.version == net.version and cand in net:
                        return False, f"Target IP {host} is in Out-of-Scope subnet: {net}"

        # Check patterns
        for pat in self.out_of_scope_patterns:
            if pat.search(host):
                return False, f"Target {host} matches Out-of-Scope rule"

        # If no in-scope rules defined, respect fail_closed flag
        if not self.in_scope_patterns and not self.in_scope_subnets:
            if self.fail_closed:
                return False, f"Target {host} is outside authorized scope (fail-closed policy)"
            return True, "No specific in-scope filter defined (Permissive)"

        # 2. فحص إذا كان يطابق قواعد الـ In-Scope
        if target_ip is not None:
            candidates = [target_ip]
            if isinstance(target_ip, ipaddress.IPv6Address) and target_ip.ipv4_mapped is not None:
                candidates.append(target_ip.ipv4_mapped)
            for cand in candidates:
                for net in self.in_scope_subnets:
                    if cand.version == net.version and cand in net:
                        return True, f"Target IP {host} matched In-Scope subnet: {net}"

        for pat in self.in_scope_patterns:
            if pat.search(host):
                return True, f"Target {host} matched In-Scope domain rule"

        return False, f"Target {host} is outside authorized scope"

    is_allowed = is_in_scope

    def filter_urls(self, urls: List[str]) -> List[str]:
        """تصفية قائمة روابط وإبقاء المسموح به فقط"""
        valid = []
        for u in urls:
            allowed, _ = self.is_in_scope(u)
            if allowed:
                valid.append(u)
        return valid

    def to_dict(self) -> Dict[str, List[str]]:
        return {
            "in_scope": self.in_scope_raw,
            "out_of_scope": self.out_of_scope_raw
        }
