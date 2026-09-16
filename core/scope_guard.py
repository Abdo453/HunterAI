"""
Scope Guard & Safety Enforcer
نظام التحقق من النطاق وقواعد الاشتباك — يمنع فحص أي أهداف خارج الـ Scope المصرح به
"""
import re
import ipaddress
from urllib.parse import urlparse
from typing import List, Dict, Tuple, Optional, Set


class ScopeGuard:
    """
    حارس النطاق الأمني:
    - يتحقق من النطاقات المسموحة (In-Scope)
    - يحظر النطاقات المستثناة (Out-of-Scope)
    - يدعم Wildcards (*.example.com) و CIDR IP ranges
    """

    def __init__(self, in_scope: Optional[List[str]] = None, out_of_scope: Optional[List[str]] = None):
        self.in_scope_raw = in_scope or []
        self.out_of_scope_raw = out_of_scope or []
        
        self.in_scope_patterns: List[re.Pattern] = []
        self.out_of_scope_patterns: List[re.Pattern] = []
        self.in_scope_subnets: List[ipaddress.IPv4Network] = []
        self.out_of_scope_subnets: List[ipaddress.IPv4Network] = []
        
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

    def _add_rule(self, item: str, patterns_list: list, subnets_list: list):
        clean = item.strip().lower()
        if not clean:
            return

        # Check if it's a CIDR or IP
        try:
            if "/" in clean:
                net = ipaddress.IPv4Network(clean, strict=False)
                subnets_list.append(net)
                return
            else:
                ip = ipaddress.IPv4Address(clean)
                subnets_list.append(ipaddress.IPv4Network(f"{clean}/32"))
                return
        except ValueError:
            pass

        # Wildcard domain handling (e.g. *, *.example.com or example.com)
        clean = re.sub(r"^https?://", "", clean)
        clean = clean.split("/")[0].split(":")[0]  # remove path and port

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

    def is_in_scope(self, target: str) -> Tuple[bool, str]:
        """
        التحقق مما إذا كان الهدف مسموحاً به في الـ Scope
        إرجاع: (is_allowed: bool, reason: str)
        """
        if not target or not target.strip():
            return False, "Target is empty"

        clean = target.strip().lower()
        # Parse hostname
        if clean.startswith("http://") or clean.startswith("https://"):
            parsed = urlparse(clean)
            host = parsed.hostname or clean
        else:
            host = clean.split("/")[0].split(":")[0]

        # 1. فحص إذا كان في الـ Out-of-Scope أولاً (Blacklist Priority)
        # Check subnets
        try:
            ip_obj = ipaddress.IPv4Address(host)
            for net in self.out_of_scope_subnets:
                if ip_obj in net:
                    return False, f"Target IP {host} is in Out-of-Scope subnet: {net}"
        except ValueError:
            pass

        # Check patterns
        for pat in self.out_of_scope_patterns:
            if pat.search(host):
                return False, f"Target {host} matches Out-of-Scope rule"

        # If no in-scope rules defined, permit by default
        if not self.in_scope_patterns and not self.in_scope_subnets:
            return True, "No specific in-scope filter defined (Permissive)"

        # 2. فحص إذا كان يطابق قواعد الـ In-Scope
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
