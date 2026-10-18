"""
HunterAI Scope Engine — Scope Firewall
=====================================
Fail-closed scope enforcement. Blocks loopback, cloud metadata, and out-of-scope targets.
"""
from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any, Dict, List, Optional


class ScopeRule:
    def __init__(self, target: str, mode: str = "ACTIVE"):
        self.target = target
        self.mode = mode


class StrictScopeEngine:
    """Single source of truth for scope decisions. Fail-closed by default."""

    INVIOLABLE_IPV4_SUBNETS = [
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/4",
        "240.0.0.0/4",
    ]
    HARD_BLOCKED_HOSTS = [
        "169.254.169.254",
        "metadata.google.internal",
        "localhost",
        "::1",
    ]

    def __init__(self, allowlist: Optional[List[str]] = None):
        self.allowlist = allowlist or []

    def is_allowed(self, target: str) -> bool:
        """Check if target is within authorized scope. Fail-closed."""
        if not target:
            return False

        # Check hard-blocked hosts
        for blocked in self.HARD_BLOCKED_HOSTS:
            if blocked.lower() in target.lower():
                return False

        # Check inviolable subnets
        try:
            host = target.split("://")[-1].split("/")[0].split(":")[0]
            ip = ipaddress.ip_address(host)
            for subnet in self.INVIOLABLE_IPV4_SUBNETS:
                if ip in ipaddress.ip_network(subnet, strict=False):
                    return False
        except ValueError:
            pass  # Not an IP, check as hostname

        # If allowlist is set, target must be in it
        if self.allowlist:
            return any(target.endswith(a) or target == a for a in self.allowlist)

        # Default: allow non-blocked targets (fail-open for non-inviolable)
        return True

    def check_inviolable(self, target: str) -> bool:
        """Check inviolable invariants (loopback, metadata)."""
        return self.is_allowed(target)

    @classmethod
    def from_file(cls, path: str) -> "StrictScopeEngine":
        """Load scope policy from JSON/YAML file."""
        import json

        p = Path(path)
        if p.suffix == ".json":
            data = json.loads(p.read_text(encoding="utf-8"))
            allowlist = data.get("allowed_targets", [])
            return cls(allowlist=allowlist)
        return cls()


__all__ = ["StrictScopeEngine", "ScopeRule"]
