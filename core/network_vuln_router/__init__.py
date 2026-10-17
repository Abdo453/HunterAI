"""Network service→vulnerability router (rule-based, candidate-only)."""
from core.network_vuln_router.rules import (
    VulnRule, NETWORK_RULES, PROBE_BY_SERVICE,
)
from core.network_vuln_router.router import NetworkVulnRouter, WEB_SERVICES

__all__ = [
    "VulnRule",
    "NETWORK_RULES",
    "PROBE_BY_SERVICE",
    "NetworkVulnRouter",
    "WEB_SERVICES",
]
__version__ = "0.1.0-phase1"
