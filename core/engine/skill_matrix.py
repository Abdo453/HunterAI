"""
HunterAI Skill Matrix — Authoritative capability registry for all agent teams.

Maps each agent team to:
- Vulnerability classes they can detect
- Tool categories they use
- Coverage scope (what asset types they analyze)
- Confidence levels achievable
- Hard limits (what they CANNOT detect — honesty principle)
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, FrozenSet, List, Set

from core.contracts.task_contracts import AgentTeam


class VulnClass(str, Enum):
    # Discovery
    ASSET_EXPOSURE        = "ASSET_EXPOSURE"
    SUBDOMAIN_TAKEOVER    = "SUBDOMAIN_TAKEOVER"
    # Network
    OPEN_PORT             = "OPEN_PORT"
    WEAK_TLS              = "WEAK_TLS"
    DEFAULT_CREDS         = "DEFAULT_CREDS"
    # Web / API
    IDOR                  = "IDOR"
    BOLA                  = "BOLA"
    BFLA                  = "BFLA"
    BROKEN_AUTH           = "BROKEN_AUTH"
    XSS_REFLECTED         = "XSS_REFLECTED"
    XSS_STORED            = "XSS_STORED"
    SQL_INJECTION         = "SQL_INJECTION"
    SSRF                  = "SSRF"
    CSRF                  = "CSRF"
    COMMAND_INJECTION     = "COMMAND_INJECTION"
    PATH_TRAVERSAL        = "PATH_TRAVERSAL"
    OPEN_REDIRECT         = "OPEN_REDIRECT"
    RATE_LIMIT_BYPASS     = "RATE_LIMIT_BYPASS"
    # API-specific
    MASS_ASSIGNMENT       = "MASS_ASSIGNMENT"
    EXCESSIVE_DATA        = "EXCESSIVE_DATA"
    GRAPHQL_INTROSPECTION = "GRAPHQL_INTROSPECTION"
    # JS
    HARDCODED_SECRET      = "HARDCODED_SECRET"
    EXPOSED_INTERNAL_API  = "EXPOSED_INTERNAL_API"
    # Logic
    BUSINESS_LOGIC        = "BUSINESS_LOGIC"
    RACE_CONDITION        = "RACE_CONDITION"


class ToolCategory(str, Enum):
    DNS_ENUM        = "DNS_ENUM"
    PORT_SCAN       = "PORT_SCAN"
    HTTP_PROBE      = "HTTP_PROBE"
    DIRECTORY_FUZZ  = "DIRECTORY_FUZZ"
    JS_ANALYSIS     = "JS_ANALYSIS"
    API_FUZZ        = "API_FUZZ"
    AUTH_TEST       = "AUTH_TEST"
    INJECTION_PROBE = "INJECTION_PROBE"
    DIFFERENTIAL    = "DIFFERENTIAL"
    TLS_AUDIT       = "TLS_AUDIT"


@dataclass(frozen=True)
class TeamSkillProfile:
    team: AgentTeam
    detectable_vulns: FrozenSet[VulnClass]
    tool_categories: FrozenSet[ToolCategory]
    asset_coverage: FrozenSet[str]  # AssetType values
    max_confidence: float  # 0.0 - 1.0
    hard_limits: FrozenSet[str]  # Things this team CANNOT detect


# Authoritative skill matrix
SKILL_MATRIX: Dict[AgentTeam, TeamSkillProfile] = {
    AgentTeam.RECON: TeamSkillProfile(
        team=AgentTeam.RECON,
        detectable_vulns=frozenset({VulnClass.ASSET_EXPOSURE, VulnClass.SUBDOMAIN_TAKEOVER}),
        tool_categories=frozenset({ToolCategory.DNS_ENUM, ToolCategory.HTTP_PROBE}),
        asset_coverage=frozenset({"DOMAIN", "HOST", "PORT"}),
        max_confidence=0.85,
        hard_limits=frozenset({
            "Cannot detect application-layer vulnerabilities",
            "Cannot analyze authenticated API endpoints",
        }),
    ),
    AgentTeam.NETWORK: TeamSkillProfile(
        team=AgentTeam.NETWORK,
        detectable_vulns=frozenset({VulnClass.OPEN_PORT, VulnClass.WEAK_TLS, VulnClass.DEFAULT_CREDS}),
        tool_categories=frozenset({ToolCategory.PORT_SCAN, ToolCategory.TLS_AUDIT, ToolCategory.AUTH_TEST}),
        asset_coverage=frozenset({"HOST", "PORT", "SERVICE"}),
        max_confidence=0.90,
        hard_limits=frozenset({
            "Cannot analyze HTTP application logic",
            "Cannot detect IDOR or authorization flaws",
        }),
    ),
    AgentTeam.WEB: TeamSkillProfile(
        team=AgentTeam.WEB,
        detectable_vulns=frozenset({
            VulnClass.XSS_REFLECTED, VulnClass.OPEN_REDIRECT,
            VulnClass.PATH_TRAVERSAL, VulnClass.CSRF,
        }),
        tool_categories=frozenset({ToolCategory.HTTP_PROBE, ToolCategory.DIRECTORY_FUZZ, ToolCategory.INJECTION_PROBE}),
        asset_coverage=frozenset({"ENDPOINT", "PARAMETER"}),
        max_confidence=0.80,
        hard_limits=frozenset({
            "Cannot detect stored XSS without authenticated session",
            "Cannot detect IDOR without two valid accounts",
        }),
    ),
    AgentTeam.API: TeamSkillProfile(
        team=AgentTeam.API,
        detectable_vulns=frozenset({
            VulnClass.IDOR, VulnClass.BOLA, VulnClass.BFLA,
            VulnClass.MASS_ASSIGNMENT, VulnClass.EXCESSIVE_DATA,
            VulnClass.GRAPHQL_INTROSPECTION, VulnClass.BROKEN_AUTH,
        }),
        tool_categories=frozenset({ToolCategory.API_FUZZ, ToolCategory.AUTH_TEST, ToolCategory.DIFFERENTIAL}),
        asset_coverage=frozenset({"API", "ENDPOINT", "PARAMETER"}),
        max_confidence=0.88,
        hard_limits=frozenset({
            "Cannot confirm without two different user accounts for differential testing",
            "Cannot detect server-side logic flaws without source code",
        }),
    ),
    AgentTeam.JAVASCRIPT: TeamSkillProfile(
        team=AgentTeam.JAVASCRIPT,
        detectable_vulns=frozenset({VulnClass.HARDCODED_SECRET, VulnClass.EXPOSED_INTERNAL_API}),
        tool_categories=frozenset({ToolCategory.JS_ANALYSIS}),
        asset_coverage=frozenset({"JS_BUNDLE", "ENDPOINT", "API"}),
        max_confidence=0.75,
        hard_limits=frozenset({
            "Cannot verify if exposed API endpoints are actually exploitable",
            "Cannot analyze server-side minified bundles",
        }),
    ),
    AgentTeam.VERIFICATION: TeamSkillProfile(
        team=AgentTeam.VERIFICATION,
        detectable_vulns=frozenset(set(VulnClass)),  # Can verify ANY vuln class
        tool_categories=frozenset({ToolCategory.DIFFERENTIAL, ToolCategory.INJECTION_PROBE}),
        asset_coverage=frozenset({"ENDPOINT", "PARAMETER", "API"}),
        max_confidence=0.98,  # Highest confidence — differential proof
        hard_limits=frozenset({
            "Cannot detect NEW vulnerability classes — only verify existing hypotheses",
            "Requires specific request/response pairs to verify",
        }),
    ),
}


def get_team_for_asset(asset_type: str) -> List[AgentTeam]:
    """Returns all teams that cover the given asset type."""
    return [
        team for team, profile in SKILL_MATRIX.items()
        if asset_type in profile.asset_coverage
    ]


def get_teams_for_vuln(vuln_class: VulnClass) -> List[AgentTeam]:
    """Returns all teams capable of detecting the given vulnerability class."""
    return [
        team for team, profile in SKILL_MATRIX.items()
        if vuln_class in profile.detectable_vulns
    ]


def skill_gap_analysis(discovered_assets: Set[str]) -> Dict[str, List[AgentTeam]]:
    """
    For each discovered asset type, returns which teams should be dispatched.
    Used by the Autonomous Assessment Engine to plan next steps.
    """
    return {asset: get_team_for_asset(asset) for asset in discovered_assets}
