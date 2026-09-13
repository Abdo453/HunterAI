"""
HunterAI Target Profiles Engine
===============================
Optimizes testing focus based on application architecture profile:
- API (REST/OpenAPI, JSON, JWT, BOLA)
- SPA (React/Vue/Angular, client routing, DOM XSS, CORS)
- GRAPHQL (Introspection, batching, field authorization)
- WORDPRESS (Core plugins, XMLRPC, users)
- GENERIC_WEB (Full OWASP baseline)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Set


class ProfileType(str, Enum):
    API = "API"
    SPA = "SPA"
    GRAPHQL = "GRAPHQL"
    WORDPRESS = "WORDPRESS"
    GENERIC_WEB = "GENERIC_WEB"


@dataclass
class TargetProfile:
    profile_type: ProfileType = ProfileType.GENERIC_WEB
    description: str = "Standard web application testing profile."
    prioritized_vuln_classes: List[str] = field(default_factory=list)
    suppressed_vuln_classes: List[str] = field(default_factory=list)
    sensitive_path_patterns: List[str] = field(default_factory=list)
    content_type_whitelist: List[str] = field(default_factory=list)

    @classmethod
    def get_profile(cls, p_type: ProfileType | str) -> TargetProfile:
        ptype = ProfileType(p_type) if isinstance(p_type, str) else p_type
        if ptype == ProfileType.API:
            return TargetProfile(
                profile_type=ProfileType.API,
                description="REST / Microservice API Profile",
                prioritized_vuln_classes=["idor", "jwt", "ssrf", "sqli", "broken_auth"],
                suppressed_vuln_classes=["clickjacking", "cookie_flags_info"],
                sensitive_path_patterns=["/api/", "/v1/", "/v2/", "/graphql", "/oauth"],
                content_type_whitelist=["application/json", "application/xml"]
            )
        elif ptype == ProfileType.SPA:
            return TargetProfile(
                profile_type=ProfileType.SPA,
                description="Single Page Application Profile (React/Vue/Angular)",
                prioritized_vuln_classes=["xss", "cors", "jwt", "idor", "open_redirect"],
                suppressed_vuln_classes=[],
                sensitive_path_patterns=["/static/js/", "/app/", "/dashboard", "/login"],
                content_type_whitelist=["text/html", "application/javascript", "application/json"]
            )
        elif ptype == ProfileType.GRAPHQL:
            return TargetProfile(
                profile_type=ProfileType.GRAPHQL,
                description="GraphQL Endpoint Profile",
                prioritized_vuln_classes=["graphql_introspection", "idor", "sqli", "dos_batching"],
                suppressed_vuln_classes=["path_traversal"],
                sensitive_path_patterns=["/graphql", "/api/graphql", "/v1/graphql"],
                content_type_whitelist=["application/json"]
            )
        elif ptype == ProfileType.WORDPRESS:
            return TargetProfile(
                profile_type=ProfileType.WORDPRESS,
                description="WordPress CMS Profile",
                prioritized_vuln_classes=["wp_plugin_cve", "sqli", "xss", "user_enumeration"],
                suppressed_vuln_classes=[],
                sensitive_path_patterns=["/wp-admin/", "/wp-json/", "/xmlrpc.php", "/wp-content/"],
                content_type_whitelist=["text/html", "application/json"]
            )
        else:
            return TargetProfile(
                profile_type=ProfileType.GENERIC_WEB,
                description="Generic Web Application Profile",
                prioritized_vuln_classes=["xss", "sqli", "idor", "ssrf", "file_upload", "cmd_injection"],
                suppressed_vuln_classes=[],
                sensitive_path_patterns=[],
                content_type_whitelist=[]
            )

    def prioritize_endpoint(self, path: str, method: str) -> int:
        """Assigns an execution priority weight (1=highest priority, 10=lowest)"""
        low_path = path.lower()
        if any(p in low_path for p in ["/login", "/auth", "/token", "/session"]):
            return 1
        if any(p in low_path for p in ["/user", "/account", "/order", "/document", "/profile"]):
            return 2
        if any(p in low_path for p in self.sensitive_path_patterns):
            return 3
        if method.upper() in ("POST", "PUT", "DELETE"):
            return 4
        return 5
