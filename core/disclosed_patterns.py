"""
Disclosed Report Heuristics & Pattern Catalog
Curated heuristics, bypass tables, and vulnerability chain templates inspired by HackerOne & Bugcrowd disclosed reports.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class VulnerabilityPattern:
    vuln_class: str
    vrt_id: str
    key_indicators: List[str]
    common_bypass_heuristics: List[str]
    root_cause_explanation: str
    defensive_remediation: str


DISCLOSED_PATTERNS: Dict[str, VulnerabilityPattern] = {
    "idor": VulnerabilityPattern(
        vuln_class="Insecure Direct Object Reference (IDOR)",
        vrt_id="broken_access_control.idor",
        key_indicators=[
            "Sequential or predictable numeric IDs in REST paths (e.g. `/api/users/1024/profile`).",
            "UUIDs or account numbers passed in JSON request body without session-context validation.",
            "Multi-tenant API endpoints allowing tenant_id or org_id parameter switching."
        ],
        common_bypass_heuristics=[
            "Switch HTTP verbs (GET -> PUT/POST/PATCH or DELETE).",
            "Array wrapping or type juggling: `{\"id\": 1024}` vs `{\"id\": [1024]}`.",
            "Parameter pollution: `?id=victim_id&id=attacker_id`.",
            "JSON vs XML parser discrepancy in multi-format handlers."
        ],
        root_cause_explanation="The server trusts client-provided identifiers without verifying that the authenticated session owns the requested object.",
        defensive_remediation="Implement centralized, server-side object-level access control checks (e.g. `user.can_access(record)`)."
    ),
    "ssrf": VulnerabilityPattern(
        vuln_class="Server-Side Request Forgery (SSRF)",
        vrt_id="server_side_injection.ssrf",
        key_indicators=[
            "Endpoints taking `url=`, `webhook=`, `target=`, `image_url=`, `callback=`, or `export_pdf=` parameters.",
            "Cloud instance hosting with access to link-local metadata address (169.254.169.254).",
            "SVG / XML / PDF generation services parsing remote entity references."
        ],
        common_bypass_heuristics=[
            "Alternative IP representations (e.g., decimal `2130706433`, octal, IPv6 `[::]`, or hex).",
            "DNS rebinding via custom domain resolving first to public IP, then to 127.0.0.1.",
            "Redirect chains (public 302 redirecting to internal metadata IP).",
            "Enclosed alphanumeric or URL encoding variations."
        ],
        root_cause_explanation="Backend server fetches remote URLs supplied by users without strict IP-level whitelist enforcement or private range egress blocking.",
        defensive_remediation="Enforce strict allowlists of trusted domains, resolve DNS and block RFC1918/link-local addresses at the socket level, and require IMDSv2."
    ),
    "oauth_sso": VulnerabilityPattern(
        vuln_class="OAuth 2.0 & OpenID Connect Flaws",
        vrt_id="broken_authentication.oauth",
        key_indicators=[
            "OAuth authorization flow passing `redirect_uri` parameter.",
            "Missing or static `state` parameter in authorization requests.",
            "Implicit grant usage exposing tokens in URI fragments."
        ],
        common_bypass_heuristics=[
            "Subdomain or path traversal in `redirect_uri`: `https://auth.target.com/callback/../../attacker`.",
            "Open redirect chaining on authorized domain to bounce authorization code to external host.",
            "Parameter pollution on redirect parameter (`redirect_uri=good.com&redirect_uri=evil.com`)."
        ],
        root_cause_explanation="Authorization server performs lax validation (e.g. regex/prefix matching) on redirect URIs or omits CSRF state token verification.",
        defensive_remediation="Enforce exact-string matching on all pre-registered redirect URIs and mandate strict PKCE + cryptographic state parameters."
    ),
    "jwt": VulnerabilityPattern(
        vuln_class="JSON Web Token (JWT) Vulnerabilities",
        vrt_id="broken_authentication.jwt_misconfiguration",
        key_indicators=[
            "Stateless authentication using JWT `ey...` in Authorization headers or cookies.",
            "`alg` parameter specified in client-controlled JWT header.",
            "`jwk` or `jku` header parameters present."
        ],
        common_bypass_heuristics=[
            "Algorithm confusion: changing `RS256` to `HS256` and signing with public key.",
            "`none` algorithm attack by setting `\"alg\": \"none\"` with empty signature.",
            "Weak HMAC secret key cracking against standard wordlists.",
            "JKU / X5U header URL redirection to attacker-controlled JWK Set."
        ],
        root_cause_explanation="JWT library accepts algorithm choice dynamically from the unauthenticated token header or permits insecure algorithms.",
        defensive_remediation="Hardcode the verification algorithm on the server side and never trust client-provided algorithm headers."
    ),
}


class DisclosedPatternsCatalog:
    """
    يوفر أنماط ومؤشرات فحص الثغرات الحقيقية المستخلصة من تقارير Bug Bounty المفتوحة
    """

    @staticmethod
    def get_pattern(vuln_class_or_key: str) -> Optional[VulnerabilityPattern]:
        k = vuln_class_or_key.lower().replace("-", "_").replace(" ", "_")
        if k in DISCLOSED_PATTERNS:
            return DISCLOSED_PATTERNS[k]
        for name, pat in DISCLOSED_PATTERNS.items():
            if name in k or k in name:
                return pat
        return None

    @staticmethod
    def list_all_patterns() -> List[VulnerabilityPattern]:
        return list(DISCLOSED_PATTERNS.values())
