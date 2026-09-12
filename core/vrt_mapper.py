"""
Bugcrowd VRT (Vulnerability Rating Taxonomy) & CWE Mapper
Maps vulnerability classes to standardized VRT priority (P1-P5), CWEs, and standard definitions.
Inspired by Claude-BugHunter & Bugcrowd VRT.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class VRTEntry:
    vrt_id: str
    category: str
    subcategory: str
    priority: str          # P1 (Critical), P2 (High), P3 (Medium), P4 (Low), P5 (Informational)
    cwe: str
    cvss_base: float
    description: str


# Standard VRT Mapping for 24 core bug-hunting classes
VRT_DATABASE: Dict[str, VRTEntry] = {
    "rce": VRTEntry(
        vrt_id="server_side_injection.remote_code_execution",
        category="Server-Side Injection",
        subcategory="Remote Code Execution (RCE)",
        priority="P1",
        cwe="CWE-94",
        cvss_base=9.8,
        description="Arbitrary command or code execution on the underlying server environment."
    ),
    "sqli": VRTEntry(
        vrt_id="server_side_injection.sql_injection",
        category="Server-Side Injection",
        subcategory="SQL Injection",
        priority="P1",
        cwe="CWE-89",
        cvss_base=9.0,
        description="Unauthorized database manipulation or exfiltration via unsanitized SQL queries."
    ),
    "ssrf_cloud": VRTEntry(
        vrt_id="server_side_injection.ssrf.cloud_metadata",
        category="Server-Side Injection",
        subcategory="SSRF into Cloud Metadata / Internal Network",
        priority="P1",
        cwe="CWE-918",
        cvss_base=9.1,
        description="Server-Side Request Forgery reaching internal metadata services (e.g. AWS IMDS)."
    ),
    "ssrf": VRTEntry(
        vrt_id="server_side_injection.ssrf",
        category="Server-Side Injection",
        subcategory="Server-Side Request Forgery (Blind/Partial)",
        priority="P2",
        cwe="CWE-918",
        cvss_base=7.5,
        description="Forcing server to make arbitrary requests to intranet or external destinations."
    ),
    "auth_bypass": VRTEntry(
        vrt_id="broken_authentication.authentication_bypass",
        category="Broken Authentication",
        subcategory="Authentication Bypass",
        priority="P1",
        cwe="CWE-287",
        cvss_base=9.8,
        description="Direct bypass of authentication controls granting unauthorized identity access."
    ),
    "oauth_takeover": VRTEntry(
        vrt_id="broken_authentication.oauth.account_takeover",
        category="Broken Authentication",
        subcategory="OAuth Account Takeover (redirect_uri / state flaw)",
        priority="P1",
        cwe="CWE-287",
        cvss_base=8.8,
        description="Pre-auth or OAuth flow hijack leading to full victim account takeover."
    ),
    "idor_critical": VRTEntry(
        vrt_id="broken_access_control.idor.pii_or_financial",
        category="Broken Access Control",
        subcategory="IDOR (Sensitive PII / Financial Data / Critical Action)",
        priority="P1",
        cwe="CWE-639",
        cvss_base=8.5,
        description="Insecure Direct Object Reference leaking sensitive user records or executing state changes."
    ),
    "idor": VRTEntry(
        vrt_id="broken_access_control.idor",
        category="Broken Access Control",
        subcategory="IDOR (Standard / Non-Critical Data)",
        priority="P2",
        cwe="CWE-639",
        cvss_base=6.5,
        description="Insecure Direct Object Reference allowing unauthorized viewing or modification of objects."
    ),
    "xss_stored": VRTEntry(
        vrt_id="cross_site_scripting.stored_xss",
        category="Cross-Site Scripting (XSS)",
        subcategory="Stored XSS (Admin/User context)",
        priority="P2",
        cwe="CWE-79",
        cvss_base=7.2,
        description="Persistent script execution rendered in user or administrative sessions."
    ),
    "xss_reflected": VRTEntry(
        vrt_id="cross_site_scripting.reflected_xss",
        category="Cross-Site Scripting (XSS)",
        subcategory="Reflected XSS",
        priority="P3",
        cwe="CWE-79",
        cvss_base=6.1,
        description="Immediate script reflection in web response from user input."
    ),
    "jwt_weakness": VRTEntry(
        vrt_id="broken_authentication.jwt_misconfiguration",
        category="Broken Authentication",
        subcategory="JWT Algorithm Confusion / Weak Secret",
        priority="P2",
        cwe="CWE-347",
        cvss_base=7.5,
        description="Flawed JSON Web Token validation (none algorithm, brute-forced HMAC secret)."
    ),
    "graphql_introspection": VRTEntry(
        vrt_id="information_disclosure.graphql_introspection",
        category="Information Disclosure",
        subcategory="GraphQL Introspection Enabled",
        priority="P4",
        cwe="CWE-200",
        cvss_base=4.3,
        description="Full GraphQL schema exposition revealing hidden queries, mutations, and types."
    ),
    "subdomain_takeover": VRTEntry(
        vrt_id="server_security_misconfiguration.subdomain_takeover",
        category="Server Security Misconfiguration",
        subcategory="Subdomain Takeover (Dangling DNS)",
        priority="P2",
        cwe="CWE-284",
        cvss_base=7.5,
        description="Dangling DNS CNAME pointing to unclaimed third-party cloud resource (S3, GitHub, etc.)."
    ),
    "secrets_leaked": VRTEntry(
        vrt_id="information_disclosure.hardcoded_secrets",
        category="Information Disclosure",
        subcategory="Hardcoded Credentials / API Keys Exposed",
        priority="P2",
        cwe="CWE-798",
        cvss_base=7.5,
        description="Leaked production tokens, private keys, or cloud access keys in JS or public endpoints."
    ),
    "cors_misconfig": VRTEntry(
        vrt_id="server_security_misconfiguration.cors",
        category="Server Security Misconfiguration",
        subcategory="CORS Origin Reflection with Credentials",
        priority="P3",
        cwe="CWE-942",
        cvss_base=6.5,
        description="Permissive CORS configuration allowing arbitrary origins to read authenticated responses."
    ),
}


class VRTMapper:
    """
    محرك مطابقة وتصنيف الثغرات وفق Bugcrowd VRT القياسي
    """

    @staticmethod
    def lookup(vuln_type: str) -> VRTEntry:
        """البحث عن تصنيف VRT بناءً على نوع الثغرة أو إرجاع افتراضي P4"""
        key = vuln_type.lower().strip().replace("-", "_").replace(" ", "_")
        if key in VRT_DATABASE:
            return VRT_DATABASE[key]

        # Substring fuzzy matching
        for k, v in VRT_DATABASE.items():
            if k in key or key in k:
                return v

        return VRTEntry(
            vrt_id=f"other.{key}",
            category="Other Security Finding",
            subcategory=vuln_type.capitalize(),
            priority="P4",
            cwe="CWE-200",
            cvss_base=5.0,
            description="General security observation or unclassified finding."
        )

    @staticmethod
    def priority_to_severity(priority: str) -> str:
        mapping = {
            "P1": "Critical",
            "P2": "High",
            "P3": "Medium",
            "P4": "Low",
            "P5": "Info",
        }
        return mapping.get(priority.upper(), "Info")
