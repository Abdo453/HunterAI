"""
HunterAI Compliance & Framework Mapper
======================================
Strict Epistemic Rule:
Compliance mappings are an interpretive classification applied AFTER a finding has
been proven with forensic evidence. A mapping NEVER serves as proof of a vulnerability.

Mappings Supported:
- OWASP Top 10 (2021)
- CWE (Common Weakness Enumeration)
- CAPEC (Common Attack Pattern Enumeration and Classification)
- NIST SP 800-53 Rev 5 Controls
- CIS Critical Security Controls v8
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class ComplianceMappingRecord:
    cwe_id: str
    vulnerability_title: str
    owasp_top10: str
    capec_id: str
    nist_sp800_53: str
    cis_control: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cwe_id": self.cwe_id,
            "title": self.vulnerability_title,
            "owasp": self.owasp_top10,
            "capec": self.capec_id,
            "nist": self.nist_sp800_53,
            "cis": self.cis_control,
        }


class ComplianceMapper:
    """Maps proven vulnerabilities to major cybersecurity frameworks"""

    _KNOWLEDGE_BASE: Dict[str, ComplianceMappingRecord] = {
        "CWE-89": ComplianceMappingRecord(
            cwe_id="CWE-89",
            vulnerability_title="SQL Injection",
            owasp_top10="A03:2021-Injection",
            capec_id="CAPEC-66: SQL Injection",
            nist_sp800_53="SI-10: Information Input Validation",
            cis_control="CIS 16.1: Maintain an Inventory of Application Software"
        ),
        "CWE-639": ComplianceMappingRecord(
            cwe_id="CWE-639",
            vulnerability_title="Broken Object Level Authorization (BOLA/IDOR)",
            owasp_top10="A01:2021-Broken Access Control",
            capec_id="CAPEC-580: Object-Based Authorization Bypass",
            nist_sp800_53="AC-3: Access Enforcement",
            cis_control="CIS 3.3: Configure Data Access Control Lists"
        ),
        "CWE-78": ComplianceMappingRecord(
            cwe_id="CWE-78",
            vulnerability_title="Command Injection",
            owasp_top10="A03:2021-Injection",
            capec_id="CAPEC-88: OS Command Injection",
            nist_sp800_53="SI-10: Information Input Validation",
            cis_control="CIS 16.3: Perform Root Cause Analysis on Application Bugs"
        ),
        "CWE-918": ComplianceMappingRecord(
            cwe_id="CWE-918",
            vulnerability_title="Server-Side Request Forgery (SSRF)",
            owasp_top10="A10:2021-Server-Side Request Forgery (SSRF)",
            capec_id="CAPEC-664: Server Side Request Forgery",
            nist_sp800_53="SC-7: Boundary Protection",
            cis_control="CIS 12.1: Ensure Network Infrastructure is Architected Safely"
        ),
        "CWE-79": ComplianceMappingRecord(
            cwe_id="CWE-79",
            vulnerability_title="Cross-Site Scripting (XSS)",
            owasp_top10="A03:2021-Injection",
            capec_id="CAPEC-63: Simple Script Injection",
            nist_sp800_53="SI-10: Information Input Validation",
            cis_control="CIS 16.2: Implement Safe Code Analysis"
        ),
        "CWE-287": ComplianceMappingRecord(
            cwe_id="CWE-287",
            vulnerability_title="Improper Authentication",
            owasp_top10="A07:2021-Identification and Authentication Failures",
            capec_id="CAPEC-115: Authentication Bypass",
            nist_sp800_53="IA-2: Identification and Authentication",
            cis_control="CIS 6.1: Establish an Access Revoking Process"
        ),
    }

    @classmethod
    def map_cwe(cls, cwe_id: str) -> ComplianceMappingRecord:
        cwe_clean = cwe_id.upper().strip()
        if cwe_clean in cls._KNOWLEDGE_BASE:
            return cls._KNOWLEDGE_BASE[cwe_clean]

        # Generic fallback
        return ComplianceMappingRecord(
            cwe_id=cwe_clean,
            vulnerability_title="General Security Flaw",
            owasp_top10="A04:2021-Insecure Design",
            capec_id="CAPEC-1: General Flaw",
            nist_sp800_53="RA-5: Vulnerability Monitoring and Scanning",
            cis_control="CIS 16.1: Secure Software Development"
        )
