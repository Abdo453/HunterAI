"""
Unit & Integration Tests for Claude-BugHunter Ported Features:
- 7-Question Gate Engine
- Bugcrowd VRT & CWE Taxonomy Mapper
- Evidence & PII Hygiene Sanitizer
- Enterprise Perimeter & Identity Matrix
- Disclosed Report Patterns & Heuristics
"""
from __future__ import annotations

import pytest

from core.disclosed_patterns import DisclosedPatternsCatalog
from core.enterprise_perimeter import EnterprisePerimeterMatrix
from core.evidence_sanitizer import EvidenceSanitizer
from core.seven_question_gate import SevenQuestionGate
from core.vrt_mapper import VRTMapper
from core.skill_registry import SkillRegistry


def test_vrt_mapper():
    rce_entry = VRTMapper.lookup("rce")
    assert rce_entry.priority == "P1"
    assert "CWE-94" in rce_entry.cwe
    assert rce_entry.cvss_base >= 9.0

    idor_entry = VRTMapper.lookup("idor")
    assert idor_entry.priority == "P2"
    assert "CWE-639" in idor_entry.cwe

    # Fuzzy match
    unknown_fuzzy = VRTMapper.lookup("custom_graphql_introspection_test")
    assert "graphql" in unknown_fuzzy.vrt_id or unknown_fuzzy.priority in ("P4", "P5")


def test_seven_question_gate():
    solid_finding = {
        "title": "IDOR in User Profile Endpoint",
        "type": "idor",
        "severity": "High",
        "url": "https://api.target.com/v1/users/5512/profile",
        "evidence": "GET /v1/users/5512/profile with user 5510 session token returned full victim profile: HTTP 200",
        "tool": "manual_probe",
        "target": "api.target.com",
        "recommendation": "Enforce server-side user ownership checks."
    }

    gate_result = SevenQuestionGate.evaluate_finding(solid_finding, in_scope_list=["api.target.com"])
    assert gate_result.passed is True
    assert gate_result.score >= 0.80
    assert len(gate_result.missing_items) == 0
    assert "PASSED" in gate_result.triage_statement

    weak_finding = {
        "title": "Possible bug somewhere",
        "type": "other",
        "evidence": "",
    }
    weak_result = SevenQuestionGate.evaluate_finding(weak_finding)
    assert weak_result.score < 0.70
    assert len(weak_result.missing_items) > 0


def test_evidence_sanitizer():
    raw_trace = """
    Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisSignature
    aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    {"user": "alice@company.com", "password": "SuperSecretPassword123!", "card": "4532 1234 5678 9012"}
    """
    cleaned = EvidenceSanitizer.sanitize(raw_trace)

    assert "[REDACTED_JWT_TOKEN]" in cleaned or "[REDACTED_BEARER_TOKEN]" in cleaned
    assert "[REDACTED_AWS_SECRET]" in cleaned
    assert "[REDACTED_PASSWORD]" in cleaned
    assert "[REDACTED_EMAIL]" in cleaned
    assert "[REDACTED_CARD_NUMBER]" in cleaned
    assert "SuperSecretPassword123!" not in cleaned
    assert "alice@company.com" not in cleaned


def test_enterprise_perimeter_matrix():
    okta_asset = EnterprisePerimeterMatrix.identify_profile("https://company.okta.com/oauth2/v1/authorize")
    assert okta_asset is not None
    assert okta_asset.asset_type == "identity_sso"
    assert "Okta" in okta_asset.vendor_platform

    fortinet_asset = EnterprisePerimeterMatrix.identify_profile("https://vpn.corp.com/remote/login")
    assert fortinet_asset is not None
    assert fortinet_asset.asset_type == "ssl_vpn"
    assert "Fortinet" in fortinet_asset.vendor_platform

    aws_imds = EnterprisePerimeterMatrix.identify_profile("http://169.254.169.254/latest/meta-data/")
    assert aws_imds is not None
    assert aws_imds.asset_type == "cloud_metadata"


def test_disclosed_patterns_catalog():
    idor_pat = DisclosedPatternsCatalog.get_pattern("idor")
    assert idor_pat is not None
    assert len(idor_pat.key_indicators) >= 2
    assert len(idor_pat.common_bypass_heuristics) >= 2

    ssrf_pat = DisclosedPatternsCatalog.get_pattern("ssrf")
    assert ssrf_pat is not None
    assert "169.254.169.254" in " ".join(ssrf_pat.key_indicators)


def test_new_analysis_skills_discovered():
    registry = SkillRegistry()
    registry.discover(force=True)

    all_names = registry.list_names()
    assert "perimeter_matrix" in all_names
    assert "triage_gate" in all_names

    p_skill = registry.instantiate("perimeter_matrix")
    assert p_skill is not None
    assert p_skill.category == "analysis"

    t_skill = registry.instantiate("triage_gate")
    assert t_skill is not None
    assert t_skill.category == "analysis"
