"""
HunterAI V12.0 Threat Intelligence & Financial Risk Test Suite
==============================================================
Verifies:
1. EPSS Calculation (Priors, Public Exploit elevation, Authentication modifiers)
2. CISA KEV Catalog Mapping and Ransomware correlation
3. CVSS v4.0 Base Score and Vector Generation (OASIS/FIRST standard)
4. Unified Threat Intelligence Profile synthesis
5. GDPR Article 83(5) statutory cap and estimated sanction calculation
6. PCI-DSS v4.0 merchant bank non-compliance penalties & card reissuance
7. HIPAA Security Rule statutory penalty cap assessment ($1,919,173)
8. Operational Downtime and DFIR Incident Response cost modeling
9. HackerOne & Bugcrowd publication-grade Markdown dossier generation
10. OASIS SARIF v2.1.0 schema validity and GitHub Code Scanning compatibility
"""
import json
import pytest
from pathlib import Path

from core.threat_intel.threat_intel_engine import (
    EPSSCalculator,
    CisaKevCatalog,
    CVSSv4Engine,
    ThreatIntelligenceEngine,
)
from core.impact.financial_impact_calculator import (
    FinancialImpactCalculator,
    FinancialExposureReport,
    DataSensitivityLevel,
)
from core.reporting.bounty_and_sarif_exporter import (
    BountyReportGenerator,
    SARIFExporter,
)


def test_epss_calculator_priors_and_modifiers():
    # 1. Baseline SQLi prior
    base_score, base_pct = EPSSCalculator.calculate("CWE-89", has_public_exploit=False, requires_auth=False)
    assert 0.70 <= base_score <= 0.85
    assert base_pct >= 0.90

    # 2. Elevated by public exploit
    exp_score, exp_pct = EPSSCalculator.calculate("CWE-89", has_public_exploit=True, requires_auth=False)
    assert exp_score > base_score
    assert exp_score >= 0.90

    # 3. Suppressed by requiring authentication
    auth_score, auth_pct = EPSSCalculator.calculate("CWE-89", has_public_exploit=False, requires_auth=True)
    assert auth_score < base_score


def test_cisa_kev_catalog_lookup():
    # CWE-78 OS Command Injection is in KEV with ransomware history
    kev_cmdi = CisaKevCatalog.lookup("CWE-78")
    assert kev_cmdi["in_cisa_kev"] is True
    assert kev_cmdi["cisa_ransomware_use"] is True
    assert "BOD 22-01" in kev_cmdi["cisa_due_date"]

    # Unknown / minor CWE is not in KEV
    kev_minor = CisaKevCatalog.lookup("CWE-200")
    assert kev_minor["in_cisa_kev"] is False
    assert kev_minor["cisa_ransomware_use"] is False


def test_cvss_v4_base_score_calculation():
    # Critical Network RCE Vector
    score, severity, vector = CVSSv4Engine.compute_base_score(
        attack_vector="N", attack_complexity="L", attack_requirements="N",
        privileges_required="N", user_interaction="N",
        vuln_confidentiality="H", vuln_integrity="H", vuln_availability="H"
    )
    assert score >= 9.0
    assert severity == "CRITICAL"
    assert "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H" in vector

    # Low / Medium Reflected XSS Vector
    xss_score, xss_sev, xss_vec = CVSSv4Engine.compute_base_score(
        attack_vector="N", attack_complexity="L", attack_requirements="N",
        privileges_required="N", user_interaction="P",
        vuln_confidentiality="L", vuln_integrity="L", vuln_availability="N"
    )
    assert 4.0 <= xss_score <= 6.5
    assert xss_sev == "MEDIUM"


def test_threat_intelligence_engine_unified_profile():
    profile = ThreatIntelligenceEngine.evaluate_finding(
        cwe_id="CWE-89",
        title="SQL Injection in Order Search",
        has_public_exploit=True,
        requires_auth=False,
        affects_subsequent_system=True
    )
    assert profile.cwe_id == "CWE-89"
    assert profile.epss_score >= 0.90
    assert profile.in_cisa_kev is True
    assert profile.active_in_wild is True
    assert profile.cvss_v4_severity in ("HIGH", "CRITICAL")
    d = profile.to_dict()
    assert d["in_cisa_kev"] is True
    assert "cvss_v4_vector" in d


def test_gdpr_article_83_statutory_and_estimated_fines():
    # Small company (€5M revenue): statutory cap is €20,000,000 (higher of €20M or 4%)
    cap_small, est_small = FinancialImpactCalculator.calculate_gdpr_fine(
        annual_turnover_eur=5_000_000.0,
        record_count=10_000,
        sensitivity=DataSensitivityLevel.PII_BASIC
    )
    assert cap_small == 20_000_000.0
    assert est_small >= 50_000.0

    # Enterprise (€1 Billion revenue): statutory cap is 4% = €40,000,000
    cap_ent, est_ent = FinancialImpactCalculator.calculate_gdpr_fine(
        annual_turnover_eur=1_000_000_000.0,
        record_count=600_000,
        sensitivity=DataSensitivityLevel.PROTECTED_HEALTH
    )
    assert cap_ent == 40_000_000.0
    assert est_ent > 10_000_000.0


def test_pci_dss_penalties_for_payment_data():
    # Non-financial data triggers $0 PCI penalties
    pci_zero = FinancialImpactCalculator.calculate_pci_penalties(
        record_count=10_000,
        sensitivity=DataSensitivityLevel.PII_BASIC
    )
    assert pci_zero == 0.0

    # Financial card data triggers forensics + card reissuance
    pci_loss = FinancialImpactCalculator.calculate_pci_penalties(
        record_count=10_000,
        sensitivity=DataSensitivityLevel.FINANCIAL_PAYMENT
    )
    # Forensics (50k) + Merchant fine (25k) + 10k * $6.50 (65k) = $140,000
    assert pci_loss == 140_000.0


def test_hipaa_penalties_for_health_records():
    # Non-health data triggers $0 HIPAA penalties
    hipaa_zero = FinancialImpactCalculator.calculate_hipaa_penalties(
        record_count=50_000,
        sensitivity=DataSensitivityLevel.PII_BASIC
    )
    assert hipaa_zero == 0.0

    # Large medical records breach is capped at statutory maximum ($1,919,173)
    hipaa_capped = FinancialImpactCalculator.calculate_hipaa_penalties(
        record_count=100_000,
        sensitivity=DataSensitivityLevel.PROTECTED_HEALTH
    )
    assert hipaa_capped == 1_919_173.0


def test_financial_exposure_report_aggregation_and_roi():
    report = FinancialImpactCalculator.assess_full_exposure(
        cwe_id="CWE-89",
        title="SQL Injection in Payments API",
        severity="CRITICAL",
        affected_records=20_000,
        annual_turnover_eur=10_000_000.0,
        sensitivity=DataSensitivityLevel.FINANCIAL_PAYMENT
    )
    assert report.total_potential_exposure_usd > 200_000.0
    assert report.pci_dss_penalties_usd > 100_000.0
    assert report.downtime_loss_usd > 50_000.0
    assert report.mitigation_roi_multiplier > 10.0
    assert "Return on Investment" in report.executive_narrative
    assert "€" in report.executive_narrative


def test_bounty_report_generator_hackerone_markdown():
    finding = {
        "title": "SQL Injection in User Search via 'filter' parameter",
        "cwe_id": "CWE-89",
        "asset": "https://payments.target.com",
        "route": "/api/v1/search",
        "method": "POST",
        "cvss_score": 9.4,
        "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N",
        "severity": "CRITICAL",
        "epss_score": 0.985,
        "evidence": "Extracted database banner and response timing disparity.",
        "remediation": "Use parameterized queries and bind variables.",
        "payload": "' OR 1=1--"
    }

    md = BountyReportGenerator.generate_hackerone_report(finding)
    assert "# SQL Injection in User Search" in md
    assert "## 🎯 Summary" in md
    assert "## 🏷️ Vulnerability Classification & Severity" in md
    assert "CRITICAL" in md
    assert "## 🔁 Step-by-Step Reproduction Procedure" in md
    assert "curl -s -X POST" in md
    assert "## 🛡️ Recommended Remediation Guidance" in md


def test_sarif_exporter_schema_and_rules(tmp_path):
    findings = [
        {
            "title": "SQL Injection in Search",
            "cwe_id": "CWE-89",
            "severity": "CRITICAL",
            "evidence": "Unauthenticated extraction confirmed",
            "file_path": "src/controllers/search.py",
            "line_number": 42
        },
        {
            "title": "Broken Access Control",
            "cwe_id": "CWE-639",
            "severity": "HIGH",
            "evidence": "IDOR accesses arbitrary user profiles",
            "file_path": "src/routes/profile.py",
            "line_number": 18
        }
    ]

    sarif_path = tmp_path / "output.sarif"
    sarif_doc = SARIFExporter.export_sarif(findings, output_file=sarif_path)

    assert sarif_path.exists()
    assert sarif_doc["version"] == "2.1.0"
    assert "sarif-schema-2.1.0.json" in sarif_doc["$schema"]

    run = sarif_doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "HunterAI"
    assert len(run["tool"]["driver"]["rules"]) == 2
    assert len(run["results"]) == 2

    # Check location mapping
    res0 = run["results"][0]
    assert res0["ruleId"] == "HUNTER-CWE89"
    assert res0["level"] == "error"
    assert res0["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/controllers/search.py"
    assert res0["locations"][0]["physicalLocation"]["region"]["startLine"] == 42
