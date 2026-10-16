"""Tests لـ Trivy Dependency Risk Analyzer Pilot — L1→L5"""
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.trivy.schemas import TrivyVulnerabilityRecord, TrivyEvidenceLevel
from core.trivy.analyzer import TrivyNormalizer, DuplicateDetector, EvidenceReviewer
from core.trivy.context import ContextEnricher, AdaptiveAdvisor


TRIVY_SAMPLE = json.dumps({
    "VulnerabilityID": "CVE-2021-44228",
    "PkgName": "log4j-core",
    "InstalledVersion": "2.14.1",
    "FixedVersion": "2.17.0",
    "Severity": "CRITICAL",
    "Title": "Log4Shell",
}, ensure_ascii=False)


def test_normalizer():
    norm = TrivyNormalizer()
    rec = norm.normalize_trivy_json_line(TRIVY_SAMPLE)
    assert rec is not None
    assert rec.vulnerability_id == "CVE-2021-44228"
    assert rec.package_name == "log4j-core"
    assert rec.installed_version == "2.14.1"
    assert rec.fixed_version == "2.17.0"
    assert rec.severity == "CRITICAL"
    assert rec.evidence_level == TrivyEvidenceLevel.E0
    print("[PASS] trivy normalizer")


def test_duplicate_detector():
    norm = TrivyNormalizer()
    dedup = DuplicateDetector()

    rec = norm.normalize_trivy_json_line(TRIVY_SAMPLE)
    g1 = dedup.add(rec)
    assert g1 is False
    g2 = dedup.add(rec)
    assert g2 is True
    count = dedup.flush()
    assert count == 1
    print("[PASS] trivy duplicate detector")


def test_evidence_reviewer():
    norm = TrivyNormalizer()
    reviewer = EvidenceReviewer()

    rec = norm.normalize_trivy_json_line(TRIVY_SAMPLE)
    report = reviewer.review(rec)

    assert report["evidence_status"] == "sufficient"
    assert rec.evidence_level == TrivyEvidenceLevel.E1
    print("[PASS] trivy evidence reviewer")


def test_context_enricher():
    enricher = ContextEnricher()
    rec = TrivyVulnerabilityRecord(
        record_id="tr1",
        vulnerability_id="CVE-2021-44228",
        package_name="log4j-core",
        installed_version="2.14.1",
        fixed_version="2.17.0",
        severity="CRITICAL",
        title="Log4Shell",
        evidence_level=TrivyEvidenceLevel.E0,
    )
    ctx = enricher.enrich(rec)
    assert ctx["is_critical_severity"] is True
    assert ctx["has_fix"] is True
    assert ctx["is_exploitable"] is True
    print("[PASS] trivy context enricher")


def test_adaptive_advisor():
    advisor = AdaptiveAdvisor()
    rec = TrivyVulnerabilityRecord(
        record_id="tr2",
        vulnerability_id="CVE-2021-44228",
        package_name="log4j-core",
        installed_version="2.14.1",
        fixed_version="2.17.0",
        severity="CRITICAL",
        title="Log4Shell",
        evidence_level=TrivyEvidenceLevel.E0,
    )
    advice = advisor.advise(rec, {"is_critical_severity": True, "has_fix": True, "is_exploitable": True})
    assert "trivy --severity CRITICAL,HIGH" in advice
    assert "مراقبة الاستغلال النشط عبر CISA KEV" in advice
    assert len(advice) <= 8
    print("[PASS] trivy adaptive advisor")


if __name__ == "__main__":
    test_normalizer()
    test_duplicate_detector()
    test_evidence_reviewer()
    test_context_enricher()
    test_adaptive_advisor()
    print("\n[INFO] جميع اختبارات Trivy Pilot نجحت!")
