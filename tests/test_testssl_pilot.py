"""Tests لـ testssl.sh TLS Configuration Intelligence Pilot — L1→L5"""
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.testssl.schemas import TestsslFindingRecord, TestsslEvidenceLevel
from core.testssl.analyzer import TestsslNormalizer, DuplicateDetector, EvidenceReviewer
from core.testssl.context import ContextEnricher, AdaptiveAdvisor


TESTSSL_SAMPLE = json.dumps({
    "severity": "HIGH",
    "title": "Heartbleed",
    "description": "OpenSSL vulnerability CVE-2014-0160",
    "cve": "CVE-2014-0160",
}, ensure_ascii=False)


def test_normalizer():
    norm = TestsslNormalizer()
    rec = norm.normalize_testssl_json_line(TESTSSL_SAMPLE)
    assert rec is not None
    assert rec.severity == "HIGH"
    assert rec.title == "Heartbleed"
    assert rec.cve == "CVE-2014-0160"
    assert rec.evidence_level == TestsslEvidenceLevel.E0
    print("[PASS] testssl normalizer")


def test_duplicate_detector():
    norm = TestsslNormalizer()
    dedup = DuplicateDetector()

    rec = norm.normalize_testssl_json_line(TESTSSL_SAMPLE)
    g1 = dedup.add(rec)
    assert g1 is False
    g2 = dedup.add(rec)
    assert g2 is True
    count = dedup.flush()
    assert count == 1
    print("[PASS] testssl duplicate detector")


def test_evidence_reviewer():
    norm = TestsslNormalizer()
    reviewer = EvidenceReviewer()

    rec = norm.normalize_testssl_json_line(TESTSSL_SAMPLE)
    report = reviewer.review(rec)

    assert report["evidence_status"] == "sufficient"
    assert rec.evidence_level == TestsslEvidenceLevel.E1
    print("[PASS] testssl evidence reviewer")


def test_context_enricher():
    enricher = ContextEnricher()
    rec = TestsslFindingRecord(
        record_id="ts1",
        severity="CRITICAL",
        title="POODLE TLS",
        description="Protocol downgrade attack",
        evidence_level=TestsslEvidenceLevel.E0,
    )
    ctx = enricher.enrich(rec)
    assert ctx["is_critical"] is True
    assert ctx["is_protocol_issue"] is True
    print("[PASS] testssl context enricher")


def test_adaptive_advisor():
    advisor = AdaptiveAdvisor()
    rec = TestsslFindingRecord(
        record_id="ts2",
        severity="HIGH",
        title="Weak Cipher",
        description="Weak cipher suite detected",
        evidence_level=TestsslEvidenceLevel.E0,
    )
    advice = advisor.advise(rec, {"is_critical": True, "is_cipher_issue": True})
    assert "testssl.sh --severity CRITICAL" in advice
    assert "testssl.sh --cipher" in advice
    assert len(advice) <= 8
    print("[PASS] testssl adaptive advisor")


if __name__ == "__main__":
    test_normalizer()
    test_duplicate_detector()
    test_evidence_reviewer()
    test_context_enricher()
    test_adaptive_advisor()
    print("\n[INFO] جميع اختبارات testssl.sh Pilot نجحت!")
