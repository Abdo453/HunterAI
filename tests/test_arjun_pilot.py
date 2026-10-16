"""Tests لـ Arjun Parameter Intelligence Pilot — L1→L5"""
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.arjun.schemas import ArjunParameterRecord, ArjunEvidenceLevel
from core.arjun.analyzer import ArjunNormalizer, DuplicateDetector, EvidenceReviewer
from core.arjun.context import ContextEnricher, AdaptiveAdvisor


ARJUN_SAMPLE = json.dumps({
    "parameter": "id",
    "url": "https://target.local/product?id=1",
    "method": "GET",
}, ensure_ascii=False)


def test_normalizer():
    norm = ArjunNormalizer()
    rec = norm.normalize_arjun_json_line(ARJUN_SAMPLE)
    assert rec is not None
    assert rec.parameter == "id"
    assert rec.url == "https://target.local/product?id=1"
    assert rec.method == "GET"
    assert rec.evidence_level == ArjunEvidenceLevel.E0
    print("[PASS] arjun normalizer")


def test_duplicate_detector():
    norm = ArjunNormalizer()
    dedup = DuplicateDetector()

    rec = norm.normalize_arjun_json_line(ARJUN_SAMPLE)
    g1 = dedup.add(rec)
    assert g1 is False
    g2 = dedup.add(rec)
    assert g2 is True
    count = dedup.flush()
    assert count == 1
    print("[PASS] arjun duplicate detector")


def test_evidence_reviewer():
    norm = ArjunNormalizer()
    reviewer = EvidenceReviewer()

    rec = norm.normalize_arjun_json_line(ARJUN_SAMPLE)
    report = reviewer.review(rec)

    assert report["evidence_status"] == "sufficient"
    assert rec.evidence_level == ArjunEvidenceLevel.E1
    print("[PASS] arjun evidence reviewer")


def test_context_enricher():
    enricher = ContextEnricher()
    rec = ArjunParameterRecord(
        record_id="arj1",
        parameter="id",
        url="https://target.local/product?id=1",
        method="GET",
        evidence_level=ArjunEvidenceLevel.E0,
    )
    ctx = enricher.enrich(rec)
    assert ctx["is_id_parameter"] is True
    print("[PASS] arjun context enricher")


def test_adaptive_advisor():
    advisor = AdaptiveAdvisor()
    rec = ArjunParameterRecord(
        record_id="arj2",
        parameter="id",
        url="https://target.local/product?id=1",
        method="POST",
        evidence_level=ArjunEvidenceLevel.E0,
    )
    advice = advisor.advise(rec, {"is_id_parameter": True, "method_category": "mutating"})
    assert "nuclei -t http/idor" in advice
    assert "sqlmap --method POST" in advice
    assert len(advice) <= 8
    print("[PASS] arjun adaptive advisor")


if __name__ == "__main__":
    test_normalizer()
    test_duplicate_detector()
    test_evidence_reviewer()
    test_context_enricher()
    test_adaptive_advisor()
    print("\n[INFO] جميع اختبارات Arjun Pilot نجحت!")
