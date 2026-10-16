"""Tests لـ Dalfox XSS Context Analyzer Pilot — L1→L5"""
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.dalfox.schemas import DalfoxFindingRecord, DalfoxEvidenceLevel
from core.dalfox.analyzer import DalfoxNormalizer, DuplicateDetector, EvidenceReviewer
from core.dalfox.context import ContextEnricher, AdaptiveAdvisor


DALFOX_SAMPLE = json.dumps({
    "url": "https://target.local/search?q=test",
    "injection_point": "query_parameter",
    "payload": "<script>alert(1)</script>",
    "type": "reflected",
    "evidence": "<script>alert(1)</script> reflected in response",
}, ensure_ascii=False)


def test_normalizer():
    norm = DalfoxNormalizer()
    rec = norm.normalize_dalfox_json_line(DALFOX_SAMPLE)
    assert rec is not None
    assert rec.url == "https://target.local/search?q=test"
    assert rec.injection_point == "query_parameter"
    assert rec.type == "reflected"
    assert rec.evidence_level == DalfoxEvidenceLevel.E0
    print("[PASS] dalfox normalizer")


def test_duplicate_detector():
    norm = DalfoxNormalizer()
    dedup = DuplicateDetector()

    rec = norm.normalize_dalfox_json_line(DALFOX_SAMPLE)
    g1 = dedup.add(rec)
    assert g1 is False
    g2 = dedup.add(rec)
    assert g2 is True
    count = dedup.flush()
    assert count == 1
    print("[PASS] dalfox duplicate detector")


def test_evidence_reviewer():
    norm = DalfoxNormalizer()
    reviewer = EvidenceReviewer()

    rec = norm.normalize_dalfox_json_line(DALFOX_SAMPLE)
    report = reviewer.review(rec)

    assert report["evidence_status"] == "sufficient"
    assert rec.evidence_level == DalfoxEvidenceLevel.E1
    print("[PASS] dalfox evidence reviewer")


def test_context_enricher():
    enricher = ContextEnricher()
    rec = DalfoxFindingRecord(
        record_id="dl1",
        url="https://target.local/search?q=test",
        injection_point="query_parameter",
        payload="<script>alert(1)</script>",
        type="reflected",
        evidence="reflected",
        evidence_level=DalfoxEvidenceLevel.E0,
    )
    ctx = enricher.enrich(rec)
    assert ctx["is_reflected"] is True
    assert ctx["injection_context"] == "parameter"
    print("[PASS] dalfox context enricher")


def test_adaptive_advisor():
    advisor = AdaptiveAdvisor()
    rec = DalfoxFindingRecord(
        record_id="dl2",
        url="https://target.local/search",
        injection_point="query_parameter",
        payload="<script>alert(1)</script>",
        type="reflected",
        evidence="reflected",
        evidence_level=DalfoxEvidenceLevel.E0,
    )
    advice = advisor.advise(rec, {"is_reflected": True, "injection_context": "parameter"})
    assert "dalfox --level 3" in advice
    assert "dalfox --method GET" in advice
    assert len(advice) <= 8
    print("[PASS] dalfox adaptive advisor")


if __name__ == "__main__":
    test_normalizer()
    test_duplicate_detector()
    test_evidence_reviewer()
    test_context_enricher()
    test_adaptive_advisor()
    print("\n[INFO] جميع اختبارات Dalfox Pilot نجحت!")
