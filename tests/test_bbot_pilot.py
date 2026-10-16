"""Tests لـ BBOT Asset Relationship Analyzer Pilot — L1→L5"""
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.bbot.schemas import BBOTAssetRecord, BBOTEvidenceLevel
from core.bbot.analyzer import BBOTNormalizer, DuplicateDetector, EvidenceReviewer
from core.bbot.context import ContextEnricher, AdaptiveAdvisor


BBOT_SAMPLE = json.dumps({
    "type": "subdomain",
    "value": "dev.target.local",
    "module": "subfinder",
    "relationship": "resolves_to",
    "related_to": "203.0.113.10",
}, ensure_ascii=False)


def test_normalizer():
    norm = BBOTNormalizer()
    rec = norm.normalize_bbot_json_line(BBOT_SAMPLE)
    assert rec is not None
    assert rec.asset_type == "subdomain"
    assert rec.asset_value == "dev.target.local"
    assert rec.source_module == "subfinder"
    assert rec.evidence_level == BBOTEvidenceLevel.E0
    print("[PASS] bbot normalizer")


def test_duplicate_detector():
    norm = BBOTNormalizer()
    dedup = DuplicateDetector()

    rec = norm.normalize_bbot_json_line(BBOT_SAMPLE)
    g1 = dedup.add(rec)
    assert g1 is False
    g2 = dedup.add(rec)
    assert g2 is True
    count = dedup.flush()
    assert count == 1
    print("[PASS] bbot duplicate detector")


def test_evidence_reviewer():
    norm = BBOTNormalizer()
    reviewer = EvidenceReviewer()

    rec = norm.normalize_bbot_json_line(BBOT_SAMPLE)
    report = reviewer.review(rec)

    assert report["evidence_status"] == "sufficient"
    assert rec.evidence_level == BBOTEvidenceLevel.E1
    print("[PASS] bbot evidence reviewer")


def test_context_enricher():
    enricher = ContextEnricher()
    rec = BBOTAssetRecord(
        record_id="bb1",
        asset_type="subdomain",
        asset_value="dev.target.local",
        source_module="subfinder",
        relationship="resolves_to",
        related_asset="203.0.113.10",
        evidence_level=BBOTEvidenceLevel.E0,
    )
    ctx = enricher.enrich(rec)
    assert ctx["is_infrastructure"] is True
    assert ctx["is_domain"] is True
    print("[PASS] bbot context enricher")


def test_adaptive_advisor():
    advisor = AdaptiveAdvisor()
    rec = BBOTAssetRecord(
        record_id="bb2",
        asset_type="subdomain",
        asset_value="dev.target.local",
        source_module="subfinder",
        evidence_level=BBOTEvidenceLevel.E0,
    )
    advice = advisor.advise(rec, {"is_domain": True, "is_infrastructure": True})
    assert "subfinder" in advice
    assert "httpx" in advice
    assert len(advice) <= 8
    print("[PASS] bbot adaptive advisor")


if __name__ == "__main__":
    test_normalizer()
    test_duplicate_detector()
    test_evidence_reviewer()
    test_context_enricher()
    test_adaptive_advisor()
    print("\n[INFO] جميع اختبارات BBOT Pilot نجحت!")
