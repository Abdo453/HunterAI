"""Tests لـ Subfinder Asset Coverage Pilot — L1→L5"""
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.subfinder.schemas import (
    SubfinderAssetRecord, AssetCoverageProfile,
    SubfinderEvidenceLevel,
)
from core.subfinder.analyzer import (
    SubfinderNormalizer, DuplicateDetector, EvidenceReviewer,
)
from core.subfinder.context import ContextEnricher, AdaptiveTestAdvisor


SUBFINDER_SAMPLE = json.dumps({
    "subdomain": "dev.example.com",
    "source": "crt.sh",
    "ip": "203.0.113.10",
    "cdn": "cloudflare",
}, ensure_ascii=False)


def test_normalizer():
    norm = SubfinderNormalizer()
    rec = norm.normalize_subfinder_json_line(SUBFINDER_SAMPLE)
    assert rec is not None
    assert rec.subdomain == "dev.example.com"
    assert rec.source == "crt.sh"
    assert rec.ip == "203.0.113.10"
    assert rec.evidence_level == SubfinderEvidenceLevel.E0
    print("[PASS] subfinder normalizer")


def test_duplicate_detector():
    norm = SubfinderNormalizer()
    dedup = DuplicateDetector()

    rec = norm.normalize_subfinder_json_line(SUBFINDER_SAMPLE)
    r2 = norm.normalize_subfinder_json_line(SUBFINDER_SAMPLE)  # نفس النطاق الفرعي → تكرار

    g1 = dedup.add(r1) if (r1 := norm.normalize_subfinder_json_line(SUBFINDER_SAMPLE)) else None
    assert g1 is None  # أصل جديد

    g2 = dedup.add(r2)
    assert g2 is not None  # تكرار

    groups = dedup.flush()
    assert len(groups) == 1
    assert len(groups["dev.example.com"]) == 2
    print("[PASS] subfinder duplicate detector")


def test_evidence_reviewer():
    norm = SubfinderNormalizer()
    reviewer = EvidenceReviewer()

    rec = norm.normalize_subfinder_json_line(SUBFINDER_SAMPLE)
    report = reviewer.review(rec)

    # فيه source + ip → sufficient → E1
    assert report["evidence_status"] == "sufficient"
    assert rec.evidence_level == SubfinderEvidenceLevel.E1  # تمت ترقيتها
    print("[PASS] subfinder evidence reviewer")


def test_context_enricher():
    enricher = ContextEnricher(
        httpx_results={"dev.example.com": ["http://dev.example.com/"]},
        katana_endpoints=["https://dev.target.local/admin"],
    )
    rec = SubfinderAssetRecord(
        record_id="sf1",
        subdomain="dev.example.com",
        source="crt.sh",
        ip="203.0.113.10",
        cdn="cloudflare",
        evidence_level=SubfinderEvidenceLevel.E0,
    )
    ctx = enricher.enrich(rec)
    assert ctx["is_live_web"] is True
    assert len(ctx["related_urls"]) == 1
    print("[PASS] subfinder context enricher")


def test_adaptive_advisor():
    advisor = AdaptiveTestAdvisor()
    rec = SubfinderAssetRecord(
        record_id="sf2",
        subdomain="admin.example.com",
        source="crt.sh",
        ip="203.0.113.11",
        evidence_level=SubfinderEvidenceLevel.E0,
    )
    advice = advisor.advise(rec, {"is_administration": True})
    assert "ffuf" in advice
    assert len(advice) <= 8
    print("[PASS] subfinder adaptive advisor")


def test_asset_coverage_profile():
    profile = AssetCoverageProfile(
        subdomain="dev.example.com",
        source="crt.sh",
        ip="203.0.113.10",
        cdn="cloudflare",
        is_high_value=True,
        is_live_web=True,
        confidence_score=0.85,
        confidence_label="strong",
        evidence_level=SubfinderEvidenceLevel.E1,
    )
    d = profile.to_dict()
    assert d["confidence_label"] == "strong"
    assert d["evidence_level"] == "E1"
    assert d["is_high_value"] is True
    print("[PASS] asset coverage profile")


if __name__ == "__main__":
    test_normalizer()
    test_duplicate_detector()
    test_evidence_reviewer()
    test_context_enricher()
    test_adaptive_advisor()
    test_asset_coverage_profile()
    print("\n[INFO] جميع اختبارات Subfinder Pilot نجحت!")
