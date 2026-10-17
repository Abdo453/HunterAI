"""Tests لـ Subjack Subdomain Takeover Pilot — L1→L5"""
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.subjack.schemas import (
    SubdomainTakeoverRecord, TakeoverProfile,
    SubjackEvidenceLevel,
)
from core.subjack.analyzer import (
    SubjackNormalizer, DuplicateDetector, EvidenceReviewer,
)
from core.subjack.context import ContextEnricher, AdaptiveTestAdvisor


SUBJACK_SAMPLE = json.dumps({
    "subdomain": "dev.target.local",
    "cname": "dev.target.local.s3.amazonaws.com",
    "status_code": 404,
    "fingerprint": "AmazonS3",
    "takeover_risk": "high",
}, ensure_ascii=False)


def test_normalizer():
    norm = SubjackNormalizer()
    rec = norm.normalize_subjack_json_line(SUBJACK_SAMPLE)
    assert rec is not None
    assert rec.subdomain == "dev.target.local"
    assert rec.cname == "dev.target.local.s3.amazonaws.com"
    assert rec.status_code == 404
    assert rec.fingerprint == "AmazonS3"
    assert rec.takeover_risk == "high"
    assert rec.evidence_level == SubjackEvidenceLevel.E0
    print("[PASS] subjack normalizer")


def test_duplicate_detector():
    norm = SubjackNormalizer()
    dedup = DuplicateDetector()

    rec = norm.normalize_subjack_json_line(SUBJACK_SAMPLE)
    r2 = norm.normalize_subjack_json_line(SUBJACK_SAMPLE)  # نفس النطاق الفرعي → تكرار

    g1 = dedup.add(r1) if (r1 := norm.normalize_subjack_json_line(SUBJACK_SAMPLE)) else None
    assert g1 is None  # أصل جديد

    g2 = dedup.add(r2)
    assert g2 is not None  # تكرار

    groups = dedup.flush()
    assert len(groups) == 1
    assert len(groups["dev.target.local"]) == 2
    print("[PASS] subjack duplicate detector")


def test_evidence_reviewer():
    norm = SubjackNormalizer()
    reviewer = EvidenceReviewer()

    rec = norm.normalize_subjack_json_line(SUBJACK_SAMPLE)
    report = reviewer.review(rec)

    assert report["evidence_status"] == "sufficient"
    assert rec.evidence_level == SubjackEvidenceLevel.E1  # تمت ترقيتها
    assert report["is_vulnerable"] is True

    print("[PASS] subjack evidence reviewer")


def test_context_enricher():
    enricher = ContextEnricher(
        katana_endpoints=["https://dev.target.local/admin"],
        httpx_results={"dev.target.local": ["http://dev.target.local/"]},
    )
    rec = SubdomainTakeoverRecord(
        record_id="sj1",
        subdomain="admin.dev.target.local",
        cname="dev.target.local.s3.amazonaws.com",
        status_code=404,
        fingerprint="AmazonS3",
        takeover_risk="high",
        evidence_level=SubjackEvidenceLevel.E0,
    )
    ctx = enricher.enrich(rec)
    assert ctx["is_administration"] is True
    assert ctx["service_category"] == "administration"
    assert len(ctx["related_urls"]) == 1
    print("[PASS] subjack context enricher")


def test_adaptive_advisor():
    advisor = AdaptiveTestAdvisor()
    rec = SubdomainTakeoverRecord(
        record_id="sj2",
        subdomain="dev.target.local",
        cname="dev.target.local.s3.amazonaws.com",
        status_code=404,
        fingerprint="AmazonS3",
        takeover_risk="high",
        evidence_level=SubjackEvidenceLevel.E0,
    )
    advice = advisor.advise(rec, {"is_administration": True})
    assert "nuclei -t http/takeovers" in advice
    assert "ffuf -u http://<subdomain>/admin/FUZZ" in advice
    assert len(advice) <= 8
    print("[PASS] subjack adaptive advisor")


def test_takeover_profile():
    profile = TakeoverProfile(
        subdomain="dev.target.local",
        cname="dev.target.local.s3.amazonaws.com",
        status_code=404,
        fingerprint="AmazonS3",
        takeover_risk="high",
        confidence_score=0.85,
        confidence_label="strong",
        evidence_level=SubjackEvidenceLevel.E1,
        is_vulnerable=True,
    )
    d = profile.to_dict()
    assert d["confidence_label"] == "strong"
    assert d["evidence_level"] == "E1"
    assert d["is_vulnerable"] is True
    print("[PASS] subjack takeover profile")


if __name__ == "__main__":
    test_normalizer()
    test_duplicate_detector()
    test_evidence_reviewer()
    test_context_enricher()
    test_adaptive_advisor()
    test_takeover_profile()
    print("\n[INFO] جميع اختبارات Subjack Pilot نجحت!")
