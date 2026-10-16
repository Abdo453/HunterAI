"""Tests لـ Katana Endpoint Intelligence Pilot — L1→L5"""
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.katana.schemas import (
    KatanaEndpointRecord, EndpointProfile,
    KatanaEvidenceLevel, EndpointCategory,
)
from core.katana.analyzer import KatanaNormalizer, DuplicateDetector, EvidenceReviewer
from core.katana.context import ContextEnricher, AdaptiveTestAdvisor


# عينة من مخرجات Katana JSON
KATANA_SAMPLE = json.dumps({
    "url": "https://target.local/api/users",
    "method": "GET",
    "status_code": 200,
    "content_length": 1024,
    "content_type": "application/json",
}, ensure_ascii=False)

KATANA_SAMPLE_AUTH = json.dumps({
    "url": "https://target.local/login",
    "method": "POST",
    "status_code": 200,
    "content_length": 512,
    "content_type": "text/html",
}, ensure_ascii=False)

KATANA_SAMPLE_ADMIN = json.dumps({
    "url": "https://target.local/admin/dashboard",
    "method": "GET",
    "status_code": 200,
    "content_length": 2048,
    "content_type": "text/html",
}, ensure_ascii=False)

KATANA_SAMPLE_DUPLICATE = json.dumps({
    "url": "https://target.local/api/users",
    "method": "GET",
    "status_code": 200,
    "content_length": 1024,
    "content_type": "application/json",
}, ensure_ascii=False)


def test_normalizer():
    norm = KatanaNormalizer()
    rec = norm.normalize_katana_json_line(KATANA_SAMPLE)
    assert rec is not None
    assert rec.url == "https://target.local/api/users"
    assert rec.method == "GET"
    assert rec.status_code == 200
    assert rec.category == EndpointCategory.API
    assert rec.evidence_level == KatanaEvidenceLevel.E0
    print("[PASS] katana normalizer")


def test_normalizer_auth():
    norm = KatanaNormalizer()
    rec = norm.normalize_katana_json_line(KATANA_SAMPLE_AUTH)
    assert rec.category == EndpointCategory.AUTH
    assert rec.parameters == []  # no query params in /login

    rec2 = norm.normalize_katana_json_line(
        '{"url": "https://target.local/search?q=test&cat=books", "method": "GET", "status_code": 200, "content_length": 100, "content_type": "text/html"}'
    )
    assert rec2 is not None
    assert "q" in rec2.parameters
    assert "cat" in rec2.parameters
    print("[PASS] katana normalizer auth + params")


def test_duplicate_detector():
    norm = KatanaNormalizer()
    dedup = DuplicateDetector()

    r1 = norm.normalize_katana_json_line(KATANA_SAMPLE)
    r2 = norm.normalize_katana_json_line(KATANA_SAMPLE_DUPLICATE)  # نفس url+method → تكرار

    g1 = dedup.add(r1)
    assert g1 is None  # نقطة جديدة

    g2 = dedup.add(r2)
    assert g2 is not None  # تكرار

    groups = dedup.flush()
    assert len(groups) == 1
    assert len(groups["https://target.local/api/users:GET"]) == 2
    print("[PASS] katana duplicate detector")


def test_evidence_reviewer():
    norm = KatanaNormalizer()
    reviewer = EvidenceReviewer()

    rec = norm.normalize_katana_json_line(KATANA_SAMPLE)
    report = reviewer.review(rec)

    # فيه status_code + category conocida → sufficient
    assert report["evidence_status"] == "sufficient"
    assert report["needs_verification"] is False
    assert rec.evidence_level == KatanaEvidenceLevel.E1  # تمت ترقيتها

    # نقطة إدارة
    rec_admin = norm.normalize_katana_json_line(KATANA_SAMPLE_ADMIN)
    report_admin = reviewer.review(rec_admin)
    assert report_admin["is_admin_sensitive"] is True
    assert report_admin["confidence"] > 0.4

    print("[PASS] katana evidence reviewer")


def test_context_enricher():
    enricher = ContextEnricher(
        httpx_tech={"https://target.local/api/users": ["nginx", "PHP 7.4"]},
        existing_endpoints={"https://target.local/api/users"},
    )
    rec = KatanaEndpointRecord(
        record_id="kt1",
        url="https://target.local/api/users",
        method="GET",
        status_code=200,
        content_length=1000,
        content_type="application/json",
        category=EndpointCategory.API,
        evidence_level=KatanaEvidenceLevel.E0,
    )
    ctx = enricher.enrich(rec)
    assert ctx["is_new_endpoint"] is False
    assert ctx["api_sensitive"] is True
    assert "nginx" in ctx["related_tech"]
    assert ctx["service_category"] == "api"
    print("[PASS] katana context enricher")


def test_adaptive_advisor():
    advisor = AdaptiveTestAdvisor()
    rec = KatanaEndpointRecord(
        record_id="kt2",
        url="https://target.local/login",
        method="POST",
        status_code=200,
        content_length=500,
        content_type="text/html",
        category=EndpointCategory.AUTH,
        evidence_level=KatanaEvidenceLevel.E0,
    )
    advice = advisor.advise(rec, {"auth_sensitive": True})
    assert "nuclei -t http/default-credentials" in advice
    assert "ffuf" in advice
    assert len(advice) <= 8
    print("[PASS] katana adaptive advisor")


def test_endpoint_profile():
    profile = EndpointProfile(
        url="https://target.local/api/users",
        method="GET",
        category=EndpointCategory.API,
        confidence_score=0.78,
        confidence_label="strong",
        evidence_level=KatanaEvidenceLevel.E1,
        is_api=True,
    )
    d = profile.to_dict()
    assert d["confidence_label"] == "strong"
    assert d["evidence_level"] == "E1"
    assert d["is_api"] is True
    print("[PASS] katana endpoint profile")


if __name__ == "__main__":
    test_normalizer()
    test_normalizer_auth()
    test_duplicate_detector()
    test_evidence_reviewer()
    test_context_enricher()
    test_adaptive_advisor()
    test_endpoint_profile()
    print("\n[INFO] جميع اختبارات Katana Pilot نجحت!")
