"""Tests لـ Soft-404 Detector Pilot — L1→L5"""
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.soft_404.schemas import (
    Soft404Record, Soft404Profile,
    Soft404EvidenceLevel,
)
from core.soft_404.analyzer import (
    Soft404Normalizer, DuplicateDetector, EvidenceReviewer,
)
from core.soft_404.context import ContextEnricher, AdaptiveTestAdvisor


SOFT404_SAMPLE = json.dumps({
    "url": "https://example.com/products/nonexistent",
    "status_code": 200,
    "content_length": 1500,
    "content_type": "text/html",
    "title": "Product Not Found",
    "is_soft_404": True,
    "similarity_score": 0.85,
}, ensure_ascii=False)


def test_normalizer():
    norm = Soft404Normalizer()
    rec = norm.normalize_soft_404_line(SOFT404_SAMPLE)
    assert rec is not None
    assert rec.url == "https://example.com/products/nonexistent"
    assert rec.status_code == 200
    assert rec.content_length == 1500
    assert rec.content_type == "text/html"
    assert rec.title == "Product Not Found"
    assert rec.is_soft_404 is True
    assert rec.similarity_score == 0.85
    assert rec.evidence_level == Soft404EvidenceLevel.E0
    print("[PASS] soft-404 normalizer")


def test_duplicate_detector():
    norm = Soft404Normalizer()
    dedup = DuplicateDetector()

    r1 = norm.normalize_soft_404_line(SOFT404_SAMPLE)
    r2 = norm.normalize_soft_404_line(SOFT404_SAMPLE)  # نفس الرابط → تكرار

    g1 = dedup.add(r1)
    assert g1 is None  # أصل جديد

    g2 = dedup.add(r2)
    assert g2 is not None  # تكرار

    groups = dedup.flush()
    assert len(groups) == 1
    assert len(groups["https://example.com/products/nonexistent"]) == 2
    print("[PASS] soft-404 duplicate detector")


def test_evidence_reviewer():
    norm = Soft404Normalizer()
    reviewer = EvidenceReviewer()

    rec = norm.normalize_soft_404_line(SOFT404_SAMPLE)
    report = reviewer.review(rec)

    # فيه status_code + content_length + title + is_soft_404 → sufficient → E1
    assert report["evidence_status"] == "sufficient"
    assert report["needs_verification"] is False
    assert rec.evidence_level == Soft404EvidenceLevel.E1  # تمت ترقيتها
    assert report["is_true_soft_404"] is True

    print("[PASS] soft-404 evidence reviewer")


def test_context_enricher():
    enricher = ContextEnricher(
        katana_endpoints=["https://example.com/products/nonexistent"],
        httpx_results={"https://example.com/products/nonexistent": ["https://example.com/products/"]},
    )
    rec = Soft404Record(
        record_id="s404_1",
        url="https://example.com/products/nonexistent",
        status_code=200,
        content_length=1500,
        content_type="text/html",
        title="Admin Panel Not Found",
        is_soft_404=True,
        similarity_score=0.85,
        evidence_level=Soft404EvidenceLevel.E0,
    )
    ctx = enricher.enrich(rec)
    assert ctx["is_admin_page"] is True
    assert ctx["service_category"] == "administration"
    assert len(ctx["related_urls"]) == 1
    print("[PASS] soft-404 context enricher")


def test_adaptive_advisor():
    advisor = AdaptiveTestAdvisor()
    rec = Soft404Record(
        record_id="s404_2",
        url="https://example.com/admin/nonexistent",
        status_code=200,
        content_length=1500,
        content_type="text/html",
        title="Admin Page Not Found",
        is_soft_404=True,
        similarity_score=0.85,
        evidence_level=Soft404EvidenceLevel.E0,
    )
    advice = advisor.advise(rec, {"is_admin_page": True})
    assert "nuclei -t http/exposed-panels" in advice
    assert "ffuf" in advice
    assert len(advice) <= 8
    print("[PASS] soft-404 adaptive advisor")


def test_soft_404_profile():
    profile = Soft404Profile(
        url="https://example.com/products/nonexistent",
        status_code=200,
        content_length=1500,
        content_type="text/html",
        title="Product Not Found",
        is_soft_404=True,
        similarity_score=0.85,
        confidence_score=0.78,
        confidence_label="strong",
        evidence_level=Soft404EvidenceLevel.E1,
    )
    d = profile.to_dict()
    assert d["confidence_label"] == "strong"
    assert d["evidence_level"] == "E1"
    assert d["is_soft_404"] is True
    print("[PASS] soft-404 profile")


if __name__ == "__main__":
    test_normalizer()
    test_duplicate_detector()
    test_evidence_reviewer()
    test_context_enricher()
    test_adaptive_advisor()
    test_soft_404_profile()
    print("\n[INFO] جميع اختبارات Soft-404 Pilot نجحت!")
