"""Tests لـ ffuf Response Intelligence Pilot — L1→L5"""
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.ffuf.schemas import (
    FfufResultRecord, ResponseCluster,
    FfufEvidenceLevel, ResponseCategory,
)
from core.ffuf.analyzer import FfufNormalizer, DuplicateDetector, Soft404Detector, EvidenceReviewer
from core.ffuf.context import ContextEnricher, AdaptiveWordlistAdvisor


# عينة من مخرجات ffuf JSON
FFUF_SAMPLE = json.dumps({
    "results": [
        {
            "url": "https://target.local/admin",
            "method": "GET",
            "status": 200,
            "length": 1234,
            "words": 150,
            "lines": 25,
            "redirectlocation": "",
        },
        {
            "url": "https://target.local/.env",
            "method": "GET",
            "status": 200,
            "length": 512,
            "words": 20,
            "lines": 5,
            "redirectlocation": "",
        },
        {
            "url": "https://target.local/login",
            "method": "GET",
            "status": 302,
            "length": 0,
            "words": 0,
            "lines": 0,
            "redirectlocation": "https://target.local/auth",
        },
        {
            "url": "https://target.local/.env",
            "method": "GET",
            "status": 200,
            "length": 512,
            "words": 20,
            "lines": 5,
            "redirectlocation": "",
        },
    ],
}, ensure_ascii=False)


def test_normalizer():
    norm = FfufNormalizer()
    records = norm.normalize_batch(FFUF_SAMPLE)
    assert records is not None
    assert len(records) == 4  # 4 نتائج في العينة (بما في ذلك مكرر .env)
    # التحقق من السجل الأول
    rec = records[0]
    assert rec.status_code == 200
    assert rec.content_length == 1234
    assert rec.url == "https://target.local/admin"
    assert rec.evidence_level == FfufEvidenceLevel.E0
    print("[PASS] ffuf normalizer")


def test_duplicate_detector():
    norm = FfufNormalizer()
    dedup = DuplicateDetector()

    records = norm.normalize_batch(FFUF_SAMPLE)
    for rec in records:
        dedup.add(rec)

    groups = dedup.flush()
    # يجب أن نجد تكرار واحد على الأقل ( .env تكرر مرتين )
    assert len(groups) >= 1
    print("[PASS] ffuf duplicate detector")


def test_soft404_detector():
    norm = FfufNormalizer()
    detector = Soft404Detector()

    # نتائج معظمها بنفس الطول → Soft-404 suspected
    records = []
    for i in range(10):
        rec = FfufResultRecord(
            record_id=f"ff_test_{i}",
            url=f"https://target.local/page{i}",
            method="GET",
            status_code=200,
            content_length=1024,
            content_words=100,
            content_lines=10,
            evidence_level=FfufEvidenceLevel.E0,
        )
        records.append(rec)

    # نتيجة واحدة بطول مختلف
    rec_unique = FfufResultRecord(
        record_id="ff_test_unique",
        url="https://target.local/unique",
        method="GET",
        status_code=200,
        content_length=5000,
        content_words=500,
        content_lines=50,
        evidence_level=FfufEvidenceLevel.E0,
    )
    records.append(rec_unique)

    detected = detector.detect(records)
    soft404s = [r for r in detected if r.category == ResponseCategory.SOFT_404]
    # معظمها يجب أن تُصنف Soft-404
    assert len(soft404s) >= 8, f"Expected >=8 soft404s, got {len(soft404s)}"
    # النتيجة الفريدة لا يجب أن تُصنف Soft-404
    unique_rec = [r for r in detected if r.record_id == "ff_test_unique"][0]
    assert unique_rec.category != ResponseCategory.SOFT_404
    print("[PASS] ffuf soft-404 detector")


def test_evidence_reviewer():
    norm = FfufNormalizer()
    reviewer = EvidenceReviewer()

    records = norm.normalize_batch(FFUF_SAMPLE)
    rec = records[0]  # admin 200
    report = reviewer.review(rec)

    assert report["is_interesting"] is True
    assert report["needs_verification"] is False  # E1
    assert rec.evidence_level == FfufEvidenceLevel.E1

    # نتيجة Soft-404
    rec_soft = FfufResultRecord(
        record_id="ff_soft",
        url="https://target.local/page",
        method="GET",
        status_code=200,
        content_length=1024,
        content_words=100,
        content_lines=10,
        category=ResponseCategory.SOFT_404,
        evidence_level=FfufEvidenceLevel.E0,
    )
    report_soft = reviewer.review(rec_soft)
    assert report_soft["needs_verification"] is True
    assert "Soft-404" in " ".join(report_soft["issues"])

    print("[PASS] ffuf evidence reviewer")


def test_context_enricher():
    enricher = ContextEnricher(
        katana_endpoints=["https://target.local/admin"],
    )
    rec = FfufResultRecord(
        record_id="ff_ctx",
        url="https://target.local/admin/config",
        method="GET",
        status_code=200,
        content_length=500,
        content_words=50,
        content_lines=5,
        evidence_level=FfufEvidenceLevel.E0,
    )
    ctx = enricher.enrich(rec)
    assert ctx["admin_sensitive"] is True
    assert ctx["path_category"] == "administration"
    assert ctx["is_on_known_endpoint"] is True
    print("[PASS] ffuf context enricher")


def test_adaptive_wordlist_advisor():
    advisor = AdaptiveWordlistAdvisor()
    rec = FfufResultRecord(
        record_id="ff_adv",
        url="https://target.local/admin",
        method="GET",
        status_code=200,
        content_length=1000,
        content_words=100,
        content_lines=10,
        evidence_level=FfufEvidenceLevel.E0,
    )
    advice = advisor.advise(rec, {"path_category": "administration"})
    assert "admin" in advice or "administrator" in advice
    assert "dashboard" in advice
    assert len(advice) <= 10
    print("[PASS] ffuf adaptive wordlist advisor")


def test_response_category():
    # اختبار أن الفئات تعمل بشكل صحيح
    assert ResponseCategory.SOFT_404 == "soft_404"
    assert ResponseCategory.AUTH_REQUIRED == "auth_required"
    assert ResponseCategory.NORMAL == "normal"
    print("[PASS] ffuf response categories")


if __name__ == "__main__":
    test_normalizer()
    test_duplicate_detector()
    test_soft404_detector()
    test_evidence_reviewer()
    test_context_enricher()
    test_adaptive_wordlist_advisor()
    test_response_category()
    print("\n[INFO] جميع اختبارات ffuf Pilot نجحت!")
