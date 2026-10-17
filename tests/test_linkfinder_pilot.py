"""Tests لـ LinkFinder JS Endpoints Pilot — L1→L5"""
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.linkfinder.schemas import (
    JSFindingRecord, JSEndpointProfile,
    LinkFinderEvidenceLevel,
)
from core.linkfinder.analyzer import (
    LinkFinderNormalizer, DuplicateDetector, EvidenceReviewer,
)
from core.linkfinder.context import ContextEnricher, AdaptiveTestAdvisor


LINKFINDER_SAMPLE = json.dumps({
    "endpoint": "/api/users/login",
    "source_file": "app.js",
    "line_number": 42,
    "method": "POST",
    "parameter": "username",
    "code_snippet": "fetch('/api/users/login', { method: 'POST', body: JSON.stringify({username, password}) })",
}, ensure_ascii=False)


def test_normalizer():
    norm = LinkFinderNormalizer()
    rec = norm.normalize_linkfinder_json_line(LINKFINDER_SAMPLE)
    assert rec is not None
    assert rec.endpoint == "/api/users/login"
    assert rec.source_file == "app.js"
    assert rec.line_number == 42
    assert rec.method == "POST"
    assert rec.parameter == "username"
    assert rec.evidence_level == LinkFinderEvidenceLevel.E0
    print("[PASS] linkfinder normalizer")


def test_duplicate_detector():
    norm = LinkFinderNormalizer()
    dedup = DuplicateDetector()

    r1 = norm.normalize_linkfinder_json_line(LINKFINDER_SAMPLE)  # السجل الأول
    r2 = norm.normalize_linkfinder_json_line(LINKFINDER_SAMPLE)  # نفس السجل → تكرار

    g1 = dedup.add(r1)
    assert g1 is None  # أصل جديد

    g2 = dedup.add(r2)
    assert g2 is not None  # تكرار

    groups = dedup.flush()
    assert len(groups) == 1
    assert len(groups["/api/users/login:app.js:42"]) == 2
    print("[PASS] linkfinder duplicate detector")


def test_evidence_reviewer():
    norm = LinkFinderNormalizer()
    reviewer = EvidenceReviewer()

    rec = norm.normalize_linkfinder_json_line(LINKFINDER_SAMPLE)
    report = reviewer.review(rec)

    # فيه endpoint + source_file + code_snippet → sufficient → E1
    assert report["evidence_status"] == "sufficient"
    assert report["needs_verification"] is False
    assert rec.evidence_level == LinkFinderEvidenceLevel.E1  # تمت ترقيتها

    print("[PASS] linkfinder evidence reviewer")


def test_context_enricher():
    enricher = ContextEnricher(
        katana_endpoints=["https://target.local/api/users/login"],
        httpx_results={"target.local": ["http://target.local/"]},
    )
    rec = JSFindingRecord(
        record_id="js1",
        endpoint="/api/users/login",
        source_file="app.js",
        line_number=42,
        method="POST",
        parameter="username",
        code_snippet="fetch('/api/users/login', ...)",
        evidence_level=LinkFinderEvidenceLevel.E0,
    )
    ctx = enricher.enrich(rec)
    assert ctx["auth_sensitive"] is True
    assert ctx["service_category"] == "authentication"
    print("[PASS] linkfinder context enricher")


def test_adaptive_advisor():
    advisor = AdaptiveTestAdvisor()
    rec = JSFindingRecord(
        record_id="js2",
        endpoint="/api/users/login",
        source_file="app.js",
        line_number=42,
        method="POST",
        parameter="username",
        code_snippet="fetch('/api/users/login', ...)",
        evidence_level=LinkFinderEvidenceLevel.E0,
    )
    advice = advisor.advise(rec, {"auth_sensitive": True})
    assert "nuclei -t http/default-credentials" in advice
    assert "ffuf" in advice
    assert len(advice) <= 8
    print("[PASS] linkfinder adaptive advisor")


def test_js_endpoint_profile():
    profile = JSEndpointProfile(
        endpoint="/api/users/login",
        source_file="app.js",
        line_number=42,
        method="POST",
        parameter="username",
        code_snippet="fetch('/api/users/login', ...)",
        confidence_score=0.78,
        confidence_label="strong",
        evidence_level=LinkFinderEvidenceLevel.E1,
        is_auth_endpoint=True,
    )
    d = profile.to_dict()
    assert d["confidence_label"] == "strong"
    assert d["evidence_level"] == "E1"
    assert d["is_auth_endpoint"] is True
    print("[PASS] linkfinder endpoint profile")


if __name__ == "__main__":
    test_normalizer()
    test_duplicate_detector()
    test_evidence_reviewer()
    test_context_enricher()
    test_adaptive_advisor()
    test_js_endpoint_profile()
    print("\n[INFO] جميع اختبارات LinkFinder Pilot نجحت!")
