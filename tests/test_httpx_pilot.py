"""Tests لـ HTTPx Technology Profiler Pilot — L1→L5"""
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.httpx.schemas import (
    HTTPxAssetRecord, TechnologyProfile,
    HTTPxEvidenceLevel, AssetStatus,
)
from core.httpx.analyzer import HTTPxNormalizer, DuplicateDetector, EvidenceReviewer
from core.httpx.context import ContextEnricher, AdaptiveTestAdvisor


# عينة من مخرجات httpx (-json) — كل سطر JSON مستقل (NDJSON)
HTTPX_SAMPLE = json.dumps({
    "url": "https://target.local/",
    "host": "target.local",
    "port": 443,
    "scheme": "https",
    "status_code": 200,
    "content_length": 1234,
    "content_type": "text/html",
    "title": "Welcome to Target",
    "web_server": "nginx/1.18.0",
    "technology": ["PHP 7.4", "OpenSSL 1.1.1"],
    "cdn": None,
    "ip": "203.0.113.10",
    "cname": None,
}, ensure_ascii=False)

HTTPX_SAMPLE_WAF = json.dumps({
    "url": "https://target.local/admin",
    "host": "target.local",
    "port": 443,
    "scheme": "https",
    "status_code": 403,
    "content_length": 512,
    "content_type": "text/html",
    "title": "Forbidden",
    "web_server": "cloudflare",
    "technology": [],
    "cdn": "cloudflare",
    "ip": "104.16.0.0",
    "cname": None,
}, ensure_ascii=False)

HTTPX_SAMPLE_DUPLICATE = json.dumps({
    "url": "https://target.local/",
    "host": "target.local",
    "port": 443,
    "scheme": "https",
    "status_code": 200,
    "content_length": 1234,
    "content_type": "text/html",
    "title": "Welcome to Target",
    "web_server": "nginx/1.18.0",
    "technology": ["PHP 7.4"],
    "cdn": None,
    "ip": "203.0.113.10",
    "cname": None,
}, ensure_ascii=False)


def test_normalizer():
    norm = HTTPxNormalizer()
    rec = norm.normalize_httpx_json_line(HTTPX_SAMPLE)
    assert rec is not None
    assert rec.host == "target.local"
    assert rec.port == 443
    assert rec.scheme == "https"
    assert rec.status_code == 200
    assert rec.web_server == "nginx/1.18.0"
    assert "PHP 7.4" in rec.technologies
    assert rec.evidence_level == HTTPxEvidenceLevel.E0
    assert rec.status == AssetStatus.ALIVE
    print("[PASS] httpx normalizer")


def test_duplicate_detector():
    norm = HTTPxNormalizer()
    dedup = DuplicateDetector()

    r1 = norm.normalize_httpx_json_line(HTTPX_SAMPLE)
    r2 = norm.normalize_httpx_json_line(HTTPX_SAMPLE_DUPLICATE)  # نفسه host:port → تكرار

    g1 = dedup.add(r1)
    assert g1 is None  # أصل جديد

    g2 = dedup.add(r2)
    assert g2 is not None  # تكرار

    groups = dedup.flush()
    assert len(groups) == 1
    assert len(groups["target.local:443"]) == 2
    print("[PASS] httpx duplicate detector")


def test_evidence_reviewer():
    norm = HTTPxNormalizer()
    reviewer = EvidenceReviewer()

    rec = norm.normalize_httpx_json_line(HTTPX_SAMPLE)
    report = reviewer.review(rec)

    # فيه status_code + web_server + technologies → sufficient
    assert report["evidence_status"] == "sufficient"
    assert report["needs_verification"] is False
    assert report["confidence"] > 0.5
    assert rec.evidence_level == HTTPxEvidenceLevel.E1  # تمت ترقيتها

    # WAF case
    rec_waf = norm.normalize_httpx_json_line(HTTPX_SAMPLE_WAF)
    report_waf = reviewer.review(rec_waf)
    assert report_waf["is_likely_waf"] is True
    assert report_waf["is_likely_cdn"] is True

    print("[PASS] httpx evidence reviewer")


def test_context_enricher():
    enricher = ContextEnricher(
        dns_records={"target.local": ["203.0.113.10", "203.0.113.11"]},
        open_ports={"target.local": [80, 443, 8080]},
        katana_endpoints=["https://target.local/admin"],
    )
    rec = HTTPxAssetRecord(
        record_id="t1",
        url="https://target.local/admin",
        host="target.local",
        port=443,
        scheme="https",
        status_code=200,
        content_length=100,
        content_type="text/html",
        title="Admin Panel",
        web_server="nginx",
        technologies=["PHP 7.4"],
        evidence_level=HTTPxEvidenceLevel.E0,
    )
    ctx = enricher.enrich(rec)
    assert ctx["dns_info"] == ["203.0.113.10", "203.0.113.11"]
    assert ctx["open_ports_on_host"] == [80, 443, 8080]
    assert ctx["is_on_known_endpoint"] is True
    assert ctx["admin_sensitive"] is True
    assert ctx["service_category"] == "administration"
    print("[PASS] httpx context enricher")


def test_adaptive_advisor():
    advisor = AdaptiveTestAdvisor()
    rec = HTTPxAssetRecord(
        record_id="t2",
        url="https://target.local/",
        host="target.local",
        port=443,
        scheme="https",
        status_code=200,
        web_server="nginx",
        technologies=["PHP 7.4", "WordPress 6.0"],
        evidence_level=HTTPxEvidenceLevel.E0,
    )
    advice = advisor.advise(rec, {"service_category": "cms", "auth_sensitive": True})
    assert "wpscan" in advice or "http/wordpress" in advice
    assert "http/default-credentials" in advice  # auth_sensitive
    assert len(advice) <= 8
    print("[PASS] httpx adaptive advisor")


def test_technology_profile():
    profile = TechnologyProfile(
        host="target.local",
        url="https://target.local/",
        port=443,
        scheme="https",
        status_code=200,
        web_server="nginx",
        technologies=["PHP 7.4"],
        cdn=None,
        confidence_score=0.78,
        confidence_label="strong",
        evidence_level=HTTPxEvidenceLevel.E1,
    )
    d = profile.to_dict()
    assert d["confidence_label"] == "strong"
    assert d["evidence_level"] == "E1"
    print("[PASS] httpx technology profile")


if __name__ == "__main__":
    test_normalizer()
    test_duplicate_detector()
    test_evidence_reviewer()
    test_context_enricher()
    test_adaptive_advisor()
    test_technology_profile()
    print("\n[INFO] جميع اختبارات HTTPx Pilot نجحت!")
