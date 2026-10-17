"""Tests لـ WhatWeb Technology Fingerprinting Pilot — L1→L5"""
import json

from core.whatweb.schemas import (
    WhatWebAssetRecord,
    WhatWebEvidenceLevel,
    WhatWebPluginRecord,
    TechFingerprintProfile,
)
from core.whatweb.analyzer import DuplicateDetector, EvidenceReviewer, WhatWebNormalizer
from core.whatweb.context import AdaptiveTestAdvisor, ContextEnricher

WHATWEB_SAMPLE = json.dumps(
    {
        "target": "http://example.com",
        "timestamp": "2021-01-01T00:00:00Z",
        "http_status": 200,
        "server": "nginx/1.18.0",
        "plugins": {
            "Title": {"name": "Title", "version": ["Example Domain"]},
            "HTTPServer": {"name": "nginx", "version": ["1.18.0"]},
            "PHP": {"name": "PHP", "version": ["8.0.1"]},
            "jQuery": {"name": "jQuery", "version": ["3.5.1"]},
        },
        "ip": "93.184.216.34",
    },
    ensure_ascii=False,
)

WHATWEB_ARRAY = json.dumps(
    [
        {
            "target": "http://example.com",
            "http_status": 200,
            "plugins": {"HTTPServer": {"name": "nginx"}},
        }
    ]
)


def test_normalizer_parses_sample():
    records = WhatWebNormalizer().normalize(WHATWEB_SAMPLE)
    assert len(records) == 1
    rec = records[0]
    assert rec.target == "http://example.com"
    assert rec.url == "http://example.com"
    assert rec.http_status == 200
    assert rec.server == "nginx/1.18.0"
    assert {p.name for p in rec.plugins} == {"Title", "nginx", "PHP", "jQuery"}
    php = [p for p in rec.plugins if p.name == "PHP"][0]
    assert php.version == "8.0.1"
    assert "PHP/8.0.1" in rec.technologies


def test_normalizer_parses_array_and_garbage():
    assert len(WhatWebNormalizer().normalize(WHATWEB_ARRAY)) == 1
    assert WhatWebNormalizer().normalize("") == []
    assert WhatWebNormalizer().normalize("not json") == []


def test_duplicate_detector_merges_targets():
    rec1 = WhatWebAssetRecord(
        target="http://example.com",
        url="http://example.com",
        plugins=[WhatWebPluginRecord(name="nginx")],
    )
    rec2 = WhatWebAssetRecord(
        target="http://example.com",
        url="http://example.com",
        plugins=[WhatWebPluginRecord(name="PHP")],
    )
    d = DuplicateDetector()
    d.add(rec1)
    d.add(rec2)
    merged = d.flush()
    assert len(merged) == 1
    assert {p.name for p in merged[0].plugins} == {"nginx", "PHP"}


def test_reviewer_promotes_on_status_and_plugins():
    rec = WhatWebNormalizer().normalize(WHATWEB_SAMPLE)[0]
    report = EvidenceReviewer().review(rec)
    assert report["evidence_status"] == "sufficient"
    assert rec.evidence_level == WhatWebEvidenceLevel.E1
    assert report["needs_verification"] is False
    assert report["confidence"] >= 0.7


def test_reviewer_stays_raw_without_data():
    rec = WhatWebAssetRecord(target="http://example.com", url="http://example.com")
    report = EvidenceReviewer().review(rec)
    assert report["evidence_status"] == "raw"
    assert rec.evidence_level == WhatWebEvidenceLevel.E0


def test_context_enricher_detects_cms_and_libraries():
    rec = WhatWebNormalizer().normalize(WHATWEB_SAMPLE)[0]
    ctx = ContextEnricher().enrich(rec)
    assert ctx["web_server"] == "nginx/1.18.0"
    assert "jquery" in ctx["javascript_libraries"]


def test_context_enricher_wordpress_cms():
    wp_sample = json.dumps(
        {
            "target": "http://blog.example.com",
            "http_status": 200,
            "plugins": {
                "WordPress": {"name": "WordPress", "version": ["6.0"]},
                "HTTPServer": {"name": "Apache"},
            },
        }
    )
    rec = WhatWebNormalizer().normalize(wp_sample)[0]
    ctx = ContextEnricher().enrich(rec)
    assert ctx["cms"] == "wordpress"
    assert ctx["is_cms"] is True


def test_adaptive_advisor_suggests_scans():
    rec = WhatWebNormalizer().normalize(WHATWEB_SAMPLE)[0]
    ctx = ContextEnricher().enrich(rec)
    advice = AdaptiveTestAdvisor().advise(rec, ctx)
    assert any("nuclei" in s for s in advice)
    assert len(advice) <= 8


def test_tech_fingerprint_profile_model():
    profile = TechFingerprintProfile(
        target="http://example.com",
        url="http://example.com",
        http_status=200,
        server="nginx",
        plugin_count=4,
        technology_count=4,
        cms_detected=False,
        web_server_detected=True,
        javascript_libraries=["jquery"],
        confidence_score=0.8,
        confidence_label="strong",
        evidence_level=WhatWebEvidenceLevel.E1,
    )
    d = profile.to_dict()
    assert d["cms_detected"] is False
    assert d["web_server_detected"] is True
    assert d["evidence_level"] == "E1"
