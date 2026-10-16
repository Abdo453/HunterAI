"""Tests لـ Subfinder Asset Coverage Pilot — L1→L5"""
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.subfinder.schemas import (
    SubfinderAssetRecord, SubfinderEvidenceLevel, SourceType,
)
from core.subfinder.analyzer import SubfinderNormalizer, DuplicateDetector, EvidenceReviewer
from core.subfinder.context import ContextEnricher, AdaptiveAdvisor


SUBFINDER_SAMPLE = json.dumps({
    "host": "dev.target.local",
    "source": "crt.sh",
    "source-type": "certificate",
    "ip": "203.0.113.10",
    "cdn": False,
}, ensure_ascii=False)

SUBFINDER_SAMPLE2 = json.dumps({
    "host": "dev.target.local",
    "source": "virustotal",
    "source-type": "dns",
    "ip": "203.0.113.10",
    "cdn": True,
}, ensure_ascii=False)

SUBFINDER_SAMPLE3 = json.dumps({
    "host": "admin.target.local",
    "source": "unknown",
    "source-type": "passive",
}, ensure_ascii=False)


def test_normalizer():
    norm = SubfinderNormalizer()
    rec = norm.normalize_subfinder_json_line(SUBFINDER_SAMPLE)
    assert rec is not None
    assert rec.subdomain == "dev.target.local"
    assert rec.source == "crt.sh"
    assert rec.source_type == SourceType.CERTIFICATE
    assert rec.ip == "203.0.113.10"
    assert rec.evidence_level == SubfinderEvidenceLevel.E0
    print("[PASS] subfinder normalizer")


def test_duplicate_detector():
    norm = SubfinderNormalizer()
    dedup = DuplicateDetector()

    r1 = norm.normalize_subfinder_json_line(SUBFINDER_SAMPLE)
    r2 = norm.normalize_subfinder_json_line(SUBFINDER_SAMPLE2)  # تكرار نفس النطاق الفرعي

    g1 = dedup.add(r1)
    assert g1 is None

    g2 = dedup.add(r2)
    assert g2 is not None

    groups = dedup.flush()
    assert len(groups) == 1
    assert len(groups["dev.target.local"]) == 2
    print("[PASS] subfinder duplicate detector")


def test_evidence_reviewer():
    norm = SubfinderNormalizer()
    reviewer = EvidenceReviewer()

    rec = norm.normalize_subfinder_json_line(SUBFINDER_SAMPLE)
    report = reviewer.review(rec)

    # مصدر معروف + شهادة + IP → sufficient → E1
    assert report["evidence_status"] == "sufficient"
    assert report["needs_verification"] is False
    assert rec.evidence_level == SubfinderEvidenceLevel.E1

    # نطاق فرعي عالي القيمة (admin)
    rec_admin = norm.normalize_subfinder_json_line(SUBFINDER_SAMPLE3)
    report_admin = reviewer.review(rec_admin)
    assert report_admin["confidence_label"] != "weak" or report_admin["issues"]
    print("[PASS] subfinder evidence reviewer")


def test_context_enricher():
    enricher = ContextEnricher(
        httpx_results={"dev.target.local": ["http://dev.target.local/"]},
        nmap_ports={"dev.target.local": [80, 443]},
    )
    rec = SubfinderAssetRecord(
        record_id="sf1",
        subdomain="dev.target.local",
        source="crt.sh",
        source_type=SourceType.CERTIFICATE,
        ip="203.0.113.10",
        evidence_level=SubfinderEvidenceLevel.E0,
    )
    ctx = enricher.enrich(rec)
    assert ctx["is_live_web"] is True
    assert ctx["open_ports"] == [80, 443]
    assert "http://dev.target.local/" in ctx["related_urls"]

    rec_admin = SubfinderAssetRecord(
        record_id="sf2",
        subdomain="admin.target.local",
        source="crt.sh",
        source_type=SourceType.CERTIFICATE,
        evidence_level=SubfinderEvidenceLevel.E0,
    )
    ctx_admin = enricher.enrich(rec_admin)
    assert ctx_admin["is_high_value"] is True
    print("[PASS] subfinder context enricher")


def test_adaptive_advisor():
    advisor = AdaptiveAdvisor()
    rec = SubfinderAssetRecord(
        record_id="sf3",
        subdomain="dev.target.local",
        source="crt.sh",
        source_type=SourceType.CERTIFICATE,
        evidence_level=SubfinderEvidenceLevel.E0,
    )
    advice = advisor.advise(rec, {"is_live_web": True, "open_ports": [80, 443], "is_high_value": True})
    assert "httpx" in advice
    assert "nuclei -t http/vuln" in advice
    assert "nmap -sV" in advice
    assert "ffuf" in advice
    assert len(advice) <= 8
    print("[PASS] subfinder adaptive advisor")


if __name__ == "__main__":
    test_normalizer()
    test_duplicate_detector()
    test_evidence_reviewer()
    test_context_enricher()
    test_adaptive_advisor()
    print("\n[INFO] جميع اختبارات Subfinder Pilot نجحت!")
