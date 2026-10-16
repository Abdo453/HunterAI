"""Tests لـ Nuclei Pilot — L1 Tool Adapter + L2-L5 Analyzer"""
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.nuclei.schemas import (
    NucleiFindingRecord, DuplicateGroup,
    NucleiEvidenceLevel, FindingStatus,
)
from core.nuclei.analyzer import FindingNormalizer, DuplicateDetector, EvidenceReviewer
from core.nuclei.context import ContextEnricher, AdaptiveTestAdvisor


# عينة من مخرجات nuclei (-json) — كل سطر JSON مستقل (NDJSON)
NUCLEI_SAMPLE = json.dumps({
    "template-id": "http-exposure-env",
    "info": {
        "name": "Environment File Exposure",
        "template_id": "http-exposure-env",
        "severity": "high",
        "description": "Environment file exposed"
    },
    "matcher-name": "env_file",
    "matched-at": "https://target.local/.env",
    "extracted-results": ["APP_KEY=", "DB_PASSWORD="],
    "request": "GET /.env HTTP/1.1",
    "response": "HTTP/1.1 200 OK\nAPP_KEY=base64:...\nDB_PASSWORD=secret",
}, ensure_ascii=False)

NUCLEI_SAMPLE2 = json.dumps({
    "template-id": "http-exposure-env",
    "info": {
        "name": "Environment File Exposure",
        "template_id": "http-exposure-env",
        "severity": "high",
    },
    "matcher-name": "env_file",
    "matched-at": "https://target.local/.env",  # نفسه → تكرار
    "extracted-results": [],
    "request": None,
    "response": None,
}, ensure_ascii=False)

NUCLEI_SAMPLE3 = json.dumps({
    "template-id": "http-missing-header-csp",
    "info": {
        "name": "Missing CSP Header",
        "template_id": "http-missing-header-csp",
        "severity": "low",
    },
    "matcher-name": "missing_header",
    "matched-at": "https://target.local/",
    "extracted-results": [],
    "request": "GET / HTTP/1.1",
    "response": "HTTP/1.1 200 OK\nContent-Type: text/html",
}, ensure_ascii=False)


def test_normalizer():
    norm = FindingNormalizer()
    rec = norm.normalize_nuclei_json_line(NUCLEI_SAMPLE)
    assert rec is not None
    assert rec.template_id == "http-exposure-env"
    assert rec.severity == "high"
    assert rec.matched_at == "https://target.local/.env"
    assert "APP_KEY=" in rec.extracted_results
    assert rec.evidence_level == NucleiEvidenceLevel.E0
    assert rec.status == FindingStatus.PENDING
    print("[PASS] nuclei normalizer")


def test_duplicate_detector():
    norm = FindingNormalizer()
    dedup = DuplicateDetector()

    r1 = norm.normalize_nuclei_json_line(NUCLEI_SAMPLE)
    r2 = norm.normalize_nuclei_json_line(NUCLEI_SAMPLE2)  # تكرار لنفس القالب+الرابط

    g1 = dedup.add(r1)
    assert g1 is None  # مجموعة جديدة
    assert r1.status == FindingStatus.PENDING

    g2 = dedup.add(r2)
    assert g2 is not None  # مجموعة تكرار
    assert r2.status == FindingStatus.DUPLICATE
    assert r2.duplicate_group == g2.group_id

    groups = dedup.flush()
    assert len(groups) == 1
    assert len(groups[0].members) == 2
    print("[PASS] nuclei duplicate detector")


def test_evidence_reviewer():
    norm = FindingNormalizer()
    reviewer = EvidenceReviewer(in_scope=True)

    rec = norm.normalize_nuclei_json_line(NUCLEI_SAMPLE)
    report = reviewer.review(rec)

    assert report["evidence_status"] == "sufficient"  # فيه request + response + in scope
    assert report["needs_verification"] is False
    assert report["scope_check"] == "passed"
    assert record_e1(rec)  # تم ترقيتها إلى E1

    # خارج النطاق → scope_check required
    reviewer_out = EvidenceReviewer(in_scope=False)
    rec2 = norm.normalize_nuclei_json_line(NUCLEI_SAMPLE3)
    report2 = reviewer_out.review(rec2)
    assert report2["scope_check"] == "required"

    print("[PASS] nuclei evidence reviewer")


def record_e1(rec: NucleiFindingRecord) -> bool:
    return rec.evidence_level == NucleiEvidenceLevel.E1


def test_context_enricher():
    enricher = ContextEnricher(
        katana_endpoints=["https://target.local/.env", "https://target.local/api/login"],
        detected_tech={"nginx", "php"},
    )
    rec = NucleiFindingRecord(
        record_id="test1",
        template_id="http-exposure-env",
        template_name="Env Exposure",
        severity="high",
        matcher_name="env_file",
        matched_at="https://target.local/.env",
        extracted_results=[],
        evidence_level=NucleiEvidenceLevel.E0,
    )
    ctx = enricher.enrich(rec)
    assert ctx["is_on_known_endpoint"] is True
    assert ctx["auth_sensitive"] is False
    assert "nginx" in ctx["related_tech"]

    # نقطة مصادقة
    rec2 = NucleiFindingRecord(
        record_id="test2",
        template_id="http-default-login",
        template_name="Default Login",
        severity="medium",
        matcher_name="default_creds",
        matched_at="https://target.local/api/login",
        extracted_results=[],
        evidence_level=NucleiEvidenceLevel.E0,
    )
    ctx2 = enricher.enrich(rec2)
    assert ctx2["auth_sensitive"] is True
    assert ctx2["endpoint_category"] == "authentication"

    print("[PASS] nuclei context enricher")


def test_adaptive_advisor():
    advisor = AdaptiveTestAdvisor()
    rec = NucleiFindingRecord(
        record_id="t",
        template_id="http-exposure-env",
        template_name="Environment File Exposure",
        severity="high",
        matcher_name="env_file",
        matched_at="https://target.local/.env",
        evidence_level=NucleiEvidenceLevel.E0,
    )
    advice = advisor.advise(rec, {"auth_sensitive": True, "related_tech": ["nginx"]})
    assert "http/apache" in advice or "http/nginx" in advice
    assert "http/default-credentials" in advice  # auth_sensitive
    assert len(advice) <= 8
    print("[PASS] nuclei adaptive advisor")


if __name__ == "__main__":
    test_normalizer()
    test_duplicate_detector()
    test_evidence_reviewer()
    test_context_enricher()
    test_adaptive_advisor()
    print("\n[INFO] جميع اختبارات Nuclei Pilot نجحت!")
