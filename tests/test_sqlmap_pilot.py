"""Tests لـ SQLmap Result Interpreter Pilot — L1→L5"""
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.sqlmap.schemas import SQLmapFindingRecord, SQLmapEvidenceLevel
from core.sqlmap.analyzer import SQLmapNormalizer, DuplicateDetector, EvidenceReviewer
from core.sqlmap.context import ContextEnricher, AdaptiveAdvisor


SQLMAP_SAMPLE = json.dumps({
    "parameter": "id",
    "payload": "1' OR '1'='1",
    "technique": "boolean-based",
    "dbms": "MySQL",
    "evidence": "SQL syntax error",
}, ensure_ascii=False)

SQLMAP_SAMPLE2 = json.dumps({
    "parameter": "id",
    "payload": "1' OR '1'='1",
    "technique": "boolean-based",
    "dbms": "MySQL",
}, ensure_ascii=False)


def test_normalizer():
    norm = SQLmapNormalizer()
    rec = norm.normalize_sqlmap_json_line(SQLMAP_SAMPLE)
    assert rec is not None
    assert rec.parameter == "id"
    assert rec.technique == "boolean-based"
    assert rec.dbms == "MySQL"
    assert rec.evidence_level == SQLmapEvidenceLevel.E0
    print("[PASS] sqlmap normalizer")


def test_duplicate_detector():
    norm = SQLmapNormalizer()
    dedup = DuplicateDetector()

    r1 = norm.normalize_sqlmap_json_line(SQLMAP_SAMPLE)
    r2 = norm.normalize_sqlmap_json_line(SQLMAP_SAMPLE2)  # نفس المعلمة والتقنية

    g1 = dedup.add(r1)
    assert g1 is False

    g2 = dedup.add(r2)
    assert g2 is True

    count = dedup.flush()
    assert count == 1
    print("[PASS] sqlmap duplicate detector")


def test_evidence_reviewer():
    norm = SQLmapNormalizer()
    reviewer = EvidenceReviewer()

    rec = norm.normalize_sqlmap_json_line(SQLMAP_SAMPLE)
    report = reviewer.review(rec)

    assert report["evidence_status"] == "sufficient"
    assert report["needs_verification"] is False
    assert rec.evidence_level == SQLmapEvidenceLevel.E1
    print("[PASS] sqlmap evidence reviewer")


def test_context_enricher():
    enricher = ContextEnricher()
    rec = SQLmapFindingRecord(
        record_id="sq1",
        parameter="id",
        payload="1' OR '1'='1",
        technique="boolean-based",
        dbms="MySQL",
        evidence="SQL syntax error",
        evidence_level=SQLmapEvidenceLevel.E0,
    )
    ctx = enricher.enrich(rec)
    assert ctx["is_id_parameter"] is True
    assert ctx["dbms_family"] == "mysql"
    print("[PASS] sqlmap context enricher")


def test_adaptive_advisor():
    advisor = AdaptiveAdvisor()
    rec = SQLmapFindingRecord(
        record_id="sq2",
        parameter="id",
        payload="1' OR '1'='1",
        technique="boolean-based",
        dbms="MySQL",
        evidence="SQL syntax error",
        evidence_level=SQLmapEvidenceLevel.E0,
    )
    advice = advisor.advise(rec, {"is_id_parameter": True, "dbms_family": "mysql"})
    assert "sqlmap --technique U" in advice
    assert "sqlmap --dbms=mysql" in advice
    assert len(advice) <= 8
    print("[PASS] sqlmap adaptive advisor")


if __name__ == "__main__":
    test_normalizer()
    test_duplicate_detector()
    test_evidence_reviewer()
    test_context_enricher()
    test_adaptive_advisor()
    print("\n[INFO] جميع اختبارات SQLmap Pilot نجحت!")
