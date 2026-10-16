"""Tests لـ Semgrep Code Finding Analyzer Pilot — L1→L5"""
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.semgrep.schemas import SemgrepFindingRecord, SemgrepEvidenceLevel
from core.semgrep.analyzer import SemgrepNormalizer, DuplicateDetector, EvidenceReviewer
from core.semgrep.context import ContextEnricher, AdaptiveAdvisor


SEMGRER_SAMPLE = json.dumps({
    "results": [
        {
            "rule_id": "python.requests.security.xss",
            "extra": {
                "message": "Possible XSS vulnerability",
                "severity": "WARNING",
                "lines": "return render_template_string(user_input)",
            },
            "path": "app/views.py",
            "start": {"line": 42},
        }
    ]
}, ensure_ascii=False)


def test_normalizer():
    norm = SemgrepNormalizer()
    records = norm.normalize_batch(SEMGRER_SAMPLE)
    assert records is not None
    assert len(records) == 1
    rec = records[0]
    assert rec.rule_id == "python.requests.security.xss"
    assert rec.severity == "WARNING"
    assert rec.file_path == "app/views.py"
    assert rec.line_number == 42
    assert rec.evidence_level == SemgrepEvidenceLevel.E0
    print("[PASS] semgrep normalizer")


def test_duplicate_detector():
    norm = SemgrepNormalizer()
    dedup = DuplicateDetector()

    rec = norm.normalize_batch(SEMGRER_SAMPLE)[0]
    g1 = dedup.add(rec)
    assert g1 is False
    g2 = dedup.add(rec)
    assert g2 is True
    count = dedup.flush()
    assert count == 1
    print("[PASS] semgrep duplicate detector")


def test_evidence_reviewer():
    norm = SemgrepNormalizer()
    reviewer = EvidenceReviewer()

    rec = norm.normalize_batch(SEMGRER_SAMPLE)[0]
    report = reviewer.review(rec)

    assert report["evidence_status"] == "sufficient"
    assert rec.evidence_level == SemgrepEvidenceLevel.E1
    print("[PASS] semgrep evidence reviewer")


def test_context_enricher():
    enricher = ContextEnricher()
    rec = SemgrepFindingRecord(
        record_id="sm1",
        rule_id="python.requests.security.xss",
        rule_message="Possible XSS",
        file_path="app/views.py",
        line_number=42,
        severity="WARNING",
        code_snippet="return render_template_string(user_input)",
        evidence_level=SemgrepEvidenceLevel.E0,
    )
    ctx = enricher.enrich(rec)
    assert ctx["is_security_rule"] is True
    assert ctx["is_input_handling"] is True
    assert ctx["language"] == "python"
    print("[PASS] semgrep context enricher")


def test_adaptive_advisor():
    advisor = AdaptiveAdvisor()
    rec = SemgrepFindingRecord(
        record_id="sm2",
        rule_id="python.requests.security.sqli",
        rule_message="SQL Injection",
        file_path="app/models.py",
        line_number=10,
        severity="HIGH",
        code_snippet="query = f'SELECT * FROM users WHERE id = {user_id}'",
        evidence_level=SemgrepEvidenceLevel.E0,
    )
    advice = advisor.advise(rec, {"is_security_rule": True, "is_input_handling": True})
    assert "semgrep --config auto" in advice
    assert "nuclei -t http/sqli" in advice
    assert len(advice) <= 8
    print("[PASS] semgrep adaptive advisor")


if __name__ == "__main__":
    test_normalizer()
    test_duplicate_detector()
    test_evidence_reviewer()
    test_context_enricher()
    test_adaptive_advisor()
    print("\n[INFO] جميع اختبارات Semgrep Pilot نجحت!")
