"""Tests لـ Gitleaks Secret Context Analyzer Pilot — L1→L5"""
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.gitleaks.schemas import GitleaksFindingRecord, GitleaksEvidenceLevel
from core.gitleaks.analyzer import GitleaksNormalizer, DuplicateDetector, EvidenceReviewer
from core.gitleaks.context import ContextEnricher, AdaptiveAdvisor


GITLEAKS_SAMPLE = json.dumps({
    "RuleID": "aws-access-key",
    "SecretType": "AWS Access Key",
    "File": "config/aws_creds.txt",
    "StartLine": 5,
    "EndLine": 5,
    "Secret": "AKIAIOSFODNN7EXAMPLE",
}, ensure_ascii=False)


def test_normalizer():
    norm = GitleaksNormalizer()
    rec = norm.normalize_gitleaks_json_line(GITLEAKS_SAMPLE)
    assert rec is not None
    assert rec.rule_id == "aws-access-key"
    assert rec.secret_type == "AWS Access Key"
    assert rec.file_path == "config/aws_creds.txt"
    assert rec.start_line == 5
    assert rec.evidence_level == GitleaksEvidenceLevel.E0
    print("[PASS] gitleaks normalizer")


def test_duplicate_detector():
    norm = GitleaksNormalizer()
    dedup = DuplicateDetector()

    rec = norm.normalize_gitleaks_json_line(GITLEAKS_SAMPLE)
    g1 = dedup.add(rec)
    assert g1 is False
    g2 = dedup.add(rec)
    assert g2 is True
    count = dedup.flush()
    assert count == 1
    print("[PASS] gitleaks duplicate detector")


def test_evidence_reviewer():
    norm = GitleaksNormalizer()
    reviewer = EvidenceReviewer()

    rec = norm.normalize_gitleaks_json_line(GITLEAKS_SAMPLE)
    report = reviewer.review(rec)

    assert report["evidence_status"] == "sufficient"
    assert rec.evidence_level == GitleaksEvidenceLevel.E1
    print("[PASS] gitleaks evidence reviewer")


def test_context_enricher():
    enricher = ContextEnricher()
    rec = GitleaksFindingRecord(
        record_id="gl1",
        rule_id="aws-access-key",
        secret_type="AWS Access Key",
        file_path="config/aws_creds.txt",
        start_line=5,
        end_line=5,
        secret_value="AKIAIOSFODNN7EXAMPLE",
        evidence_level=GitleaksEvidenceLevel.E0,
    )
    ctx = enricher.enrich(rec)
    assert ctx["is_credential_file"] is True
    assert ctx["is_high_risk_secret"] is True
    print("[PASS] gitleaks context enricher")


def test_adaptive_advisor():
    advisor = AdaptiveAdvisor()
    rec = GitleaksFindingRecord(
        record_id="gl2",
        rule_id="private-key",
        secret_type="Private Key",
        file_path="src/main.py",
        start_line=10,
        end_line=15,
        evidence_level=GitleaksEvidenceLevel.E0,
    )
    advice = advisor.advise(rec, {"is_high_risk_secret": True, "is_source_code": True})
    assert "git filter-branch" in advice
    assert "semgrep --config auto" in advice
    assert len(advice) <= 8
    print("[PASS] gitleaks adaptive advisor")


if __name__ == "__main__":
    test_normalizer()
    test_duplicate_detector()
    test_evidence_reviewer()
    test_context_enricher()
    test_adaptive_advisor()
    print("\n[INFO] جميع اختبارات Gitleaks Pilot نجحت!")
