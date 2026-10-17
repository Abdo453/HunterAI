"""Tests لـ Masscan Port Discovery Pilot — L1→L5"""
import json

from core.masscan.schemas import (
    MasscanPortRecord, PortScanProfile,
    MasscanEvidenceLevel, PortConfidence,
)
from core.masscan.analyzer import MasscanNormalizer, DuplicateDetector, EvidenceReviewer
from core.masscan.context import ContextEnricher, AdaptiveTestAdvisor


# masscan -oJ ينتج تدفّق كائنات JSON تفصلها فاصلة (ليس مصفوفة صحيحة)
MASSACAN_STREAM = (
    '{ "ip": "10.0.0.5", "timestamp": "1", "ports": ['
    ' {"port": 445, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 52},'
    ' {"port": 22, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64}'
    ' ] },\n'
    '{ "ip": "10.0.0.9", "timestamp": "2", "ports": ['
    ' {"port": 6379, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 61}'
    ' ] },\n'
)

MASSACAN_ARRAY = json.dumps([
    {"ip": "203.0.113.10", "ports": [
        {"port": 3389, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 50},
    ]},
])


def test_normalizer_parses_stream():
    records = MasscanNormalizer.normalize_batch(MASSACAN_STREAM)
    assert len(records) == 3
    hosts = {r.host for r in records}
    assert hosts == {"10.0.0.5", "10.0.0.9"}
    smb = [r for r in records if r.port == 445][0]
    assert smb.protocol == "tcp"
    assert smb.state == "open"
    assert smb.reason == "syn-ack"
    assert smb.ttl == 52
    assert smb.canonical_key == "10.0.0.5:445:tcp"


def test_normalizer_parses_array_and_garbage():
    assert len(MasscanNormalizer.normalize_batch(MASSACAN_ARRAY)) == 1
    assert MasscanNormalizer.normalize_batch("") == []
    assert MasscanNormalizer.normalize_batch("this is not json") == []


def test_duplicate_detector():
    recs = MasscanNormalizer.normalize_batch(MASSACAN_STREAM)
    dedup = DuplicateDetector()
    r1 = recs[0]
    assert dedup.add(r1) is None              # أول ظهور
    assert dedup.add(r1) is not None          # نفس host:port:proto → تكرار
    groups = dedup.flush()
    assert r1.canonical_key in groups
    assert len(groups[r1.canonical_key]) == 2


def test_evidence_reviewer_promotes_on_synack_ttl():
    reviewer = EvidenceReviewer()
    rec = MasscanPortRecord(record_id="", host="10.0.0.5", port=445, protocol="tcp",
                            state="open", reason="syn-ack", ttl=52)
    report = reviewer.review(rec)
    assert report["evidence_status"] == "sufficient"
    assert report["needs_verification"] is False
    assert rec.evidence_level == MasscanEvidenceLevel.E1
    assert rec.confidence == PortConfidence.PROBABLE
    assert report["confidence"] >= 0.7


def test_evidence_reviewer_without_reason_stays_raw():
    reviewer = EvidenceReviewer()
    rec = MasscanPortRecord(record_id="", host="10.0.0.5", port=445, protocol="tcp",
                            state="open", reason=None, ttl=None)
    report = reviewer.review(rec)
    assert report["evidence_status"] == "raw"
    assert report["needs_verification"] is True
    assert rec.evidence_level == MasscanEvidenceLevel.E0


def test_context_enricher_flags_high_value_and_non_standard():
    enricher = ContextEnricher()
    hv = enricher.enrich(MasscanPortRecord(record_id="", host="h", port=445,
                                           protocol="tcp", state="open"))
    assert hv["is_high_value"] is True
    assert hv["expected_service"] == "smb"

    odd = enricher.enrich(MasscanPortRecord(record_id="", host="h", port=44444,
                                            protocol="tcp", state="open"))
    assert odd["is_non_standard"] is True
    assert odd["expected_service"] == "unknown"


def test_adaptive_advisor_suggests_fingerprint():
    advisor = AdaptiveTestAdvisor()
    rec = MasscanPortRecord(record_id="", host="10.0.0.5", port=445,
                            protocol="tcp", state="open")
    advice = advisor.advise(rec, {"expected_service": "smb"})
    assert any("nmap -sV -p 445" in s for s in advice)
    assert any("smb-enum-shares" in s for s in advice)
    assert len(advice) <= 8


def test_port_scan_profile_model():
    profile = PortScanProfile(
        host="10.0.0.5",
        open_ports=[22, 445],
        open_count=2,
        high_value_ports=[445],
        confidence_score=0.8,
        confidence_label="strong",
        evidence_level=MasscanEvidenceLevel.E1,
    )
    d = profile.to_dict()
    assert d["open_ports"] == [22, 445]
    assert d["evidence_level"] == "E1"
