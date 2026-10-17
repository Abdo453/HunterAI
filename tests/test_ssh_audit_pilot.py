"""Tests لـ SSH-Audit Security Profiler Pilot — L1→L5"""
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.ssh_audit.schemas import (
    SSHAssetRecord, SSHSecurityProfile,
    SSHAuditEvidenceLevel,
)
from core.ssh_audit.analyzer import (
    SSHAuditNormalizer, DuplicateDetector, EvidenceReviewer,
)
from core.ssh_audit.context import ContextEnricher, AdaptiveTestAdvisor


SSHAUDIT_SAMPLE = json.dumps({
    "url": "https://target.local:22/",
    "host": "target.local",
    "port": 22,
    "scheme": "ssh",
    "status_code": 200,
    "content_length": 100,
    "content_type": "text/plain",
    "web_server": "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7",
    "technology": ["SSH", "OpenSSH"],
    "cdn": None,
    "ip": "203.0.113.10",
    "cname": None,
}, ensure_ascii=False)


def test_normalizer():
    norm = SSHAuditNormalizer()
    rec = norm.normalize_ssh_audit_json_line(SSHAUDIT_SAMPLE)
    assert rec is not None
    assert rec.host == "target.local"
    assert rec.port == 22
    assert rec.status_code == 200
    assert rec.web_server == "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7"
    assert "SSH" in rec.technologies
    assert rec.evidence_level == SSHAuditEvidenceLevel.E1
    print("[PASS] ssh-audit normalizer")


def test_duplicate_detector():
    norm = SSHAuditNormalizer()
    dedup = DuplicateDetector()

    rec = norm.normalize_ssh_audit_json_line(SSHAUDIT_SAMPLE)
    g1 = dedup.add(rec)
    assert g1 is None
    g2 = dedup.add(rec)
    assert g2 is not None

    groups = dedup.flush()
    assert len(groups) == 1
    assert len(groups["target.local:22"]) == 2
    print("[PASS] ssh-audit duplicate detector")


def test_evidence_reviewer():
    norm = SSHAuditNormalizer()
    reviewer = EvidenceReviewer()

    rec = norm.normalize_ssh_audit_json_line(SSHAUDIT_SAMPLE)
    report = reviewer.review(rec)

    assert rec.evidence_level == SSHAuditEvidenceLevel.E1
    assert rec.evidence_status == "sufficient"
    assert report["needs_verification"] is False
    print("[PASS] ssh-audit evidence reviewer")


def test_context_enricher():
    enricher = ContextEnricher(
        httpx_results={"target.local:22": ["http://target.local:22/"]},
    )
    rec = SSHAssetRecord(
        record_id="ssh1",
        url="https://target.local:22/",
        host="target.local",
        port=22,
        scheme="ssh",
        status_code=200,
        content_length=100,
        content_type="text/plain",
        web_server="SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7",
        technologies=["SSH"],
        cdn=None,
        ip="203.0.113.10",
        cname=None,
        evidence_level=SSHAuditEvidenceLevel.E0,
    )
    ctx = enricher.enrich(rec)
    assert ctx["is_ssh_service"] is True
    assert ctx["is_web_service"] is False
    print("[PASS] ssh-audit context enricher")


def test_adaptive_advisor():
    advisor = AdaptiveTestAdvisor()
    rec = SSHAssetRecord(
        record_id="ssh2",
        url="https://target.local:22/",
        host="target.local",
        port=22,
        scheme="ssh",
        status_code=200,
        content_length=100,
        content_type="text/plain",
        web_server="SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7",
        technologies=["SSH"],
        evidence_level=SSHAuditEvidenceLevel.E0,
    )
    advice = advisor.advise(rec, {"is_high_value": True})
    assert "nmap --script ssh-brute" in advice
    assert len(advice) <= 8
    print("[PASS] ssh-audit adaptive advisor")


def test_security_profile():
    profile = SSHSecurityProfile(
        host="target.local",
        url="https://target.local:22/",
        port=22,
        scheme="ssh",
        status_code=200,
        content_length=100,
        content_type="text/plain",
        web_server="SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7",
        technologies=["SSH"],
        cdn=None,
        ip="203.0.113.10",
        cname=None,
        evidence_level=SSHAuditEvidenceLevel.E0,
    )
    d = profile.to_dict()
    assert d["confidence_label"] == "weak"
    assert d["evidence_level"] == "E0"
    print("[PASS] ssh-audit security profile")


if __name__ == "__main__":
    test_normalizer()
    test_duplicate_detector()
    test_evidence_reviewer()
    test_context_enricher()
    test_adaptive_advisor()
    test_security_profile()
    print("\n[INFO] جميع اختبارات SSH-Audit Pilot نجحت!")
