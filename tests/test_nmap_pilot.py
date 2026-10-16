"""Tests لـ Nmap Service Fingerprint Pilot — L1→L5"""
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.nmap.schemas import (
    NmapPortRecord, ServiceProfile,
    NmapEvidenceLevel, ServiceConfidence,
)
from core.nmap.analyzer import NmapNormalizer, DuplicateDetector, EvidenceReviewer
from core.nmap.context import ContextEnricher, AdaptiveTestAdvisor


# عينة من مخرجات Nmap XML
NMAP_SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="203.0.113.10" addrtype="ipv4"/>
    <ports>
      <port portid="22" protocol="tcp">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="7.4"/>
      </port>
      <port portid="80" protocol="tcp">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0"/>
      </port>
      <port portid="443" protocol="tcp">
        <state state="open"/>
        <service name="https" product="nginx" version="1.18.0"/>
      </port>
      <port portid="3306" protocol="tcp">
        <state state="open"/>
        <service name="mysql" product="MySQL" version="5.7.34"/>
      </port>
      <port portid="6667" protocol="tcp">
        <state state="closed"/>
        <service name="irc"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

NMAP_SAMPLE_CLOSED = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port portid="22" protocol="tcp">
        <state state="closed"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


def test_normalizer():
    records = NmapNormalizer.normalize_nmap_xml(NMAP_SAMPLE_XML)
    assert len(records) == 5

    ssh = [r for r in records if r.port == 22][0]
    assert ssh.state == "open"
    assert ssh.service_name == "ssh"
    assert ssh.service_product == "OpenSSH"
    assert ssh.service_version == "7.4"
    assert ssh.confidence == ServiceConfidence.CONFIRMED
    assert ssh.evidence_level == NmapEvidenceLevel.E0

    mysql = [r for r in records if r.port == 3306][0]
    assert mysql.confidence == ServiceConfidence.CONFIRMED

    closed = [r for r in records if r.port == 6667][0]
    assert closed.state == "closed"
    assert closed.confidence == ServiceConfidence.UNKNOWN

    print("[PASS] nmap normalizer")


def test_duplicate_detector():
    records = NmapNormalizer.normalize_nmap_xml(NMAP_SAMPLE_XML)
    dedup = DuplicateDetector()

    # أول منفذ SSH → مجموعة جديدة
    ssh_rec = [r for r in records if r.port == 22][0]
    g1 = dedup.add(ssh_rec)
    assert g1 is None

    # مكرر لنفس المنفذ
    g2 = dedup.add(ssh_rec)
    assert g2 is not None

    groups = dedup.flush()
    assert len(groups) == 1
    assert len(groups["203.0.113.10:22:tcp"]) == 2
    print("[PASS] nmap duplicate detector")


def test_evidence_reviewer():
    records = NmapNormalizer.normalize_nmap_xml(NMAP_SAMPLE_XML)
    reviewer = EvidenceReviewer()

    # SSH OpenSSH 7.4 → sufficient → E1
    ssh_rec = [r for r in records if r.port == 22][0]
    report = reviewer.review(ssh_rec)
    assert report["evidence_status"] == "sufficient"
    assert report["needs_verification"] is False
    assert report["is_high_value"] is True
    assert ssh_rec.evidence_level == NmapEvidenceLevel.E1

    # منفذ مغلق → insufficient
    closed_rec = [r for r in records if r.port == 6667][0]
    report_closed = reviewer.review(closed_rec)
    assert report_closed["evidence_status"] == "insufficient"
    assert report_closed["needs_verification"] is True

    # MySQL → high value
    mysql_rec = [r for r in records if r.port == 3306][0]
    report_mysql = reviewer.review(mysql_rec)
    assert report_mysql["is_high_value"] is True

    print("[PASS] nmap evidence reviewer")


def test_context_enricher():
    enricher = ContextEnricher(
        httpx_results={80: ["http://203.0.113.10/"], 443: ["https://203.0.113.10/"]},
        katana_endpoints=["https://203.0.113.10/admin/dashboard"],
    )
    rec = NmapPortRecord(
        record_id="nm_test",
        host="203.0.113.10",
        port=443,
        protocol="tcp",
        state="open",
        service_name="https",
        service_version="1.18.0",
        service_product="nginx",
        banner="nginx 1.18.0",
        evidence_level=NmapEvidenceLevel.E0,
    )
    ctx = enricher.enrich(rec)
    assert ctx["is_web_service"] is True
    assert ctx["service_family"] == "web"
    assert len(ctx["related_urls"]) == 1
    assert "https://203.0.113.10/" in ctx["related_urls"]

    # منفذ SSH
    rec_ssh = NmapPortRecord(
        record_id="nm_ssh",
        host="203.0.113.10",
        port=22,
        protocol="tcp",
        state="open",
        service_name="ssh",
        evidence_level=NmapEvidenceLevel.E0,
    )
    ctx_ssh = enricher.enrich(rec_ssh)
    assert ctx_ssh["is_remote_access"] is True
    assert ctx_ssh["service_family"] == "remote_access"
    print("[PASS] nmap context enricher")


def test_adaptive_advisor():
    advisor = AdaptiveTestAdvisor()
    rec = NmapPortRecord(
        record_id="nm_adv",
        host="203.0.113.10",
        port=80,
        protocol="tcp",
        state="open",
        service_name="http",
        service_product="Apache",
        service_version="2.4.41",
        evidence_level=NmapEvidenceLevel.E0,
    )
    advice = advisor.advise(rec, {"service_family": "web", "auth_sensitive": True})
    assert "nuclei -t http/vuln" in advice
    assert "nuclei -t http/apache" in advice
    assert "nuclei -t http/default-credentials" in advice
    assert len(advice) <= 8
    print("[PASS] nmap adaptive advisor")


def test_service_profile():
    profile = ServiceProfile(
        host="203.0.113.10",
        port=22,
        protocol="tcp",
        state="open",
        service_name="ssh",
        service_version="7.4",
        service_product="OpenSSH",
        banner="OpenSSH 7.4",
        confidence="strong",
        confidence_label="strong",
        confidence_score=0.85,
        evidence_level=NmapEvidenceLevel.E1,
        is_high_value=True,
    )
    d = profile.to_dict()
    assert d["confidence_label"] == "strong"
    assert d["evidence_level"] == "E1"
    assert d["is_high_value"] is True
    print("[PASS] nmap service profile")


if __name__ == "__main__":
    test_normalizer()
    test_duplicate_detector()
    test_evidence_reviewer()
    test_context_enricher()
    test_adaptive_advisor()
    test_service_profile()
    print("\n[INFO] جميع اختبارات Nmap Pilot نجحت!")
