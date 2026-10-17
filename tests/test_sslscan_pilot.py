"""Tests لـ SSLScan TLS Cipher & Protocol Intelligence Pilot — L1→L5"""
from core.sslscan.schemas import (
    SSLCertRecord,
    SSLCipherRecord,
    SSLAssetRecord,
    SSLEvidenceLevel,
    SSLProtocolRecord,
    TLSConfigProfile,
)
from core.sslscan.analyzer import DuplicateDetector, EvidenceReviewer, SSLScanNormalizer
from core.sslscan.context import AdaptiveTestAdvisor, ContextEnricher

SSLSCAN_XML = """<?xml version="1.0"?>
<sslscan version="1.9.3">
  <target host="example.com" port="443"/>
  <ssltls>
    <protocol version="TLS 1.2" enabled="yes"/>
    <protocol version="SSLv3" enabled="no"/>
    <protocol version="TLSv1" enabled="yes"/>
  </ssltls>
  <ciphers>
    <cipher name="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" bits="128" used="yes" export="no"/>
    <cipher name="EXP-RC4-MD5" bits="40" used="yes" export="yes"/>
  </ciphers>
  <certificate>
    <subject>CN=example.com</subject>
    <issuer>CN=Let's Encrypt</issuer>
    <sig_alg>sha256WithRSAEncryption</sig_alg>
  </certificate>
  <heartbleed>
    <vulnerable>no</vulnerable>
  </heartbleed>
  <poodle>
    <vulnerable>yes</vulnerable>
  </poodle>
</sslscan>"""


def test_normalizer_parses_xml():
    records = SSLScanNormalizer().normalize_xml(SSLSCAN_XML)
    assert len(records) == 1
    rec = records[0]
    assert rec.host == "example.com"
    assert rec.port == 443
    assert rec.enabled_protocols == ["TLS 1.2", "TLSv1"]
    assert {c.name for c in rec.ciphers} == {
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "EXP-RC4-MD5",
    }
    assert rec.certificates[0].subject == "CN=example.com"
    assert rec.heartbleed is False
    assert rec.poodle is True


def test_normalizer_handles_empty_and_garbage():
    n = SSLScanNormalizer()
    assert n.normalize_xml("") == []
    assert n.normalize_xml("not xml") == []


def test_weak_cipher_flag():
    rec = SSLScanNormalizer().normalize_xml(SSLSCAN_XML)[0]
    weak = rec.weak_ciphers
    assert "EXP-RC4-MD5" in weak
    assert rec.ciphers[0].is_weak is False  # 128 bits, not export/anon


def test_legacy_protocol_flag():
    proto = SSLProtocolRecord(version="SSLv3")
    assert proto.is_legacy is True
    proto2 = SSLProtocolRecord(version="TLS 1.2")
    assert proto2.is_legacy is False


def test_duplicate_detector_merges_targets():
    rec1 = SSLAssetRecord(
        host="example.com", port=443,
        protocols=[SSLProtocolRecord(version="TLS 1.2", enabled=True)],
    )
    rec2 = SSLAssetRecord(
        host="example.com", port=443,
        ciphers=[SSLCipherRecord(name="AES128-SHA", bits="128", used=True)],
    )
    d = DuplicateDetector()
    d.add(rec1)
    d.add(rec2)
    merged = d.flush()
    assert len(merged) == 1
    assert len(merged[0].protocols) == 1
    assert len(merged[0].ciphers) == 1


def test_reviewer_promotes_on_protocols_and_ciphers():
    rec = SSLScanNormalizer().normalize_xml(SSLSCAN_XML)[0]
    report = EvidenceReviewer().review(rec)
    assert report["evidence_status"] == "sufficient"
    assert rec.evidence_level == SSLEvidenceLevel.E1
    assert report["weak_cipher_count"] == 1
    assert report["poodle"] is True


def test_reviewer_stays_raw_without_data():
    rec = SSLAssetRecord(host="example.com", port=443)
    report = EvidenceReviewer().review(rec)
    assert report["evidence_status"] == "raw"
    assert rec.evidence_level == SSLEvidenceLevel.E0


def test_context_enricher_flags_legacy_and_weak():
    rec = SSLScanNormalizer().normalize_xml(SSLSCAN_XML)[0]
    ctx = ContextEnricher().enrich(rec)
    assert ctx["has_legacy_protocol"] is True  # TLSv1 + SSLv3? SSLv3 not enabled
    # TLSv1 is legacy and enabled
    assert "TLSv1" in ctx["tls_version_surface"]
    assert ctx["has_weak_cipher"] is True
    assert "weak_ciphers" in ctx["attack_surface"]


def test_adaptive_advisor_suggests_scans():
    rec = SSLScanNormalizer().normalize_xml(SSLSCAN_XML)[0]
    ctx = ContextEnricher().enrich(rec)
    advice = AdaptiveTestAdvisor().advise(rec, ctx)
    assert any("sslscan" in s for s in advice)
    assert any("testssl" in s for s in advice)
    assert any("ssl-enum-ciphers" in s for s in advice)
    assert len(advice) <= 8


def test_tls_config_profile_model():
    profile = TLSConfigProfile(
        host="example.com",
        port=443,
        enabled_protocols=["TLS 1.2"],
        legacy_protocols=[],
        cipher_count=5,
        weak_cipher_count=1,
        heartbleed=False,
        poodle=True,
        confidence_score=0.7,
        confidence_label="probable",
        evidence_level=SSLEvidenceLevel.E1,
    )
    d = profile.to_dict()
    assert d["port"] == 443
    assert d["poodle"] is True
    assert d["evidence_level"] == "E1"
