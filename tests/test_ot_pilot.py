"""Tests لـ OT / ICS Asset Discovery Pilot — L1→L5"""
import json

from core.ot.schemas import (
    OTAssetRecord,
    OTEvidenceLevel,
    OTProtocol,
    OTSecurityProfile,
)
from core.ot.analyzer import DuplicateDetector, EvidenceReviewer, OTNormalizer
from core.ot.context import AdaptiveTestAdvisor, ContextEnricher

OT_SAMPLE = json.dumps(
    {
        "assets": [
            {
                "ip": "10.0.0.50",
                "port": 502,
                "protocol": "modbus",
                "vendor": "Schneider",
                "model": "M340",
                "unit_id": 1,
                "function_codes": [1, 3, 16],
                "unauthenticated": True,
                "write_access": False,
            },
            {
                "ip": "10.0.0.51",
                "port": 102,
                "protocol": "s7",
                "vendor": "Siemens",
                "model": "S7-1200",
                "unit_id": 2,
                "function_codes": [],
                "unauthenticated": False,
                "write_access": True,
            },
        ]
    },
    ensure_ascii=False,
)


def test_normalizer_parses_sample():
    records = OTNormalizer().normalize(OT_SAMPLE, source="nmap")
    assert len(records) == 2
    modbus = [r for r in records if r.ip == "10.0.0.50"][0]
    assert modbus.port == 502
    assert modbus.protocol == OTProtocol.MODBUS
    assert modbus.vendor == "Schneider"
    assert modbus.unit_id == 1
    assert modbus.function_codes == [1, 3, 16]
    assert modbus.unauthenticated is True
    assert modbus.is_high_risk is True


def test_normalizer_handles_empty_and_garbage():
    assert OTNormalizer().normalize("") == []
    assert OTNormalizer().normalize("not json") == []


def test_duplicate_detector_merges_endpoint():
    rec1 = OTAssetRecord(
        ip="10.0.0.50", port=502, vendor="Schneider", function_codes=[1]
    )
    rec2 = OTAssetRecord(
        ip="10.0.0.50", port=502, model="M340", unauthenticated=True
    )
    d = DuplicateDetector()
    d.add(rec1)
    d.add(rec2)
    merged = d.flush()
    assert len(merged) == 1
    assert merged[0].vendor == "Schneider"
    assert merged[0].model == "M340"
    assert merged[0].unauthenticated is True


def test_reviewer_promotes_high_risk():
    rec = OTNormalizer().normalize(OT_SAMPLE, source="nmap")[0]
    report = EvidenceReviewer().review(rec)
    assert report["evidence_status"] == "sufficient"
    assert rec.evidence_level == OTEvidenceLevel.E1
    assert report["needs_verification"] is False
    assert report["confidence"] >= 0.7


def test_reviewer_stays_raw_low_risk():
    rec = OTAssetRecord(ip="10.0.0.99", port=502, protocol=OTProtocol.MODBUS)
    report = EvidenceReviewer().review(rec)
    assert report["evidence_status"] == "raw"
    assert rec.evidence_level == OTEvidenceLevel.E0


def test_context_enricher_flags_safety_impact():
    rec = OTAssetRecord(
        ip="10.0.0.50", port=502, protocol=OTProtocol.MODBUS,
        unauthenticated=True, write_access=True,
    )
    ctx = ContextEnricher().enrich(rec)
    assert ctx["safety_impact"] == "critical"
    assert ctx["process_control"] is True
    assert "modbus_cleartext" in ctx["protocol_risk"]


def test_adaptive_advisor_suggests_modbus():
    rec = OTAssetRecord(ip="10.0.0.50", port=502, protocol=OTProtocol.MODBUS, unit_id=1)
    advice = AdaptiveTestAdvisor().advise(rec, {})
    assert any("modbus-discover" in s for s in advice)
    assert any("read-holding-registers" in s for s in advice)
    assert len(advice) <= 8


def test_ot_security_profile_model():
    profile = OTSecurityProfile(
        ip="10.0.0.50",
        port=502,
        protocol=OTProtocol.MODBUS,
        unauthenticated=True,
        write_access=False,
        safety_impact="high",
        confidence_score=0.85,
        confidence_label="strong",
        evidence_level=OTEvidenceLevel.E1,
    )
    d = profile.to_dict()
    assert d["safety_impact"] == "high"
    assert d["evidence_level"] == "E1"
