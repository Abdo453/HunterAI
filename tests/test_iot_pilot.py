"""Tests لـ IoT Device Discovery Pilot — L1→L5"""
import json

from core.iot.schemas import (
    IoTDeviceRecord,
    IoTEvidenceLevel,
    IoTProtocol,
    IoTSecurityProfile,
)
from core.iot.analyzer import DuplicateDetector, EvidenceReviewer, IoTNormalizer
from core.iot.context import AdaptiveTestAdvisor, ContextEnricher

IOT_SAMPLE = json.dumps(
    {
        "devices": [
            {
                "mac": "AA:BB:CC:DD:EE:01",
                "ip": "192.168.1.10",
                "vendor": "Acme Cameras",
                "protocol": "mqtt",
                "ports": [1883, 80],
                "default_creds": True,
                "unauthenticated": False,
            },
            {
                "mac": "AA:BB:CC:DD:EE:02",
                "ip": "192.168.1.11",
                "vendor": "SmartHome Hub",
                "protocol": "zigbee",
                "ports": [],
                "default_creds": False,
                "unauthenticated": False,
            },
        ]
    },
    ensure_ascii=False,
)


def test_normalizer_parses_sample():
    records = IoTNormalizer().normalize(IOT_SAMPLE, source="zigbee2mqtt")
    assert len(records) == 2
    cam = [r for r in records if r.mac == "AA:BB:CC:DD:EE:01"][0]
    assert cam.ip == "192.168.1.10"
    assert cam.vendor == "Acme Cameras"
    assert cam.protocol == IoTProtocol.MQTT
    assert cam.ports == [1883, 80]
    assert cam.default_creds is True
    assert cam.is_high_risk is True


def test_normalizer_handles_empty_and_garbage():
    assert IoTNormalizer().normalize("") == []
    assert IoTNormalizer().normalize("not json") == []


def test_duplicate_detector_merges_mac():
    rec1 = IoTDeviceRecord(
        mac="AA:BB:CC:DD:EE:01",
        ip="192.168.1.10",
        ports=[1883],
        default_creds=False,
    )
    rec2 = IoTDeviceRecord(
        mac="AA:BB:CC:DD:EE:01",
        ports=[80],
        default_creds=True,
    )
    d = DuplicateDetector()
    d.add(rec1)
    d.add(rec2)
    merged = d.flush()
    assert len(merged) == 1
    assert merged[0].ip == "192.168.1.10"
    assert set(merged[0].ports) == {1883, 80}
    assert merged[0].default_creds is True


def test_reviewer_promotes_high_risk():
    rec = IoTNormalizer().normalize(IOT_SAMPLE, source="zigbee2mqtt")[0]
    report = EvidenceReviewer().review(rec)
    assert report["evidence_status"] == "sufficient"
    assert rec.evidence_level == IoTEvidenceLevel.E1
    assert report["needs_verification"] is False
    assert report["confidence"] >= 0.7


def test_reviewer_stays_raw_low_risk():
    rec = IoTDeviceRecord(mac="AA:BB:CC:DD:EE:09", protocol=IoTProtocol.BLE)
    report = EvidenceReviewer().review(rec)
    assert report["evidence_status"] == "raw"
    assert rec.evidence_level == IoTEvidenceLevel.E0


def test_context_enricher_flags_mqtt_and_default_creds():
    rec = IoTDeviceRecord(
        mac="AA:BB:CC:DD:EE:01",
        ip="192.168.1.10",
        protocol=IoTProtocol.MQTT,
        ports=[1883],
        default_creds=True,
    )
    ctx = ContextEnricher().enrich(rec)
    assert ctx["network_exposed"] is True
    assert ctx["risk_tier"] == "critical"
    assert "mqtt_broker_access" in ctx["protocol_risk"]


def test_adaptive_advisor_suggests_protocol_scans():
    rec = IoTDeviceRecord(
        mac="AA:BB:CC:DD:EE:01",
        ip="192.168.1.10",
        protocol=IoTProtocol.MQTT,
        default_creds=True,
    )
    advice = AdaptiveTestAdvisor().advise(rec, {})
    assert any("mosquitto_sub" in s for s in advice)
    assert any("hydra" in s for s in advice)
    assert len(advice) <= 8


def test_iot_security_profile_model():
    profile = IoTSecurityProfile(
        mac="AA:BB:CC:DD:EE:01",
        ip="192.168.1.10",
        protocol=IoTProtocol.MQTT,
        default_creds=True,
        open_ports=[1883],
        risk_tier="critical",
        confidence_score=0.9,
        confidence_label="strong",
        evidence_level=IoTEvidenceLevel.E1,
    )
    d = profile.to_dict()
    assert d["risk_tier"] == "critical"
    assert d["evidence_level"] == "E1"
