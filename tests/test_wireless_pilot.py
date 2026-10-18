"""Tests لـ Wireless / WiFi Intelligence Pilot — L1→L5"""
import json

from core.wireless.schemas import (
    EncryptionStrength,
    WiFiNetworkRecord,
    WirelessEvidenceLevel,
    WiFiSecurityProfile,
)
from core.wireless.analyzer import DuplicateDetector, EvidenceReviewer, WirelessNormalizer
from core.wireless.context import AdaptiveTestAdvisor, ContextEnricher

WIRELESS_JSON = json.dumps(
    [
        {
            "bssid": "AA:BB:CC:DD:EE:01",
            "ssid": "OpenGuest",
            "channel": 6,
            "signal_dbm": -45,
            "encryption": "none",
            "cipher": None,
            "auth": "open",
            "wps": False,
            "hidden": False,
        },
        {
            "bssid": "AA:BB:CC:DD:EE:02",
            "ssid": "WeakWEP",
            "channel": 1,
            "signal_dbm": -60,
            "encryption": "wep",
            "cipher": "wep",
            "auth": "open",
            "wps": True,
            "hidden": False,
        },
        {
            "bssid": "AA:BB:CC:DD:EE:03",
            "ssid": "SecureWPA",
            "channel": 11,
            "signal_dbm": -70,
            "encryption": "wpa2",
            "cipher": "ccmp",
            "auth": "psk",
            "wps": False,
            "hidden": True,
        },
    ],
    ensure_ascii=False,
)

AIRODUMP_CSV = """BSSID,First time seen,CH,Speed,Privacy,Cipher,Auth,Power,#beacons,#IV,LAN IP,ID-length,ESSID,Key
AA:BB:CC:DD:EE:01,2021-01-01,6,54e,OPN,,,-45,10,0,,,OpenGuest,
AA:BB:CC:DD:EE:02,2021-01-01,1,54e,WEP,WEP,OPN,-60,5,0,,,WeakWEP,
"""


def test_normalizer_parses_json():
    records = WirelessNormalizer().normalize(WIRELESS_JSON, source="kismet")
    assert len(records) == 3
    open_net = [r for r in records if r.ssid == "OpenGuest"][0]
    assert open_net.bssid == "AA:BB:CC:DD:EE:01"
    assert open_net.channel == 6
    assert open_net.encryption == EncryptionStrength.NONE
    assert open_net.is_open is True
    assert open_net.is_weak is True

    wep = [r for r in records if r.ssid == "WeakWEP"][0]
    assert wep.encryption == EncryptionStrength.WEP
    assert wep.is_weak is True

    wpa = [r for r in records if r.ssid == "SecureWPA"][0]
    assert wpa.encryption == EncryptionStrength.WPA
    assert wpa.hidden is True


def test_normalizer_parses_airodump_csv():
    records = WirelessNormalizer().normalize(AIRODUMP_CSV, source="airodump")
    assert len(records) == 2
    assert records[0].bssid == "AA:BB:CC:DD:EE:01"
    assert records[0].channel == 6
    assert records[0].encryption == EncryptionStrength.NONE


def test_normalizer_handles_empty_and_garbage():
    assert WirelessNormalizer().normalize("") == []
    assert WirelessNormalizer().normalize("not json") == []


def test_duplicate_detector_merges_bssid_channel():
    rec1 = WiFiNetworkRecord(
        ssid="X", bssid="AA:BB:CC:DD:EE:01", channel=6, signal_dbm=-50
    )
    rec2 = WiFiNetworkRecord(
        ssid="X", bssid="AA:BB:CC:DD:EE:01", channel=6, cipher="ccmp"
    )
    d = DuplicateDetector()
    d.add(rec1)
    d.add(rec2)
    merged = d.flush()
    assert len(merged) == 1
    assert merged[0].cipher == "ccmp"
    assert merged[0].signal_dbm == -50


def test_reviewer_promotes_weak():
    records = WirelessNormalizer().normalize(WIRELESS_JSON, source="kismet")
    wep = [r for r in records if r.encryption == EncryptionStrength.WEP][0]
    report = EvidenceReviewer().review(wep)
    assert report["evidence_status"] == "sufficient"
    assert wep.evidence_level == WirelessEvidenceLevel.E1
    assert report["needs_verification"] is False
    assert report["confidence"] >= 0.7


def test_reviewer_stays_raw_strong():
    records = WirelessNormalizer().normalize(WIRELESS_JSON, source="kismet")
    wpa = [r for r in records if r.encryption == EncryptionStrength.WPA][0]
    report = EvidenceReviewer().review(wpa)
    assert report["evidence_status"] == "raw"
    assert wpa.evidence_level == WirelessEvidenceLevel.E0


def test_context_enricher_flags_overlap_and_wps():
    records = WirelessNormalizer().normalize(WIRELESS_JSON, source="kismet")
    wep = [r for r in records if r.ssid == "WeakWEP"][0]
    ctx = ContextEnricher(other_networks=records).enrich(wep)
    assert ctx["risk_tier"] in ("high", "critical")
    assert "WPS" in "".join(ctx["notes"])


def test_adaptive_advisor_suggests_attacks():
    records = WirelessNormalizer().normalize(WIRELESS_JSON, source="kismet")
    wep = [r for r in records if r.ssid == "WeakWEP"][0]
    advice = AdaptiveTestAdvisor().advise(wep, {})
    assert any("aircrack-ng" in s for s in advice)
    assert any("reaver" in s for s in advice)
    assert len(advice) <= 8


def test_wifi_security_profile_model():
    profile = WiFiSecurityProfile(
        ssid="Test",
        bssid="AA:BB:CC:DD:EE:01",
        encryption=EncryptionStrength.WEP,
        encryption_strength=EncryptionStrength.WEP,
        wps_vulnerable=True,
        hidden=True,
        channel_overlap=True,
        signal_dbm=-60,
        confidence_score=0.9,
        confidence_label="strong",
        evidence_level=WirelessEvidenceLevel.E1,
    )
    d = profile.to_dict()
    assert d["wps_vulnerable"] is True
    assert d["evidence_level"] == "E1"
