"""Wireless / WiFi intelligence — Canonical Data Schemas (L2-L5 shared data model)"""
from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


class WirelessEvidenceLevel(str):
    E0 = "E0"  # Raw wireless scan output — needs review
    E1 = "E1"  # Corroborated / evidence sufficient


class EncryptionStrength(str):
    NONE = "none"        # Open network — highest risk
    WEP = "wep"          # WEP — trivially crackable
    WPA = "wpa"          # WPA/WPA2 — dictionary attack surface
    WPA3 = "wpa3"        # WPA3 — current standard
    UNKNOWN = "unknown"


@dataclass
class WiFiNetworkRecord:
    """سجل شبكة WiFi واحدة موحّد."""

    ssid: str
    bssid: str
    channel: Optional[int] = None
    frequency: Optional[int] = None  # MHz
    signal_dbm: Optional[int] = None
    encryption: str = EncryptionStrength.UNKNOWN
    cipher: Optional[str] = None
    auth: Optional[str] = None
    wps: bool = False
    hidden: bool = False
    vendor: Optional[str] = None
    evidence_level: str = WirelessEvidenceLevel.E0
    captured_at: float = field(default_factory=time.time)
    source_tool: str = "kismet"
    raw_json: Dict[str, Any] = field(default_factory=dict)
    validation_note: str = ""
    record_id: str = ""

    def __post_init__(self) -> None:
        if not self.record_id:
            self.record_id = f"wifi_{uuid.uuid4().hex[:10]}"

    @property
    def canonical_key(self) -> str:
        return f"{self.bssid.lower()}:{self.channel or '?'}"

    @property
    def is_open(self) -> bool:
        return self.encryption == EncryptionStrength.NONE

    @property
    def is_weak(self) -> bool:
        return self.encryption in (EncryptionStrength.NONE, EncryptionStrength.WEP)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class WiFiSecurityProfile:
    """ملف أمان موحّد لشبكة WiFi بعد التحليل + سياق إضافي."""

    ssid: str
    bssid: str
    encryption: str = EncryptionStrength.UNKNOWN
    encryption_strength: str = EncryptionStrength.UNKNOWN
    wps_vulnerable: bool = False
    hidden: bool = False
    channel_overlap: bool = False
    signal_dbm: Optional[int] = None
    confidence_score: float = 0.0
    confidence_label: str = "weak"
    evidence_level: str = WirelessEvidenceLevel.E0
    context_notes: List[str] = field(default_factory=list)
    adaptive_suggestions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
