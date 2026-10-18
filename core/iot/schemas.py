"""IoT device intelligence — Canonical Data Schemas (L2-L5 shared data model)"""
from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


class IoTEvidenceLevel(str):
    E0 = "E0"  # Raw IoT discovery output — needs review
    E1 = "E1"  # Corroborated / evidence sufficient


class IoTProtocol(str):
    MQTT = "mqtt"
    ZIGBEE = "zigbee"
    BLE = "ble"
    COAP = "coap"
    UPNP = "upnp"
    UNKNOWN = "unknown"


@dataclass
class IoTDeviceRecord:
    """سجل جهاز إنترنت الأشياء واحد موحّد."""

    mac: str
    ip: Optional[str] = None
    vendor: Optional[str] = None
    protocol: str = IoTProtocol.UNKNOWN
    fingerprint: Optional[str] = None
    ports: List[int] = field(default_factory=list)
    default_creds: bool = False
    unauthenticated: bool = False
    evidence_level: str = IoTEvidenceLevel.E0
    captured_at: float = field(default_factory=time.time)
    source_tool: str = "zigbee2mqtt"
    raw_json: Dict[str, Any] = field(default_factory=dict)
    validation_note: str = ""
    record_id: str = ""

    def __post_init__(self) -> None:
        if not self.record_id:
            self.record_id = f"iot_{uuid.uuid4().hex[:10]}"

    @property
    def canonical_key(self) -> str:
        return self.mac.lower()

    @property
    def is_high_risk(self) -> bool:
        return self.default_creds or self.unauthenticated or self.protocol in (
            IoTProtocol.MQTT,
            IoTProtocol.UPNP,
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class IoTSecurityProfile:
    """ملف أمان موحّد لجهاز IoT بعد التحليل + سياق إضافي."""

    mac: str
    ip: Optional[str] = None
    protocol: str = IoTProtocol.UNKNOWN
    default_creds: bool = False
    unauthenticated: bool = False
    open_ports: List[int] = field(default_factory=list)
    risk_tier: str = "low"
    confidence_score: float = 0.0
    confidence_label: str = "weak"
    evidence_level: str = IoTEvidenceLevel.E0
    context_notes: List[str] = field(default_factory=list)
    adaptive_suggestions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
