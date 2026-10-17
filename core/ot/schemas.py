"""OT / ICS intelligence — Canonical Data Schemas (L2-L5 shared data model)"""
from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


class OTEvidenceLevel(str):
    E0 = "E0"  # Raw OT/ICS scan output — needs review
    E1 = "E1"  # Corroborated / evidence sufficient


class OTProtocol(str):
    MODBUS = "modbus"
    S7 = "s7"
    ETHERNET_IP = "ethernet-ip"
    PROFINET = "profinet"
    UNKNOWN = "unknown"


@dataclass
class OTAssetRecord:
    """سجل أصل OT واحد موحّد."""

    record_id: str
    ip: str
    port: int
    protocol: str = OTProtocol.UNKNOWN
    vendor: Optional[str] = None
    model: Optional[str] = None
    unit_id: Optional[int] = None
    function_codes: List[int] = field(default_factory=list)
    unauthenticated: bool = False
    write_access: bool = False
    evidence_level: str = OTEvidenceLevel.E0
    captured_at: float = field(default_factory=time.time)
    source_tool: str = "nmap"
    raw_json: Dict[str, Any] = field(default_factory=dict)
    validation_note: str = ""

    def __post_init__(self) -> None:
        if not self.record_id:
            self.record_id = f"ot_{uuid.uuid4().hex[:10]}"

    @property
    def canonical_key(self) -> str:
        return f"{self.ip}:{self.port}"

    @property
    def is_high_risk(self) -> bool:
        return self.unauthenticated or self.write_access

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class OTSecurityProfile:
    """ملف أمان موحّد لأصل OT بعد التحليل + سياق إضافي."""

    ip: str
    port: int
    protocol: str = OTProtocol.UNKNOWN
    unauthenticated: bool = False
    write_access: bool = False
    safety_impact: str = "low"  # low | medium | high | critical
    confidence_score: float = 0.0
    confidence_label: str = "weak"
    evidence_level: str = OTEvidenceLevel.E0
    context_notes: List[str] = field(default_factory=list)
    adaptive_suggestions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
