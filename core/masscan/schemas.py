"""Masscan Port Discovery — Canonical Data Schemas (L2-L5 shared data model)"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
import time
import uuid
import hashlib


class MasscanEvidenceLevel(str):
    E0 = "E0"      # Raw masscan result — needs review
    E1 = "E1"      # Corroborated / evidence sufficient


class PortConfidence(str):
    CONFIRMED = "confirmed"   # reason syn-ack + ttl observed
    PROBABLE = "probable"     # reason syn-ack only
    POSSIBLE = "possible"     # weak/derived evidence
    UNKNOWN = "unknown"


@dataclass
class MasscanPortRecord:
    """سجل منفذ واحد من masscan موحد."""
    record_id: str
    host: str
    port: int
    protocol: str
    state: str
    reason: Optional[str] = None
    ttl: Optional[int] = None
    banner: Optional[str] = None
    confidence: str = PortConfidence.UNKNOWN
    evidence_level: str = MasscanEvidenceLevel.E0
    captured_at: float = field(default_factory=time.time)
    source_tool: str = "masscan"
    raw_json: Dict[str, Any] = field(default_factory=dict)
    validation_note: str = ""
    duplicate_group: Optional[str] = None

    def __post_init__(self):
        if not self.record_id:
            self.record_id = f"mscan_{str(uuid.uuid4())[:10]}"

    @property
    def canonical_key(self) -> str:
        """مفتاح التكرارات: host:port:protocol"""
        return f"{self.host.lower()}:{self.port}:{self.protocol}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PortScanProfile:
    """ملف مسح موحد لمضيف واحد بعد تحليل masscan + سياق إضافي."""
    host: str
    open_ports: List[int]
    open_count: int
    top_ports: List[int] = field(default_factory=list)
    high_value_ports: List[int] = field(default_factory=list)
    confidence_score: float = 0.0
    confidence_label: str = "weak"
    evidence_level: str = MasscanEvidenceLevel.E0
    context_notes: List[str] = field(default_factory=list)
    adaptive_suggestions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
