"""Nmap Service Fingerprint — Canonical Data Schemas (L2-L5 shared data model)"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
import time
import uuid
import hashlib


class NmapEvidenceLevel(str):
    E0 = "E0"      # Raw nmap result — needs review
    E1 = "E1"      # Corroborated / evidence sufficient


class ServiceConfidence(str):
    CONFIRMED = "confirmed"   # Banner + version match
    PROBABLE = "probable"     # Strong banner match
    POSSIBLE = "possible"     # Port only / weak banner
    UNKNOWN = "unknown"       # Closed / filtered


@dataclass
class NmapPortRecord:
    """سجل منفذ واحد من Nmap موحد."""
    record_id: str
    host: str
    port: int
    protocol: str
    state: str
    service_name: Optional[str] = None
    service_version: Optional[str] = None
    service_product: Optional[str] = None
    banner: Optional[str] = None
    confidence: str = ServiceConfidence.UNKNOWN
    evidence_level: str = NmapEvidenceLevel.E0
    captured_at: float = field(default_factory=time.time)
    source_tool: str = "nmap"
    raw_json: Dict[str, Any] = field(default_factory=dict)
    validation_note: str = ""
    duplicate_group: Optional[str] = None

    def __post_init__(self):
        if not self.record_id:
            self.record_id = f"nm_{str(uuid.uuid4())[:10]}"

    @property
    def canonical_key(self) -> str:
        """مفتاح للتكرارات: host:port:protocol"""
        return f"{self.host}:{self.port}:{self.protocol}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ServiceProfile:
    """ملف خدمة موحد بعد تحليل Nmap + سياق إضافي."""
    host: str
    port: int
    protocol: str
    state: str
    service_name: Optional[str] = None
    service_version: Optional[str] = None
    service_product: Optional[str] = None
    banner: Optional[str] = None
    confidence: str = ServiceConfidence.UNKNOWN
    confidence_score: float = 0.0
    confidence_label: str = "weak"
    evidence_level: str = NmapEvidenceLevel.E0
    is_high_value: bool = False
    is_likely_waf: bool = False
    context_notes: List[str] = field(default_factory=list)
    adaptive_suggestions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
