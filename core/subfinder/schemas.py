"""Subfinder Asset Coverage — Canonical Data Schemas (L2-L5 shared data model)"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
import time
import uuid
import hashlib


class SubfinderEvidenceLevel(str):
    E0 = "E0"      # Raw subfinder result — needs review
    E1 = "E1"      # Corroborated / evidence sufficient


class SourceType(str):
    """نوع مصدر اكتشاف النطاق الفرعي (من حقل source-type في مخرجات subfinder)"""
    CERTIFICATE = "certificate"   # crt.sh / CT logs
    DNS = "dns"                   # DNS resolution
    PASSIVE = "passive"           # passive sources (shodan, virustotal...)
    ACTIVE = "active"             # active DNS bruteforce
    API = "api"                   # third-party API source
    UNKNOWN = "unknown"


@dataclass
class SubfinderAssetRecord:
    """سجل أصل فرعي واحد من subfinder موحد."""
    record_id: str
    subdomain: str
    source: str
    source_type: str = SourceType.UNKNOWN
    ip: Optional[str] = None
    cdn: Optional[str] = None
    evidence_level: str = SubfinderEvidenceLevel.E0
    captured_at: float = field(default_factory=time.time)
    source_tool: str = "subfinder"
    raw_json: Dict[str, Any] = field(default_factory=dict)
    validation_note: str = ""
    duplicate_group: Optional[str] = None

    def __post_init__(self):
        if not self.record_id:
            self.record_id = f"sf_{str(uuid.uuid4())[:10]}"

    @property
    def canonical_key(self) -> str:
        """مفتاح للتكرارات: subdomain"""
        return self.subdomain.lower()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AssetCoverageProfile:
    """ملف تغطية أصلي موحد بعد تحليل subfinder + سياق إضافي."""
    subdomain: str
    source: str
    ip: Optional[str] = None
    cdn: Optional[str] = None
    is_high_value: bool = False
    is_live_web: bool = False
    confidence_score: float = 0.0       # 0.0 → 1.0
    confidence_label: str = "weak"      # weak | possible | probable | strong
    evidence_level: str = "E0"          # E0 | E1
    context_notes: List[str] = field(default_factory=list)
    adaptive_suggestions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
