"""HTTPx Technology Profiler — Canonical Data Schemas (L2-L5 shared data model)"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
import time
import uuid
import hashlib


class HTTPxEvidenceLevel(str):
    E0 = "E0"      # Raw httpx result — needs review
    E1 = "E1"      # Corroborated / evidence sufficient for profiling


class AssetStatus(str):
    ALIVE = "alive"
    DEAD = "dead"
    UNKNOWN = "unknown"


@dataclass
class HTTPxAssetRecord:
    """سجل أصل واحد من HTTPx موحد."""
    record_id: str
    url: str
    host: str
    port: int
    scheme: str
    status_code: Optional[int] = None
    content_length: Optional[int] = None
    content_type: Optional[str] = None
    title: Optional[str] = None
    web_server: Optional[str] = None
    technologies: List[str] = field(default_factory=list)
    cdn: Optional[str] = None
    ip: Optional[str] = None
    cname: Optional[str] = None
    status: str = AssetStatus.ALIVE
    evidence_level: str = HTTPxEvidenceLevel.E0
    captured_at: float = field(default_factory=time.time)
    source_tool: str = "httpx"
    raw_json: Dict[str, Any] = field(default_factory=dict)
    validation_note: str = ""
    duplicate_group: Optional[str] = None

    def __post_init__(self):
        if not self.record_id:
            self.record_id = f"hx_{str(uuid.uuid4())[:10]}"
        if not self.host and self.url:
            from urllib.parse import urlparse
            self.host = urlparse(self.url).hostname or ""

    @property
    def canonical_key(self) -> str:
        """مفتاح للتكرارات: host:port normalized"""
        return f"{self.host.lower()}:{self.port}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TechnologyProfile:
    """ملف تقني موحد لأصل واحد بعد تحليل HTTPx + سياق إضافي."""
    host: str
    url: str
    port: int
    scheme: str
    status_code: Optional[int]
    web_server: Optional[str]
    technologies: List[str]
    cdn: Optional[str]
    confidence_score: float       # 0.0 → 1.0
    confidence_label: str         # weak | possible | probable | strong
    evidence_level: str           # E0 | E1
    is_likely_waf: bool = False
    is_likely_cdn: bool = False
    context_notes: List[str] = field(default_factory=list)
    adaptive_suggestions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
