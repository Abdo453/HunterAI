"""Katana Endpoint Intelligence — Canonical Data Schemas (L2-L5 shared data model)"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
import time
import uuid
import hashlib


class KatanaEvidenceLevel(str):
    E0 = "E0"      # Raw katana result — needs review
    E1 = "E1"      # Corroborated / evidence sufficient


class EndpointCategory(str):
    STATIC = "static"
    API = "api"
    AUTH = "auth"
    ADMIN = "admin"
    FILE = "file"
    UNKNOWN = "unknown"


@dataclass
class KatanaEndpointRecord:
    """سجل نقطة نهاية واحد من Katana موحد."""
    record_id: str
    url: str
    method: str
    status_code: Optional[int]
    content_length: Optional[int]
    content_type: Optional[str]
    category: str = EndpointCategory.UNKNOWN
    is_js: bool = False
    is_form: bool = False
    parameters: List[str] = field(default_factory=list)
    evidence_level: str = KatanaEvidenceLevel.E0
    captured_at: float = field(default_factory=time.time)
    source_tool: str = "katana"
    raw_json: Dict[str, Any] = field(default_factory=dict)
    validation_note: str = ""
    duplicate_group: Optional[str] = None

    def __post_init__(self):
        if not self.record_id:
            self.record_id = f"kt_{str(uuid.uuid4())[:10]}"

    @property
    def canonical_key(self) -> str:
        """مفتاح للتكرارات: url + method"""
        return f"{self.url}:{self.method}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EndpointProfile:
    """ملف نقطة نهاية موحد بعد تحليل Katana + سياق إضافي."""
    url: str
    method: str
    category: str
    confidence_score: float       # 0.0 → 1.0
    confidence_label: str         # weak | possible | probable | strong
    evidence_level: str           # E0 | E1
    is_auth_sensitive: bool = False
    is_admin_sensitive: bool = False
    is_api: bool = False
    context_notes: List[str] = field(default_factory=list)
    adaptive_suggestions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
