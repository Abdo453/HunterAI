"""Soft-404 Detector — Canonical Data Schemas (L2-L5 shared data model)"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
import time
import uuid
import hashlib


class Soft404EvidenceLevel(str):
    E0 = "E0"      # Raw soft-404 result — needs review
    E1 = "E1"      # Corroborated / evidence sufficient


@dataclass
class Soft404Record:
    """سجل نتيجة واحدة من soft-404-detector موحد."""
    record_id: str
    url: str
    status_code: int
    content_length: int
    content_type: Optional[str]
    title: Optional[str]
    is_soft_404: bool
    similarity_score: float  # 0.0 → 1.0: تشابه الصفحة مع صفحة 404 الحقيقية
    evidence_level: str = Soft404EvidenceLevel.E0
    captured_at: float = field(default_factory=time.time)
    source_tool: str = "soft-404-detector"
    raw_json: Dict[str, Any] = field(default_factory=dict)
    validation_note: str = ""

    def __post_init__(self):
        if not self.record_id:
            self.record_id = f"s404_{str(uuid.uuid4())[:10]}"

    @property
    def canonical_key(self) -> str:
        """مفتاح للتكرارات: url"""
        return self.url.lower()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Soft404Profile:
    """ملف Soft-404 موحد بعد التحليل + سياق إضافي."""
    url: str
    status_code: int
    content_length: int
    content_type: Optional[str]
    title: Optional[str]
    is_soft_404: bool
    similarity_score: float
    confidence_score: float       # 0.0 → 1.0
    confidence_label: str         # weak | possible | probable | strong
    evidence_level: str           # E0 | E1
    context_notes: List[str] = field(default_factory=list)
    adaptive_suggestions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
