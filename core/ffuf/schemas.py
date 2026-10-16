"""ffuf Response Intelligence — Canonical Data Schemas (L2-L5 shared data model)"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
import time
import uuid
import hashlib


class FfufEvidenceLevel(str):
    E0 = "E0"      # Raw ffuf result — needs review
    E1 = "E1"      # Corroborated / evidence sufficient


class ResponseCategory(str):
    NORMAL = "normal"
    ERROR = "error"
    REDIRECT = "redirect"
    AUTH_REQUIRED = "auth_required"
    SOFT_404 = "soft_404"
    INTERESTING = "interesting"


@dataclass
class FfufResultRecord:
    """سجل نتيجة واحد من ffuf موحد."""
    record_id: str
    url: str
    method: str
    status_code: int
    content_length: int
    content_words: int
    content_lines: int
    redirect_location: Optional[str] = None
    category: str = ResponseCategory.NORMAL
    confidence_score: float = 0.0
    confidence_label: str = "weak"
    evidence_level: str = FfufEvidenceLevel.E0
    captured_at: float = field(default_factory=time.time)
    source_tool: str = "ffuf"
    raw_json: Dict[str, Any] = field(default_factory=dict)
    validation_note: str = ""
    duplicate_group: Optional[str] = None

    def __post_init__(self):
        if not self.record_id:
            self.record_id = f"ff_{str(uuid.uuid4())[:10]}"

    @property
    def canonical_key(self) -> str:
        """مفتاح للتكرارات: url + status_code"""
        return f"{self.url}:{self.status_code}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ResponseCluster:
    """مجموعة استجابات متشابهة تُحتمل أنها Soft-404 أو نتائج مكررة."""
    cluster_id: str
    status_code: int
    content_length_range: str
    members: List[FfufResultRecord] = field(default_factory=list)
    representative: Optional[FfufResultRecord] = None
    is_likely_soft_404: bool = False

    def __post_init__(self):
        if not self.cluster_id:
            self.cluster_id = f"rc_{str(uuid.uuid4())[:10]}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
