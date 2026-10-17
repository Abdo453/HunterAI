"""LinkFinder JS Endpoints — Canonical Data Schemas (L2-L5 shared data model)"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
import time
import uuid
import hashlib


class LinkFinderEvidenceLevel(str):
    E0 = "E0"      # Raw linkfinder result — needs review
    E1 = "E1"      # Corroborated / evidence sufficient


@dataclass
class JSFindingRecord:
    """سجل نتيجة واحدة من linkfinder موحد."""
    record_id: str
    endpoint: str
    source_file: str
    line_number: int
    method: str
    parameter: str
    code_snippet: str
    evidence_level: str = LinkFinderEvidenceLevel.E0
    captured_at: float = field(default_factory=time.time)
    source_tool: str = "linkfinder"
    raw_json: Dict[str, Any] = field(default_factory=dict)
    validation_note: str = ""

    def __post_init__(self):
        if not self.record_id:
            self.record_id = f"js_{str(uuid.uuid4())[:10]}"

    @property
    def canonical_key(self) -> str:
        """مفتاح التكرارات: endpoint + source_file + line_number
        (نفس endpoint في سطر مصدري مختلف = رابط مختلف، مش تكرار)"""
        return f"{self.endpoint}:{self.source_file}:{self.line_number}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class JSEndpointProfile:
    """ملف نقطة نهاية JS موحد بعد تحليل linkfinder + سياق إضافي."""
    endpoint: str
    source_file: str
    line_number: int
    method: str
    parameter: str
    code_snippet: str
    confidence_score: float       # 0.0 → 1.0
    confidence_label: str         # weak | possible | probable | strong
    evidence_level: str           # E0 | E1
    is_auth_endpoint: bool = False
    is_admin_endpoint: bool = False
    is_api_endpoint: bool = False
    context_notes: List[str] = field(default_factory=list)
    adaptive_suggestions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
