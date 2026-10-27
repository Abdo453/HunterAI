"""testssl.sh TLS Configuration Intelligence — Canonical Data Schemas"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
import time
import uuid
import hashlib


class TestsslEvidenceLevel(str):
    __test__ = False
    E0 = "E0"
    E1 = "E1"


@dataclass
class TestsslFindingRecord:
    __test__ = False
    record_id: str
    severity: str
    title: str
    description: str
    cve: Optional[str] = None
    evidence_level: str = TestsslEvidenceLevel.E0
    captured_at: float = field(default_factory=time.time)
    source_tool: str = "testssl.sh"
    raw_json: Dict[str, Any] = field(default_factory=dict)
    validation_note: str = ""

    def __post_init__(self):
        if not self.record_id:
            self.record_id = f"ts_{str(uuid.uuid4())[:10]}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TLSFindingProfile:
    severity: str
    title: str
    description: str
    cve: Optional[str]
    evidence_level: str
    confidence_score: float
    confidence_label: str
    is_critical: bool = False
    context_notes: List[str] = field(default_factory=list)
    adaptive_suggestions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
