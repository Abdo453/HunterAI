"""Nuclei Pilot — Canonical Schemas (L2-L5 shared data model)"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
import time
import uuid
import hashlib


class NucleiEvidenceLevel(str):
    E0 = "E0"      # Raw nuclei match — needs review
    E1 = "E1"      # Corroborated / evidence sufficient
    E2 = "E2"      # Reproduced (requires active verification — outside nuclei scope)


class FindingStatus(str):
    PENDING = "pending"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    DUPLICATE = "duplicate"
    NEEDS_VERIFICATION = "needs_verification"


@dataclass
class NucleiFindingRecord:
    """سجل نتيجة واحد من Nuclei موحد."""
    record_id: str
    template_id: str
    template_name: str
    severity: str          # info, low, medium, high, critical
    matcher_name: str
    matched_at: str        # URL / endpoint
    extracted_results: List[str] = field(default_factory=list)
    request: Optional[str] = None
    response: Optional[str] = None
    evidence_level: str = NucleiEvidenceLevel.E0
    status: str = FindingStatus.PENDING
    captured_at: float = field(default_factory=time.time)
    source_tool: str = "nuclei"
    raw_match_json: Dict[str, Any] = field(default_factory=dict)
    validation_note: str = ""
    duplicate_group: Optional[str] = None

    def __post_init__(self):
        if not self.record_id:
            self.record_id = f"nf_{str(uuid.uuid4())[:10]}"
        if not self.raw_match_json:
            self.raw_match_json = {}

    @property
    def canonical_key(self) -> str:
        """مفتاح للتكرارات: template_id + matched_at المعياري"""
        return f"{self.template_id}:{self.matched_at.rstrip('/')}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DuplicateGroup:
    """مجموعة نتائج مكررة تشير لنفس المشكلة."""
    group_id: str
    template_id: str
    members: List[NucleiFindingRecord] = field(default_factory=list)
    representative: Optional[NucleiFindingRecord] = None
    reason: str = ""

    def __post_init__(self):
        if not self.group_id:
            self.group_id = f"dg_{str(uuid.uuid4())[:10]}"
