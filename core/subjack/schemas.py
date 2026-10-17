"""Subjack Subdomain Takeover — Canonical Data Schemas"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
import time
import uuid
import hashlib


class SubjackEvidenceLevel(str):
    E0 = "E0"
    E1 = "E1"


@dataclass
class SubdomainTakeoverRecord:
    record_id: str
    subdomain: str
    cname: Optional[str]
    status_code: Optional[int]
    fingerprint: Optional[str]
    takeover_risk: str
    evidence_level: str = SubjackEvidenceLevel.E0
    captured_at: float = field(default_factory=time.time)
    source_tool: str = "subjack"
    raw_json: Dict[str, Any] = field(default_factory=dict)
    validation_note: str = ""

    def __post_init__(self):
        if not self.record_id:
            self.record_id = f"sj_{str(uuid.uuid4())[:10]}"

    @property
    def canonical_key(self) -> str:
        return self.subdomain.lower()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TakeoverProfile:
    subdomain: str
    cname: Optional[str]
    status_code: Optional[int]
    fingerprint: Optional[str]
    takeover_risk: str
    confidence_score: float
    confidence_label: str
    evidence_level: str
    is_vulnerable: bool = False
    context_notes: List[str] = field(default_factory=list)
    adaptive_suggestions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
