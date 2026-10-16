"""Dalfox XSS Context Analyzer — Canonical Data Schemas"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
import time
import uuid
import hashlib


class DalfoxEvidenceLevel(str):
    E0 = "E0"
    E1 = "E1"


@dataclass
class DalfoxFindingRecord:
    record_id: str
    url: str
    injection_point: str
    payload: str
    type: str
    evidence: str
    evidence_level: str = DalfoxEvidenceLevel.E0
    captured_at: float = field(default_factory=time.time)
    source_tool: str = "dalfox"
    raw_json: Dict[str, Any] = field(default_factory=dict)
    validation_note: str = ""

    def __post_init__(self):
        if not self.record_id:
            self.record_id = f"dl_{str(uuid.uuid4())[:10]}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
