"""Gitleaks Secret Context Analyzer — Canonical Data Schemas"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
import time
import uuid
import hashlib


class GitleaksEvidenceLevel(str):
    E0 = "E0"
    E1 = "E1"


@dataclass
class GitleaksFindingRecord:
    record_id: str
    rule_id: str
    secret_type: str
    file_path: str
    start_line: int
    end_line: int
    secret_value: Optional[str] = None
    evidence_level: str = GitleaksEvidenceLevel.E0
    captured_at: float = field(default_factory=time.time)
    source_tool: str = "gitleaks"
    raw_json: Dict[str, Any] = field(default_factory=dict)
    validation_note: str = ""

    def __post_init__(self):
        if not self.record_id:
            self.record_id = f"gl_{str(uuid.uuid4())[:10]}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
