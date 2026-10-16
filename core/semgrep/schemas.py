"""Semgrep Code Finding Analyzer — Canonical Data Schemas"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
import time
import uuid
import hashlib


class SemgrepEvidenceLevel(str):
    E0 = "E0"
    E1 = "E1"


@dataclass
class SemgrepFindingRecord:
    record_id: str
    rule_id: str
    rule_message: str
    file_path: str
    line_number: int
    severity: str
    code_snippet: Optional[str]
    evidence_level: str = SemgrepEvidenceLevel.E0
    captured_at: float = field(default_factory=time.time)
    source_tool: str = "semgrep"
    raw_json: Dict[str, Any] = field(default_factory=dict)
    validation_note: str = ""

    def __post_init__(self):
        if not self.record_id:
            self.record_id = f"sm_{str(uuid.uuid4())[:10]}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
