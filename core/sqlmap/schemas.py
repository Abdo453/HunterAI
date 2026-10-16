"""SQLmap Result Interpreter — Canonical Data Schemas"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
import time
import uuid
import hashlib


class SQLmapEvidenceLevel(str):
    E0 = "E0"
    E1 = "E1"


@dataclass
class SQLmapFindingRecord:
    record_id: str
    parameter: str
    payload: str
    technique: str
    dbms: Optional[str]
    evidence: str
    evidence_level: str = SQLmapEvidenceLevel.E0
    captured_at: float = field(default_factory=time.time)
    source_tool: str = "sqlmap"
    raw_json: Dict[str, Any] = field(default_factory=dict)
    validation_note: str = ""

    def __post_init__(self):
        if not self.record_id:
            self.record_id = f"sq_{str(uuid.uuid4())[:10]}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
