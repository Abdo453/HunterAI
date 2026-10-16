"""Burp Suite Traffic Intelligence — Canonical Data Schemas"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
import time
import uuid
import hashlib


class BurpEvidenceLevel(str):
    E0 = "E0"
    E1 = "E1"


@dataclass
class BurpTrafficRecord:
    record_id: str
    request_url: str
    request_method: str
    request_headers: Dict[str, str]
    request_body: Optional[str]
    response_status: Optional[int]
    response_headers: Dict[str, str]
    response_body: Optional[str]
    evidence_level: str = BurpEvidenceLevel.E0
    captured_at: float = field(default_factory=time.time)
    source_tool: str = "burp"
    raw_json: Dict[str, Any] = field(default_factory=dict)
    validation_note: str = ""

    def __post_init__(self):
        if not self.record_id:
            self.record_id = f"bp_{str(uuid.uuid4())[:10]}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
