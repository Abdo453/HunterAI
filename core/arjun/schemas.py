"""Arjun Parameter Intelligence — Canonical Data Schemas"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
import time
import uuid
import hashlib


class ArjunEvidenceLevel(str):
    E0 = "E0"
    E1 = "E1"


@dataclass
class ArjunParameterRecord:
    record_id: str
    parameter: str
    url: str
    method: str
    evidence_level: str = ArjunEvidenceLevel.E0
    captured_at: float = field(default_factory=time.time)
    source_tool: str = "arjun"
    raw_json: Dict[str, Any] = field(default_factory=dict)
    validation_note: str = ""

    def __post_init__(self):
        if not self.record_id:
            self.record_id = f"arj_{str(uuid.uuid4())[:10]}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ParameterProfile:
    parameter: str
    url: str
    method: str
    confidence_score: float
    confidence_label: str
    evidence_level: str
    is_auth_parameter: bool = False
    is_id_parameter: bool = False
    is_search_parameter: bool = False
    context_notes: List[str] = field(default_factory=list)
    adaptive_suggestions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
