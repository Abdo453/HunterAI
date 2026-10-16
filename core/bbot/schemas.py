"""BBOT Asset Relationship Analyzer — Canonical Data Schemas"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
import time
import uuid
import hashlib


class BBOTEvidenceLevel(str):
    E0 = "E0"
    E1 = "E1"


@dataclass
class BBOTAssetRecord:
    record_id: str
    asset_type: str
    asset_value: str
    source_module: str
    relationship: Optional[str] = None
    related_asset: Optional[str] = None
    evidence_level: str = BBOTEvidenceLevel.E0
    captured_at: float = field(default_factory=time.time)
    source_tool: str = "bbot"
    raw_json: Dict[str, Any] = field(default_factory=dict)
    validation_note: str = ""

    def __post_init__(self):
        if not self.record_id:
            self.record_id = f"bb_{str(uuid.uuid4())[:10]}"

    @property
    def canonical_key(self) -> str:
        return f"{self.asset_type}:{self.asset_value}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
