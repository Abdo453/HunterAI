"""Subfinder Asset Coverage — Canonical Data Schemas (L2-L5 shared data model)"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
import time
import uuid
import hashlib


class SubfinderEvidenceLevel(str):
    E0 = "E0"
    E1 = "E1"


class SourceType(str):
    PASSIVE = "passive"
    ACTIVE = "active"
    CERTIFICATE = "certificate"
    DNS = "dns"


@dataclass
class SubfinderAssetRecord:
    record_id: str
    subdomain: str
    source: str
    source_type: str = SourceType.PASSIVE
    ip: Optional[str] = None
    cdn: bool = False
    evidence_level: str = SubfinderEvidenceLevel.E0
    captured_at: float = field(default_factory=time.time)
    source_tool: str = "subfinder"
    raw_json: Dict[str, Any] = field(default_factory=dict)
    validation_note: str = ""
    duplicate_group: Optional[str] = None

    def __post_init__(self):
        if not self.record_id:
            self.record_id = f"sf_{str(uuid.uuid4())[:10]}"

    @property
    def canonical_key(self) -> str:
        return self.subdomain.lower()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
