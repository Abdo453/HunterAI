"""Trivy Dependency Risk Analyzer — Canonical Data Schemas"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
import time
import uuid
import hashlib


class TrivyEvidenceLevel(str):
    E0 = "E0"
    E1 = "E1"


@dataclass
class TrivyVulnerabilityRecord:
    record_id: str
    vulnerability_id: str
    package_name: str
    installed_version: str
    fixed_version: Optional[str]
    severity: str
    title: str
    evidence_level: str = TrivyEvidenceLevel.E0
    captured_at: float = field(default_factory=time.time)
    source_tool: str = "trivy"
    raw_json: Dict[str, Any] = field(default_factory=dict)
    validation_note: str = ""

    def __post_init__(self):
        if not self.record_id:
            self.record_id = f"tr_{str(uuid.uuid4())[:10]}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DependencyRiskProfile:
    vulnerability_id: str
    package_name: str
    installed_version: str
    fixed_version: Optional[str]
    severity: str
    title: str
    confidence_score: float
    confidence_label: str
    evidence_level: str
    is_critical: bool = False
    context_notes: List[str] = field(default_factory=list)
    adaptive_suggestions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
