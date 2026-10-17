"""WhatWeb Technology Fingerprinting — Canonical Data Schemas (L2-L5 shared data model)"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


class WhatWebEvidenceLevel(str):
    E0 = "E0"  # Raw whatweb plugin output — needs review
    E1 = "E1"  # Corroborated / evidence sufficient


@dataclass
class WhatWebPluginRecord:
    """بصمة تقنية واحدة من إضافة whatweb واحدة."""

    name: str
    version: Optional[str] = None
    category: Optional[str] = None  # e.g. "CMS", "Web Server", "JavaScript Library"
    confidence: Optional[int] = None  # whatweb confidence 0-100
    evidence: List[str] = field(default_factory=list)
    url: Optional[str] = None
    source_tool: str = "whatweb"
    record_id: str = ""

    def __post_init__(self) -> None:
        if not self.record_id:
            self.record_id = f"ww_{uuid.uuid4().hex[:10]}"

    @property
    def canonical_key(self) -> str:
        return f"{(self.url or '').lower()}::{self.name.lower()}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class WhatWebAssetRecord:
    """سجل بصمة موحد لهدف واحد من whatweb."""

    target: str
    url: str
    http_status: Optional[int] = None
    server: Optional[str] = None
    plugins: List[WhatWebPluginRecord] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    evidence_level: str = WhatWebEvidenceLevel.E0
    captured_at: float = field(default_factory=time.time)
    source_tool: str = "whatweb"
    record_id: str = ""
    raw_json: Dict[str, Any] = field(default_factory=dict)
    validation_note: str = ""

    def __post_init__(self) -> None:
        if not self.record_id:
            self.record_id = f"wwa_{uuid.uuid4().hex[:10]}"

    @property
    def canonical_key(self) -> str:
        return self.url.lower()

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["plugins"] = [p.to_dict() for p in self.plugins]
        return data


@dataclass
class TechFingerprintProfile:
    """ملف بصمة موحد لهدف بعد تحليل whatweb + سياق إضافي."""

    target: str
    url: str
    http_status: Optional[int] = None
    server: Optional[str] = None
    plugin_count: int = 0
    technology_count: int = 0
    cms_detected: bool = False
    web_server_detected: bool = False
    javascript_libraries: List[str] = field(default_factory=list)
    confidence_score: float = 0.0
    confidence_label: str = "weak"
    evidence_level: str = WhatWebEvidenceLevel.E0
    context_notes: List[str] = field(default_factory=list)
    adaptive_suggestions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
