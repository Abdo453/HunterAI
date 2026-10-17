"""NetExec (nxc) — Canonical Data Schemas (L2-L5 shared data model)"""
from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


class NetExecEvidenceLevel(str):
    E0 = "E0"  # Raw netexec output — needs review
    E1 = "E1"  # Corroborated (valid credential / pwned marker)


@dataclass
class NetExecHostRecord:
    """سجل مضيف واحد من netexec (لكل بروتوكول)."""

    host: str
    protocol: str
    port: int
    hostname: Optional[str] = None
    domain: Optional[str] = None
    os_family: Optional[str] = None
    signing: Optional[bool] = None
    smbv1: Optional[bool] = None
    pwned: bool = False
    credentials_valid: bool = False
    username: Optional[str] = None
    message: Optional[str] = None
    evidence_level: str = NetExecEvidenceLevel.E0
    captured_at: float = field(default_factory=time.time)
    source_tool: str = "netexec"
    record_id: str = ""
    raw_line: str = ""

    def __post_init__(self) -> None:
        if not self.record_id:
            self.record_id = f"nxc_{uuid.uuid4().hex[:10]}"

    @property
    def canonical_key(self) -> str:
        return f"{self.protocol.lower()}://{self.host.lower()}:{self.port}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class NetExecProfile:
    """ملف موحد لمضيف بعد تحليل netexec + سياق إضافي."""

    host: str
    protocol: str
    domain: Optional[str] = None
    signing: Optional[bool] = None
    smbv1: Optional[bool] = None
    pwned: bool = False
    credentials_valid: bool = False
    confidence_score: float = 0.0
    confidence_label: str = "weak"
    evidence_level: str = NetExecEvidenceLevel.E0
    context_notes: List[str] = field(default_factory=list)
    adaptive_suggestions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
