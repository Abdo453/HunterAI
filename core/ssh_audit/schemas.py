"""SSH-Audit Security Profiler — Canonical Data Schemas (L2-L5 shared data model)"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
import time
import uuid
import hashlib


class SSHAuditEvidenceLevel(str):
    E0 = "E0"      # Raw ssh-audit result — needs review
    E1 = "E1"      # Corroborated / evidence sufficient


@dataclass
class SSHAssetRecord:
    """سجل نتيجة واحد من ssh-audit موحد."""

    record_id: str
    host: str
    port: int
    banner: Optional[str] = None
    # right-side (web/audit) context carried from the raw tool output
    url: Optional[str] = None
    scheme: Optional[str] = None
    status_code: Optional[int] = None
    content_length: Optional[int] = None
    content_type: Optional[str] = None
    web_server: Optional[str] = None
    technologies: List[str] = field(default_factory=list)
    cdn: Optional[str] = None
    ip: Optional[str] = None
    cname: Optional[str] = None
    # SSH-specific algorithm lists
    kex_algorithms: List[str] = field(default_factory=list)
    server_host_key_algorithms: List[str] = field(default_factory=list)
    encryption_algorithms: List[str] = field(default_factory=list)
    mac_algorithms: List[str] = field(default_factory=list)
    compression_algorithms: List[str] = field(default_factory=list)
    issues: List[Dict[str, Any]] = field(default_factory=list)
    evidence_level: str = SSHAuditEvidenceLevel.E0
    evidence_status: str = "raw"
    confidence_score: float = 0.0
    captured_at: float = field(default_factory=time.time)
    source_tool: str = "ssh-audit"
    raw_json: Dict[str, Any] = field(default_factory=dict)
    validation_note: str = ""

    def __post_init__(self):
        if not self.record_id:
            self.record_id = f"ssh_{str(uuid.uuid4())[:10]}"

    @property
    def canonical_key(self) -> str:
        """مفتاح للتكرارات: host:port"""
        return f"{self.host.lower()}:{self.port}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SSHSecurityProfile:
    """ملف أمني موحد لخادم SSH بعد تحليل ssh-audit + سياق إضافي."""

    host: str
    port: int
    banner: Optional[str] = None
    # right-side (web/audit) context carried from the raw tool output
    url: Optional[str] = None
    scheme: Optional[str] = None
    status_code: Optional[int] = None
    content_length: Optional[int] = None
    content_type: Optional[str] = None
    web_server: Optional[str] = None
    technologies: List[str] = field(default_factory=list)
    cdn: Optional[str] = None
    ip: Optional[str] = None
    cname: Optional[str] = None
    # SSH algorithm counts
    kex_count: int = 0
    key_algorithms_count: int = 0
    encryption_count: int = 0
    mac_count: int = 0
    issues_count: int = 0
    critical_issues: int = 0
    high_issues: int = 0
    medium_issues: int = 0
    low_issues: int = 0
    info_issues: int = 0
    confidence_score: float = 0.0
    confidence_label: str = "weak"
    evidence_level: str = SSHAuditEvidenceLevel.E0
    is_outdated_ssh: bool = False
    context_notes: List[str] = field(default_factory=list)
    adaptive_suggestions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
