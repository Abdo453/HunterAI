"""enum4linux-ng — Canonical Data Schemas (L2-L5 shared data model)"""
from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


class Enum4LinuxEvidenceLevel(str):
    E0 = "E0"  # Raw enum4linux-ng output — needs review
    E1 = "E1"  # Corroborated / evidence sufficient


@dataclass
class SMBShareRecord:
    """مشاركة SMB واحدة موحّدة."""

    host: str
    name: str
    access: Optional[str] = None
    comment: Optional[str] = None
    is_anonymous: bool = False
    evidence_level: str = Enum4LinuxEvidenceLevel.E0
    source_tool: str = "enum4linux-ng"
    record_id: str = ""

    def __post_init__(self) -> None:
        if not self.record_id:
            self.record_id = f"e4l_sh_{uuid.uuid4().hex[:10]}"

    @property
    def canonical_key(self) -> str:
        return f"{self.host.lower()}:{self.name.lower()}"

    @property
    def writable(self) -> bool:
        return "WRITE" in (self.access or "").upper()

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["writable"] = self.writable
        return data


@dataclass
class SMBUserRecord:
    """مستخدم واحد موحّد من تعداد SMB/RPC."""

    host: str
    username: str
    rid: Optional[int] = None
    full_name: Optional[str] = None
    description: Optional[str] = None
    groups: List[str] = field(default_factory=list)
    is_admin: bool = False
    evidence_level: str = Enum4LinuxEvidenceLevel.E0
    source_tool: str = "enum4linux-ng"
    record_id: str = ""

    def __post_init__(self) -> None:
        if not self.record_id:
            self.record_id = f"e4l_us_{uuid.uuid4().hex[:10]}"

    @property
    def canonical_key(self) -> str:
        return f"{self.host.lower()}:{(self.username or '').lower()}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Enum4LinuxAssetRecord:
    """سجل تعداد موحّد لمضيف واحد من enum4linux-ng."""

    host: str
    domain: Optional[str] = None
    netbios: Optional[str] = None
    os_info: Optional[str] = None
    is_dc: bool = False
    anonymous_access: bool = False
    users: List[SMBUserRecord] = field(default_factory=list)
    shares: List[SMBShareRecord] = field(default_factory=list)
    groups: Dict[str, Any] = field(default_factory=dict)
    policy: Dict[str, Any] = field(default_factory=dict)
    evidence_level: str = Enum4LinuxEvidenceLevel.E0
    captured_at: float = field(default_factory=time.time)
    source_tool: str = "enum4linux-ng"
    record_id: str = ""
    raw_json: Dict[str, Any] = field(default_factory=dict)
    validation_note: str = ""

    def __post_init__(self) -> None:
        if not self.record_id:
            self.record_id = f"e4l_{uuid.uuid4().hex[:10]}"

    @property
    def canonical_key(self) -> str:
        return self.host.lower()

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["users"] = [u.to_dict() for u in self.users]
        data["shares"] = [s.to_dict() for s in self.shares]
        return data


@dataclass
class ADHostProfile:
    """ملف موحّد لمضيف بعد تحليل enum4linux-ng + سياق إضافي."""

    host: str
    domain: Optional[str] = None
    is_dc: bool = False
    anonymous_access: bool = False
    user_count: int = 0
    share_count: int = 0
    writable_shares: int = 0
    confidence_score: float = 0.0
    confidence_label: str = "weak"
    evidence_level: str = Enum4LinuxEvidenceLevel.E0
    context_notes: List[str] = field(default_factory=list)
    adaptive_suggestions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
