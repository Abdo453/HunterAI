"""SSLScan TLS Cipher & Protocol Intelligence — Canonical Data Schemas (L2-L5 shared data model)"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


class SSLEvidenceLevel(str):
    E0 = "E0"  # Raw sslscan output — needs review
    E1 = "E1"  # Corroborated / evidence sufficient


@dataclass
class SSLCipherRecord:
    """تشفير واحد من مخرجات sslscan."""

    name: str
    bits: Optional[int] = None
    used: bool = False
    export: bool = False
    anonymous: bool = False
    source_tool: str = "sslscan"
    record_id: str = ""

    def __post_init__(self) -> None:
        if not self.record_id:
            self.record_id = f"ssl_c_{uuid.uuid4().hex[:10]}"

    @property
    def canonical_key(self) -> str:
        return self.name.lower()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @property
    def is_weak(self) -> bool:
        weak_bits = self.bits is not None and self.bits < 128
        return self.export or self.anonymous or weak_bits


@dataclass
class SSLProtocolRecord:
    """بروتوكول TLS واحد (مفعل/معطل)."""

    version: str
    enabled: bool = False
    source_tool: str = "sslscan"
    record_id: str = ""

    def __post_init__(self) -> None:
        if not self.record_id:
            self.record_id = f"ssl_p_{uuid.uuid4().hex[:10]}"

    @property
    def canonical_key(self) -> str:
        return self.version.lower()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @property
    def is_legacy(self) -> bool:
        return self.version.strip() in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")


@dataclass
class SSLCertRecord:
    """شهادة TLS واحدة."""

    subject: Optional[str] = None
    issuer: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    sig_alg: Optional[str] = None
    source_tool: str = "sslscan"
    record_id: str = ""

    def __post_init__(self) -> None:
        if not self.record_id:
            self.record_id = f"ssl_x_{uuid.uuid4().hex[:10]}"

    @property
    def canonical_key(self) -> str:
        return f"{self.subject or ''}::{self.issuer or ''}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SSLAssetRecord:
    """سجل TLS موحد لمضيف:منفذ واحد من sslscan."""

    host: str
    port: int
    protocols: List[SSLProtocolRecord] = field(default_factory=list)
    ciphers: List[SSLCipherRecord] = field(default_factory=list)
    certificates: List[SSLCertRecord] = field(default_factory=list)
    heartbleed: bool = False
    poodle: bool = False
    evidence_level: str = SSLEvidenceLevel.E0
    captured_at: float = field(default_factory=time.time)
    source_tool: str = "sslscan"
    record_id: str = ""
    raw_xml: str = ""
    validation_note: str = ""

    def __post_init__(self) -> None:
        if not self.record_id:
            self.record_id = f"ssla_{uuid.uuid4().hex[:10]}"

    @property
    def canonical_key(self) -> str:
        return f"{self.host.lower()}:{self.port}"

    @property
    def enabled_protocols(self) -> List[str]:
        return [p.version for p in self.protocols if p.enabled]

    @property
    def weak_ciphers(self) -> List[str]:
        return [c.name for c in self.ciphers if c.is_weak]

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["protocols"] = [p.to_dict() for p in self.protocols]
        data["ciphers"] = [c.to_dict() for c in self.ciphers]
        data["certificates"] = [c.to_dict() for c in self.certificates]
        return data


@dataclass
class TLSConfigProfile:
    """ملف تكوين TLS موحد لمضيف بعد تحليل sslscan + سياق إضافي."""

    host: str
    port: int
    enabled_protocols: List[str] = field(default_factory=list)
    legacy_protocols: List[str] = field(default_factory=list)
    cipher_count: int = 0
    weak_cipher_count: int = 0
    heartbleed: bool = False
    poodle: bool = False
    confidence_score: float = 0.0
    confidence_label: str = "weak"
    evidence_level: str = SSLEvidenceLevel.E0
    context_notes: List[str] = field(default_factory=list)
    adaptive_suggestions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
