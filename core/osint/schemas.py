"""OSINT Identity Subsystem — Canonical Data Schemas"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional
import time
import uuid
import hashlib


class OSINTVector(str, Enum):
    USERNAME = "username"
    EMAIL = "email"
    GITHUB = "github"
    DOMAIN = "domain"
    BREACH = "breach"


class EvidenceLevel(str, Enum):
    E0 = "E0"
    E1 = "E1"


class DetectionMethod(str, Enum):
    WEB_STATUS = "web_status"
    MOBILE_API = "mobile_api"
    PASSWORD_RESET = "password_reset"
    API_ENUMERATION = "api_enumeration"
    CROSS_SCAN = "cross_scan"


@dataclass
class IdentityEvidenceRecord:
    """N结果一条 从一工具一於一平台 — E0 总起 (实验室 E1 认证后)"""
    record_id: str
    vector: str
    platform: str
    query_value: str
    match_url: str
    detection_method: str
    raw_response_digest: str
    tool_name: str
    evidence_level: str = "E0"
    captured_at: float = field(default_factory=time.time)
    validation_note: str = ""
    corroborating_tools: List[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.record_id:
            self.record_id = f"ev_{str(uuid.uuid4())[:12]}"

    @property
    def canonical_key(self) -> str:
        """مفتاح التكرارية: المنصة + قيمة الاستفسار (نفس الهوية عبر أدوات متعددة)."""
        return f"{self.platform}:{self.query_value}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class IdentityCluster:
    """تجمع أدلة هوية متعددة لمنطقة واحدة، مع درجة الثقة المحسوبة."""
    cluster_id: str
    anchor: str
    members: List[IdentityEvidenceRecord] = field(default_factory=list)
    correlation_signals: Dict[str, float] = field(default_factory=dict)
    confidence: float = 0.0
    confidence_label: str = "weak"
    open_questions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ConfidenceLabel(str, Enum):
    WEAK = "weak"
    POSSIBLE = "possible"
    PROBABLE = "probable"
    STRONG = "strong"
