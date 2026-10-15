"""OSINT Identity Subsystem — Canonical Data Schemas"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Optional, Any
import time
import uuid
import hashlib
import json


class OSINTVector(str, Enum):
    USERNAME = "username"
    EMAIL = "email"
    GITHUB = "github"
    DOMAIN = "domain"
    BREACH = "breach"


class EvidenceLevel(str, Enum):
    E0 = "E0"
    E1 = "E1"


class ConfidenceLabel(str, Enum):
    WEAK = "weak"
    POSSIBLE = "possible"
    PROBABLE = "probable"
    STRONG = "strong"


class DetectionMethod(str, Enum):
    WEB_STATUS = "web_status"
    MOBILE_API = "mobile_api"
    PASSWORD_RESET = "password_reset"
    API_ENUMERATION = "api_enumeration"
    CROSS_SCAN = "cross_scan"


@dataclass
class IdentityEvidenceRecord:
    """نتيجة واحدة من أداة واحدة على منصة واحدة — E0 دائمًا (إلا إذا corroborated)."""
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
            self.record_id = str(uuid.uuid4())[:12]
        if not self.raw_response_digest:
            # hash من الـ match_url + tool + platform للتمييز
            self.raw_response_digest = hashlib.md5(
                f"{self.tool_name}:{self.platform}:{self.match_url}".encode()
            ).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IdentityEvidenceRecord":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    @property
    def canonical_key(self) -> str:
        """مفتاح للـ dedupe: platform + match_url المعياري"""
        return f"{self.platform.lower()}:{self.match_url.lower().rstrip('/')}"


@dataclass
class IdentityCluster:
    """مجموعة evidence مرتبطة بنفس الهوية الافتراضية."""
    cluster_id: str
    anchor: str
    members: List[IdentityEvidenceRecord]
    correlation_signals: Dict[str, float] = field(default_factory=dict)
    confidence: float = 0.0
    confidence_label: str = "weak"
    open_questions: List[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.cluster_id:
            self.cluster_id = f"cl_{str(uuid.uuid4())[:10]}"
        # حدّث الـ label من الـ confidence
        self.confidence_label = self._label_from_confidence(self.confidence)

    @staticmethod
    def _label_from_confidence(score: float) -> str:
        if score >= 0.75:
            return ConfidenceLabel.STRONG
        elif score >= 0.50:
            return ConfidenceLabel.PROBABLE
        elif score >= 0.25:
            return ConfidenceLabel.POSSIBLE
        return ConfidenceLabel.WEAK

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "anchor": self.anchor,
            "member_count": len(self.members),
            "members": [m.to_dict() for m in self.members],
            "correlation_signals": self.correlation_signals,
            "confidence": round(self.confidence, 3),
            "confidence_label": self.confidence_label,
            "open_questions": self.open_questions,
        }

    def to_finding_dict(self, severity: str = "Info") -> Dict[str, Any]:
        """تحويل لـ AgentResult finding format"""
        platforms = sorted(set(m.platform for m in self.members))
        tool_summary = {}
        for m in self.members:
            tool_summary.setdefault(m.platform, []).append(m.tool_name)

        evidence_text = (
            f"Anchor: {self.anchor}\n"
            f"Confidence: {self.confidence_label} ({self.confidence:.2f})\n"
            f"Platforms ({len(platforms)}): {', '.join(platforms)}\n\n"
            "Signals:\n" +
            "\n".join(f"  {k}: {v:+.2f}" for k, v in sorted(self.correlation_signals.items(), key=lambda x: -x[1])) +
            "\n\nOpen Questions:\n" +
            "\n".join(f"  - {q}" for q in self.open_questions) +
            "\n\nNote: This is OSINT evidence (E0/E1), NOT a confirmed finding."
        )

        return {
            "type": "identity_evidence",
            "severity": severity,
            "title": f"🔍 Identity Cluster: {self.anchor} ({self.confidence_label})",
            "evidence": evidence_text,
            "tool": "OSINTIdentityAgent",
            "recommendation": "Validate via active browser inspection before treating as confirmed identity link.",
            "confidence": self.confidence,
            "confidence_label": self.confidence_label,
            "cluster_id": self.cluster_id,
        }