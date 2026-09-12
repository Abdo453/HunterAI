"""
Base Skill Interface for PentestAI-Unified
==========================================
Standardized interface for all autonomous vulnerability skills.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Any


class SkillState(Enum):
    IDLE       = auto()
    DETECT     = auto()
    EXPLOIT    = auto()
    VERIFY     = auto()
    FALLBACK   = auto()
    COMPLETE   = auto()
    FAILED     = auto()


@dataclass
class SkillResult:
    verified: bool = False
    vuln_type: str = "unknown"
    title: str = ""
    severity: str = "Info"
    endpoint: str = ""
    param_name: str = ""
    evidence: str = ""
    payload_used: str = ""
    remediation: str = ""
    confidence: float = 0.0
    tool: str = "BaseSkill"
    evidence_sources: List[str] = field(default_factory=list)
    cwe: str = "CWE-000"
    owasp_top10: str = "A00:2021"
    fallback_used: bool = False
    fallback_engine: Optional[str] = None
    fallback_details: Optional[str] = None
    logs: List[str] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "verified": self.verified,
            "type": self.vuln_type,
            "vuln_type": self.vuln_type,
            "title": self.title,
            "severity": self.severity,
            "endpoint": self.endpoint,
            "param_name": self.param_name,
            "evidence": self.evidence,
            "payload_used": self.payload_used,
            "remediation": self.remediation,
            "confidence": self.confidence,
            "tool": self.tool,
            "evidence_sources": self.evidence_sources,
            "cwe": self.cwe,
            "owasp_top10": self.owasp_top10,
            "fallback_used": self.fallback_used,
            "fallback_engine": self.fallback_engine,
            "fallback_details": self.fallback_details,
            "logs": self.logs,
        }
        d.update(self.extra)
        return d


class BaseSkill(ABC):
    name: str = "base_skill"
    vuln_type: str = "generic"
    cwe: str = "CWE-000"
    owasp_top10: str = "A00:2021"
    default_severity: str = "Medium"

    def __init__(self, proxy: Optional[str] = None, timeout: float = 12.0):
        self.proxy = proxy
        self.timeout = timeout

    @abstractmethod
    async def run(
        self,
        target_url: str,
        param_name: str,
        **kwargs
    ) -> SkillResult:
        """Run autonomous detection and verification loop"""
        pass

    async def fallback(
        self,
        target_url: str,
        param_name: str,
        **kwargs
    ) -> Optional[SkillResult]:
        """Optional fallback method invoking external CLI tools (sqlmap, dalfox, etc.)"""
        return None

    def can_handle(self, param_name: str, url: str = "", sample_value: str = "") -> float:
        """Return heuristic suitability score between 0.0 and 1.0"""
        return 0.5
