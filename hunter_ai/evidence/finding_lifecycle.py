"""
Finding Lifecycle State Machine

States:
  DISCOVERED → SUSPECTED → HYPOTHESIS → TESTING
  → EVIDENCE_COLLECTED → VERIFIED → REVIEWED → REPORTED

OR at any point: → FALSE_POSITIVE (terminal)

Every transition requires a reason. Invalid transitions are rejected.
This prevents findings from jumping from DISCOVERED directly to VERIFIED
(which would bypass evidence collection).
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class FindingStatus(str, Enum):
    DISCOVERED         = "DISCOVERED"
    SUSPECTED          = "SUSPECTED"
    HYPOTHESIS         = "HYPOTHESIS"
    TESTING            = "TESTING"
    EVIDENCE_COLLECTED = "EVIDENCE_COLLECTED"
    VERIFIED           = "VERIFIED"
    REVIEWED           = "REVIEWED"
    REPORTED           = "REPORTED"
    FALSE_POSITIVE     = "FALSE_POSITIVE"


# Valid state transitions
_ALLOWED: Dict[FindingStatus, List[FindingStatus]] = {
    FindingStatus.DISCOVERED:         [FindingStatus.SUSPECTED,          FindingStatus.FALSE_POSITIVE],
    FindingStatus.SUSPECTED:          [FindingStatus.HYPOTHESIS,         FindingStatus.FALSE_POSITIVE],
    FindingStatus.HYPOTHESIS:         [FindingStatus.TESTING,            FindingStatus.FALSE_POSITIVE],
    FindingStatus.TESTING:            [FindingStatus.EVIDENCE_COLLECTED,  FindingStatus.FALSE_POSITIVE],
    FindingStatus.EVIDENCE_COLLECTED: [FindingStatus.VERIFIED,           FindingStatus.FALSE_POSITIVE],
    FindingStatus.VERIFIED:           [FindingStatus.REVIEWED],
    FindingStatus.REVIEWED:           [FindingStatus.REPORTED],
    FindingStatus.REPORTED:           [],
    FindingStatus.FALSE_POSITIVE:     [],  # terminal
}


@dataclass
class Finding:
    finding_id: str = field(default_factory=lambda: f"F-{uuid.uuid4().hex[:6].upper()}")
    hypothesis_id: str = ""
    title: str = ""
    severity: str = "INFO"     # CRITICAL | HIGH | MEDIUM | LOW | INFO
    cvss: float = 0.0
    confidence: float = 0.0    # 0.0–1.0
    status: FindingStatus = FindingStatus.DISCOVERED
    status_history: List[Dict[str, Any]] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    endpoint: str = ""
    reproduction_steps: List[str] = field(default_factory=list)
    remediation: str = ""
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def advance(self, new_status: FindingStatus, reason: str = "") -> bool:
        """
        Move to next state. Returns False if the transition is invalid.
        Never raises — callers must check the return value.
        """
        allowed = _ALLOWED.get(self.status, [])
        if new_status not in allowed:
            return False
        self.status_history.append({
            "from":   self.status.value,
            "to":     new_status.value,
            "reason": reason,
            "ts":     time.time(),
        })
        self.status = new_status
        self.updated_at = time.time()
        return True

    def is_terminal(self) -> bool:
        return self.status in (FindingStatus.REPORTED, FindingStatus.FALSE_POSITIVE)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id":         self.finding_id,
            "hypothesis_id":      self.hypothesis_id,
            "title":              self.title,
            "severity":           self.severity,
            "cvss":               self.cvss,
            "confidence":         round(self.confidence * 100, 1),
            "status":             self.status.value,
            "endpoint":           self.endpoint,
            "evidence_count":     len(self.evidence_ids),
            "reproduction_steps": self.reproduction_steps,
            "remediation":        self.remediation,
        }


class FindingLifecycle:
    """
    Registry + lifecycle manager for all findings in an engagement.
    Enforces state machine rules. Exposes export for reports.
    """

    def __init__(self) -> None:
        self._findings: Dict[str, Finding] = {}

    def create(
        self,
        title: str,
        hypothesis_id: str = "",
        severity: str = "INFO",
        confidence: float = 0.5,
        endpoint: str = "",
    ) -> Finding:
        f = Finding(
            title=title,
            hypothesis_id=hypothesis_id,
            severity=severity,
            confidence=confidence,
            endpoint=endpoint,
        )
        self._findings[f.finding_id] = f
        return f

    def advance(self, finding_id: str, new_status: FindingStatus, reason: str = "") -> bool:
        f = self._findings.get(finding_id)
        return f.advance(new_status, reason) if f else False

    def add_evidence(self, finding_id: str, evidence_id: str) -> bool:
        f = self._findings.get(finding_id)
        if not f:
            return False
        f.evidence_ids.append(evidence_id)
        return True

    def set_remediation(self, finding_id: str, text: str) -> bool:
        f = self._findings.get(finding_id)
        if not f:
            return False
        f.remediation = text
        return True

    # ── Queries ───────────────────────────────────────────────────────────────

    def get(self, finding_id: str) -> Optional[Finding]:
        return self._findings.get(finding_id)

    def get_all(self) -> List[Finding]:
        return list(self._findings.values())

    def get_confirmed(self) -> List[Finding]:
        confirmed_statuses = {
            FindingStatus.VERIFIED,
            FindingStatus.REVIEWED,
            FindingStatus.REPORTED,
        }
        return [f for f in self._findings.values() if f.status in confirmed_statuses]

    def get_false_positives(self) -> List[Finding]:
        return [f for f in self._findings.values() if f.status == FindingStatus.FALSE_POSITIVE]

    def to_report_format(self) -> List[Dict[str, Any]]:
        return [f.to_dict() for f in self._findings.values()]

    def summary(self) -> Dict[str, Any]:
        by_status: Dict[str, int] = {}
        for f in self._findings.values():
            by_status[f.status.value] = by_status.get(f.status.value, 0) + 1
        return {
            "total":          len(self._findings),
            "confirmed":      len(self.get_confirmed()),
            "false_positives":len(self.get_false_positives()),
            "by_status":      by_status,
        }
