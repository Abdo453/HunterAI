"""
Network Court Adjudicator — Phase 5 (Court / Reports)

يُغذّي كل اكتشاف شبكة/AD/لاسلكي/إنترنت أشياء/OT (NetworkFinding) عبر
:class:`~core.evidence_court.EvidenceCourt` ليُصدر حكمًا نهائيًا.

القاعدة الجوهرية (Creed): لا اكتشاف يُؤكد تلقائيًا. يُدرج في التقرير النهائي
فقط ما يحكم به القضاء كـ ``CONFIRMED`` مع ``proof_strength == "DERIVED"``
(أثر فعلي قابل لإعادة التقييم). كل ما دون ذلك يبقى ``candidate`` / ``unverified``
ويُذكر في التقرير كـ "مستغرق للتحقق" وليس كثغرة مؤكدة.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.evidence_court import CourtVerdict, EvidenceCourt
from core.network_model import NetworkFinding

log = logging.getLogger("network_court_adjudicator")


@dataclass
class CourtAdjudicationResult:
    """نتيجة تحكيم اكتشاف واحد في محكمة الأدلة."""

    finding_id: str
    title: str
    host: str
    port: Optional[int]
    protocol: str
    vuln_class: str
    severity: str
    verdict: str  # CONFIRMED | UNVERIFIED | INCONCLUSIVE | FALSE_POSITIVE | ...
    reportable: bool
    proof_strength: str
    epistemic_state: str
    confidence: float
    rationale: str
    court_judgment_id: str
    evidence_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "vuln_class": self.vuln_class,
            "severity": self.severity,
            "verdict": self.verdict,
            "reportable": self.reportable,
            "proof_strength": self.proof_strength,
            "epistemic_state": self.epistemic_state,
            "confidence": self.confidence,
            "rationale": self.rationale,
            "court_judgment_id": self.court_judgment_id,
            "evidence_ids": list(self.evidence_ids),
        }


@dataclass
class NegativeSpaceEntry:
    """نقطة هجوم حُذفت من النطاق مع السبب (مساحة سلبية)."""

    host: str
    port: Optional[int]
    protocol: str
    reason: str  # SKIPPED_SCOPE | OUT_OF_SCOPE | TOOL_MISSING | ...
    detail: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "reason": self.reason,
            "detail": self.detail,
        }


@dataclass
class NetworkCourtReport:
    """تقرير محاكمة شبكة كامل: مؤكد + غير مؤكد + مساحة سلبية."""

    target: str
    total_findings: int
    confirmed_findings: int = 0
    unconfirmed_findings: int = 0
    false_positives: int = 0
    negative_space_entries: int = 0
    confirmed: List[CourtAdjudicationResult] = field(default_factory=list)
    unconfirmed: List[CourtAdjudicationResult] = field(default_factory=list)
    false_positive_list: List[CourtAdjudicationResult] = field(default_factory=list)
    negative_space: List[NegativeSpaceEntry] = field(default_factory=list)
    generated_at: float = field(default_factory=lambda: __import__("time").time())

    @property
    def confirmation_rate(self) -> float:
        if self.total_findings == 0:
            return 0.0
        return round(self.confirmed_findings / self.total_findings * 100, 2)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "total_findings": self.total_findings,
            "confirmed_findings": self.confirmed_findings,
            "unconfirmed_findings": self.unconfirmed_findings,
            "false_positives": self.false_positives,
            "negative_space_entries": self.negative_space_entries,
            "confirmation_rate": self.confirmation_rate,
            "generated_at": self.generated_at,
            "confirmed": [r.to_dict() for r in self.confirmed],
            "unconfirmed": [r.to_dict() for r in self.unconfirmed],
            "false_positives": [r.to_dict() for r in self.false_positive_list],
            "negative_space": [e.to_dict() for e in self.negative_space],
        }


# ── Court Adjudicator ─────────────────────────────────────────────────────────


class NetworkCourtAdjudicator:
    """
    يُحاكم نتائج الشبكة في محكمة الأدلة ويصنفها إلى:
      * Confirmed (DERIVED proof) → يُدرج في التقرير النهائي
      * Unconfirmed (UNVERIFIED/INCONCLUSIVE) → يُذكر كمستغرق للتحقق
      * False Positives → يُستبعد مع السبب
    """

    def __init__(self, is_in_scope: bool = True, allow_declared_proof: bool = False):
        self.is_in_scope = is_in_scope
        self.allow_declared_proof = allow_declared_proof

    def adjudicate(
        self,
        findings: List[NetworkFinding],
        target: str = "",
    ) -> NetworkCourtReport:
        """
        يُحاكم قائمة من الاكتشافات ويعيد تقرير محكمة كامل.
        """
        report = NetworkCourtReport(target=target, total_findings=len(findings))

        for finding in findings:
            result = self._adjudicate_one(finding)
            if result.verdict == CourtVerdict.CONFIRMED.value:
                report.confirmed.append(result)
                report.confirmed_findings += 1
            elif result.verdict == CourtVerdict.FALSE_POSITIVE.value:
                report.false_positive_list.append(result)
                report.false_positives += 1
            else:
                report.unconfirmed.append(result)
                report.unconfirmed_findings += 1

        report.negative_space = []
        return report

    def add_negative_space(
        self,
        report: NetworkCourtReport,
        entries: List[NegativeSpaceEntry],
    ) -> None:
        """يُضيف إدخالات مساحة سلبية إلى التقرير."""
        report.negative_space.extend(entries)
        report.negative_space_entries = len(report.negative_space)

    # ── internals ─────────────────────────────────────────────────────────────
    def _adjudicate_one(self, finding: NetworkFinding) -> CourtAdjudicationResult:
        target_url = (
            f"{finding.protocol}://{finding.host}:{finding.port}"
            if finding.port
            else f"{finding.protocol}://{finding.host}"
        )

        # preuve nulle: لا إثبات فعلي للاكتشافات الشبكية الخام — حكم القضاء سيكون
        # UNVERIFIED / INCONCLUSIVE ما لم يُزود caller بـ proof_payload لاحقًا.
        judgment = EvidenceCourt.adjudicate(
            target_url=target_url,
            parameter="",
            vuln_class=finding.vuln_class,
            finder_claim={
                "title": finding.title,
                "description": finding.description,
                "reproduction_command": finding.reproduction_command,
                "remediation": finding.remediation,
                "source_tool": "network_pipeline",
            },
            verifier_result={},  # لا مدقق مستقل → لا إثبات
            proof_payload=None,  # لا ProofPayload → DECLARED فقط إن وُجد → لا يؤكد
            is_in_scope=self.is_in_scope,
            allow_declared_proof=self.allow_declared_proof,
        )

        return CourtAdjudicationResult(
            finding_id=finding.finding_id,
            title=finding.title,
            host=finding.host,
            port=finding.port,
            protocol=finding.protocol,
            vuln_class=finding.vuln_class,
            severity=finding.severity,
            verdict=judgment.verdict.value,
            reportable=judgment.reportable,
            proof_strength=judgment.proof_strength,
            epistemic_state=judgment.epistemic_state,
            confidence=finding.confidence,
            rationale=judgment.adjudication_rationale,
            court_judgment_id=judgment.judgment_id,
            evidence_ids=list(finding.evidence_ids),
        )


# ── convenience: adapt NetworkFinding → CourtAdjudicationResult dicts ─────────


def adjudicate_findings(
    findings: List[NetworkFinding],
    target: str = "",
    is_in_scope: bool = True,
) -> List[Dict[str, Any]]:
    """دالة مساعدة تُحاكم قائمة discoveries وتعيد القاموس الجاهز للتقرير."""
    court = NetworkCourtAdjudicator(is_in_scope=is_in_scope)
    report = court.adjudicate(findings, target=target)
    return report.to_dict()
