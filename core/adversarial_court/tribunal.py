"""
HunterAI Adversarial Evidence Court (المحكمة विरोधية للأدلة)
مقتبس من فكرة HunterAI Architecture: Finder → Advocate → Adversarial Prosecutor → Verifier → Justice

المبدأ: لا نتيجة تُبلَغ كـ Confirmed إلا بعد اجتياز محاكمة من خمسة أدوار:
1. Finder — يكتشف الدليل الأولي
2. Advocate — يدافع عن الدليل ويجمع الأدلة المؤيدة
3. Adversarial Prosecutor — يتحدى الدليل ويبحث عن الثغرات في الاستدلال
4. Verifier — يتحقق من إعادة الإنتاج والاستقلالية
5. Justice — يصدر الحكم النهائي (Confirmed / Rejected / Inconclusive)
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum

log = logging.getLogger("hunter_ai.evidence_court")


class Verdict(str, Enum):
    CONFIRMED = "confirmed"      # أثبتت الأدلة بعد المحاكمة
    REJECTED = "rejected"        # دحضت الأدلة أو كاذبة
    INCONCLUSIVE = "inconclusive" # غير حاسمة — تحتاج تحقيق يدوي
    ESCALATED = "escalated"      # أُحيلت لمراجعة بشرية


@dataclass
class CourtEvidence:
    """قطعة أدلة واحدة تُعرض على المحكمة"""
    evidence_id: str
    source: str                  # أي أداة اكتشفتها (nuclei, sherlock, ...)
    type: str                    # username_match, open_port, sqli_indicator, ...
    description: str
    confidence: float            # 0.0 → 1.0
    raw_data: Dict[str, Any] = field(default_factory=dict)
    captured_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "evidence_id": self.evidence_id,
            "source": self.source,
            "type": self.type,
            "description": self.description,
            "confidence": self.confidence,
            "raw_data": self.raw_data,
            "captured_at": self.captured_at,
        }


@dataclass
class CourtArgument:
    """حجة من أحد الأدوار في المحكمة"""
    role: str                    # finder, advocate, prosecutor, verifier, justice
    argument: str
    supporting_evidence: List[str] = field(default_factory=list)
    confidence_delta: float = 0.0  # كم تغيرت الثقة بسبب هذه الحجة
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "role": self.role,
            "argument": self.argument,
            "supporting_evidence": self.supporting_evidence,
            "confidence_delta": self.confidence_delta,
            "timestamp": self.timestamp,
        }


@dataclass
class CourtCase:
    """قضية واحدة تمثل نتيجة أمنية واحدة تُعرض على المحكمة"""
    case_id: str
    finding_type: str
    target: str
    evidence: List[CourtEvidence] = field(default_factory=list)
    arguments: List[CourtArgument] = field(default_factory=list)
    verdict: str = Verdict.INCONCLUSIVE
    final_confidence: float = 0.0
    reasoning_summary: str = ""
    requires_manual_review: bool = False
    created_at: float = field(default_factory=time.time)
    concluded_at: Optional[float] = None

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "finding_type": self.finding_type,
            "target": self.target,
            "evidence": [e.to_dict() for e in self.evidence],
            "arguments": [a.to_dict() for a in self.arguments],
            "verdict": self.verdict,
            "final_confidence": round(self.final_confidence, 3),
            "reasoning_summary": self.reasoning_summary,
            "requires_manual_review": self.requires_manual_review,
            "created_at": self.created_at,
            "concluded_at": self.concluded_at,
        }


class EvidenceCourt:
    """
    محكمة الأدلة विरोधية — تصدر أحكامًا على النتائج الأمنية قبل الإبلاغ عنها.
    كل نتيجة تمر عبر خمسة أدوار قبل أن تُصنف كـ Confirmed.
    """

    def __init__(self):
        self.cases: Dict[str, CourtCase] = {}
        self.verdict_history: List[CourtCase] = []

    # ── واجهة رئيسية ──────────────────────────────────────────────

    async def try_case(
        self,
        case_id: str,
        finding_type: str,
        target: str,
        evidence: List[CourtEvidence],
        initial_confidence: float = 0.5,
    ) -> CourtCase:
        """
        محاكمة قضية واحدة عبر الأدوار الخمسة.
        يرجع CourtCase مع الحكم النهائي.
        """
        case = CourtCase(
            case_id=case_id,
            finding_type=finding_type,
            target=target,
            evidence=evidence,
            verdict=Verdict.INCONCLUSIVE,
            final_confidence=initial_confidence,
        )

        # 역할 1: Finder — تقديم الدليل الأولي
        case.arguments.append(CourtArgument(
            role="finder",
            argument=f"تم اكتشاف {finding_type} على {target} من خلال أداة OSINT/سكانر أولية",
            supporting_evidence=[e.evidence_id for e in evidence],
            confidence_delta=0.0,
        ))

        # 역할 2: Advocate — الدفاع عن الدليل
        advocate_conf = self._advocate_role(case)
        case.final_confidence = advocate_conf

        # 역할 3: Adversarial Prosecutor — التحدي والبحث عن ثغرات
        prosecutor_conf = self._prosecutor_role(case)
        case.final_confidence = prosecutor_conf

        # 역할 4: Verifier — التحقق من إعادة الإنتاج والاستقلالية
        verifier_conf = self._verifier_role(case)
        case.final_confidence = verifier_conf

        # 역할 5: Justice — الحكم النهائي
        verdict, requires_manual = self._justice_role(case)
        case.verdict = verdict
        case.requires_manual_review = requires_manual
        case.concluded_at = time.time()

        self.cases[case_id] = case
        self.verdict_history.append(case)

        log.info(
            f"[EvidenceCourt] Case {case_id}: {verdict.value} "
            f"(confidence={case.final_confidence:.2f}, manual_review={requires_manual})"
        )
        return case

    # ── الأدوار الخمسة ────────────────────────────────────────────

    def _advocate_role(self, case: CourtCase) -> float:
        """المدافع — يبحث عن أدلة مؤيدة ويقوي القضية"""
        conf = case.final_confidence
        supporting = sum(1 for e in case.evidence if e.confidence > 0.6)
        if supporting >= 2:
            conf += 0.15
            case.arguments.append(CourtArgument(
                role="advocate",
                argument=f"دعمت القضية {supporting} أدلة عالية الثقة، مما يزيد من مصداقية الاكتشاف",
                supporting_evidence=[e.evidence_id for e in case.evidence if e.confidence > 0.6],
                confidence_delta=+0.15,
            ))
        else:
            case.arguments.append(CourtArgument(
                role="advocate",
                argument="أدلة محدودة — لا يمكن تعزيز الثقة بشكل كبير",
                confidence_delta=0.0,
            ))
        return min(conf, 1.0)

    def _prosecutor_role(self, case: CourtCase) -> float:
        """المدعي العام المعارض — يتحدى الدليل ويبحث عن تناقضات"""
        conf = case.final_confidence
        penalties = 0.0

        # إذا كان المصدر أداة واحدة فقط → خصم
        sources = {e.source for e in case.evidence}
        if len(sources) == 1:
            penalties += 0.20
            case.arguments.append(CourtArgument(
                role="prosecutor",
                argument="المصدر الوحيد للأدلة — قد يكون نتيجة كاذبة (False Positive) من أداة واحدة",
                confidence_delta=-0.20,
            ))

        # إذا كانت الثقة الأولية منخفضة → خصم
        if case.final_confidence < 0.4:
            penalties += 0.15
            case.arguments.append(CourtArgument(
                role="prosecutor",
                argument="ثقة أولية منخفضة — الاكتشاف غير مؤكد",
                confidence_delta=-0.15,
            ))

        # إذا لم تكن هناك أدلة corroborating → خصم
        corroborating = [e for e in case.evidence if e.type == "corroboration"]
        if not corroborating:
            penalties += 0.10
            case.arguments.append(CourtArgument(
                role="prosecutor",
                argument="لا توجد أدلة مصادقة (corroboration) مستقلة",
                confidence_delta=-0.10,
            ))

        case.final_confidence = max(conf - penalties, 0.0)
        return case.final_confidence

    def _verifier_role(self, case: CourtCase) -> float:
        """المدقق — يتحقق من إمكانية إعادة الإنتاج والاستقلالية"""
        conf = case.final_confidence

        # إذا كان هناك أدلة من مصادر متعددة → زيادة الثقة
        sources = {e.source for e in case.evidence}
        if len(sources) >= 2:
            conf += 0.10
            case.arguments.append(CourtArgument(
                role="verifier",
                argument=f"أُكدت النتيجة من {len(sources)} مصادر مختلفة — زيادة الموثوقية",
                confidence_delta=+0.10,
            ))

        # إذا كانت هناك أدلة من نوع E1 (مؤكدة) → زيادة
        e1_count = sum(1 for e in case.evidence if "E1" in str(e.raw_data.get("evidence_level", "")))
        if e1_count > 0:
            conf += 0.10
            case.arguments.append(CourtArgument(
                role="verifier",
                argument=f"يوجد {e1_count} أدلة على مستوى E1 (مؤكدة) — 강화 الثقة",
                confidence_delta=+0.10,
            ))

        case.final_confidence = min(conf, 1.0)
        return case.final_confidence

    def _justice_role(self, case: CourtCase) -> tuple:
        """القاضي — يصدر الحكم النهائي"""
        conf = case.final_confidence

        if conf >= 0.75:
            return Verdict.CONFIRMED, False
        elif conf >= 0.40:
            return Verdict.INCONCLUSIVE, True  # تحتاج مراجعة يدوية
        else:
            return Verdict.REJECTED, False

    # ── استرجاع النتائج ──────────────────────────────────────────

    def get_confirmed_cases(self) -> List[CourtCase]:
        return [c for c in self.cases.values() if c.verdict == Verdict.CONFIRMED]

    def get_manual_review_queue(self) -> List[CourtCase]:
        return [c for c in self.cases.values() if c.requires_manual_review]

    def get_rejected_cases(self) -> List[CourtCase]:
        return [c for c in self.cases.values() if c.verdict == Verdict.REJECTED]

    def get_all_cases(self) -> List[CourtCase]:
        return list(self.cases.values())

    def clear(self):
        self.cases.clear()
        self.verdict_history.clear()


# مثيل افتراضي يمكن استخدامه في toda the system
evidence_court = EvidenceCourt()
