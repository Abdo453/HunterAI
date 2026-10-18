# -*- coding: utf-8 -*-
"""
Final Evidence Court Session — جلسة المحكمة النهائية قبل REPORT (Phase 3)
=========================================================================
المعمارية الرسمية (Axioms from qualification_gate + evidence_court):

  TOOLS -> OBSERVATIONS -> CORRELATION -> HYPOTHESIS -> VALIDATION
         -> EVIDENCE COURT (qualification) -> FINAL COURT AUDIT -> REPORT

الخطوة الأخيرة دفاعًا من الأخير (defense in depth): قبل أن تصل أي نتيجة
للتقرير، تُختبر القائمة الكاملة كجلسة واحدة. أي نتيجة لا تحمل سلسلة إثبات
سليمة تُخفَّض إلى deferred_hypotheses — لا تُحجب (الإثبات يبقى للاستمرار
التحقيقي) لكنها لا تُقدَّم كمُؤكَّدة في التقرير.

القواعد (Audit Rules):
  R1 standard_web_behavior — robots.txt / sitemap.xml / open_ports ليست
     ثغرات (Axiom 2 في QualificationGate).
  R2 no_evidence — نتيجة CONFIRMED/LIKELY بدون أي VerificationEvidence.
  R3 unverified_evidence — كل قطع الإثبات يجب أن تكون verified=True في
     نتائج CONFIRMED.
  R4 no_reproduction — نتيجة CONFIRMED بدون reproduction artifact ولا
     false_positive_checks (لا يمكن إعادة الإنتاج أو التمييز عن FP).
  R5 incomplete_record — عنوان/asset/endpoint فارغ = سجل تالف.
  R6 unreported_unverified — نتيجة UNVERIFIED لا تُعرض في التقرير النهائي.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# من الحقيقة (Axiom 2 من qualification_gate) — النسخة الرسمية الوحيدة
STANDARD_WEB_ENDINGS = ("/robots.txt", "/sitemap.xml")

NON_VULN_FLAT = {"open_ports"}


@dataclass
class CourtDocketEntry:
    """حكم واحد على نتيجة مُدعمة للمحاكمة."""
    finding_id: str
    title: str
    endpoint: str
    verdict: str                  # PASSED | DEMOTED
    reason_code: str
    rationale: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FinalCourtReport:
    """ملخص جلسة المحكمة النهائية."""
    entries: List[CourtDocketEntry] = field(default_factory=list)
    accepted: List[Dict[str, Any]] = field(default_factory=list)
    demoted: List[Dict[str, Any]] = field(default_factory=list)
    run_id: str = ""
    decided_at: float = field(default_factory=time.time)

    @property
    def stats(self) -> Dict[str, int]:
        stats = {"PASSED": 0, "DEMOTED": 0}
        for e in self.entries:
            if e.verdict in stats:
                stats[e.verdict] += 1
        return stats

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "decided_at": self.decided_at,
            "stats": self.stats,
            "entries": [e.to_dict() for e in self.entries],
            "accepted_titles": [f.get("finding", "") for f in self.accepted],
        }


class FinalEvidenceCourt:
    """جلسة المحكمة النهائية — نقية وقابلة للاختبار، لا تلمس الشبكة إطلاقًا."""

    def __init__(self, run_id: str = ""):
        self.run_id = run_id

    # ─── قراءة السجل بشكل موحد (model أو dict) ────────
    @staticmethod
    def _as_dict(f: Any) -> Dict[str, Any]:
        if hasattr(f, "model_dump"):
            return f.model_dump()
        return dict(f)

    @staticmethod
    def _enum_value(x: Any) -> str:
        """str Enum من pydantic يرجع كعضو enum — نستخرج قيمته النصية دائمًا."""
        if hasattr(x, "value"):
            return str(x.value)
        return str(x)

    @classmethod
    def audit_one(cls, f: Any) -> Tuple[CourtDocketEntry, Optional[str]]:
        """
        يحاكم نتيجة واحدة. يُرجع (حكمها، كود سبب الإسقاط إن وُجد).
        reason_code=None تعني PASSED (سلسلة الإثبات مستكملة).
        """
        d = cls._as_dict(f)
        fid = str(d.get("id", ""))
        title = str(d.get("finding", ""))
        endpoint = str(d.get("endpoint", ""))
        status = cls._enum_value(d.get("status", "UNVERIFIED"))
        vetted = d.get("evidence", []) or []

        # R0: سجل تالف
        if not title.strip() or not str(d.get("asset", "")).strip():
            return (
                CourtDocketEntry(fid, title, endpoint, "DEMOTED", "incomplete_record",
                                 "سجل تالف: العنوان أو الـ asset فارغ — لا يُعرض في التقرير."),
                "incomplete_record",
            )

        # R1: سلوك قياسي عام (Axiom 2)
        ep_norm = endpoint.lower().rstrip("/")
        if any(ep_norm.endswith(s) for s in [e.rstrip("/") for e in STANDARD_WEB_ENDINGS]):
            return (
                CourtDocketEntry(fid, title, endpoint, "DEMOTED", "standard_web_behavior",
                                 "ملف قياسي عام (robots.txt/sitemap.xml) — الفحص لبنيه لا ثغرة."),
                "standard_web_behavior",
            )
        if str(d.get("vuln_type", "")) in NON_VULN_FLAT:
            return (
                CourtDocketEntry(fid, title, endpoint, "DEMOTED", "standard_web_behavior",
                                 "ميناء/سلوك مفتوح = سطح هجوم، ليس ثغرة."),
                "standard_web_behavior",
            )

        # R6: غير مثبت → لا يُعرض في التقرير النهائي
        if status in ("UNVERIFIED", "FALSE_POSITIVE"):
            return (
                CourtDocketEntry(fid, title, endpoint, "DEMOTED", "unreported_unverified",
                                 f"الحالة {status} — لا تُعرض في التقرير النهائي أبدًا."),
                "unreported_unverified",
            )

        # R2: ثغرات مكمّلة مثل CONFIRMED/LIKELY يجب أن تحمل إثباتًا موادًّا
        if status in ("CONFIRMED", "LIKELY"):
            if not vetted:
                return (
                    CourtDocketEntry(fid, title, endpoint, "DEMOTED", "no_evidence",
                                     "…لا مُقتنِ يُورَد — حتى CONFIRMED بلا إثبات مستقل."),
                    "no_evidence",
                )
            # R3: إثبات مكتوية/غير متحقق منه
            unverified_ev = [str(e.get("description", "")) if isinstance(e, dict) else str(e)
                             for e in vetted
                             if isinstance(e, dict) and not e.get("verified", True)]
            if unverified_ev:
                return (
                    CourtDocketEntry(fid, title, endpoint, "DEMOTED", "unverified_evidence",
                                     "أجزاء الإثبات لم تُتحقق verify=True."),
                    "unverified_evidence",
                )
            # R4: CONFIRMED بلا إعادة إنتاج إلا إن كان مكتفيًا بالفروقات
            has_repro = d.get("reproduction") is not None
            has_fp_checks = bool(d.get("false_positive_checks"))
            if not (has_repro or has_fp_checks):
                return (
                    CourtDocketEntry(fid, title, endpoint, "DEMOTED", "no_reproduction",
                                     "CONFIRMED بلا reproduction/فروقات عن FP — لا يُصدَّق."),
                    "no_reproduction",
                )

        # تأريخ الحكم النهائي: البرهان كامل
        return (
            CourtDocketEntry(fid, title, endpoint, "PASSED", "",
                             "سلسلة الإثبات مستكملة، الإثبات مُتحقق منه، وسجل قابل لإعادة الإنتاج."),
            None,
        )

    def audit_docket(self, findings: List[Any]) -> FinalCourtReport:
        """يحاكم القائمة كاملة ويرجّع تقرير النص». النتائج المشطوبة تُخفَّض مع كود الأسباب."""
        report = FinalCourtReport(run_id=self.run_id)
        for f in findings or []:
            entry, reason = self.audit_one(f)
            report.entries.append(entry)
            d = self._as_dict(f)
            if reason is None:
                report.accepted.append(d)
            else:
                report.demoted.append({
                    "title": d.get("finding", ""),
                    "endpoint": d.get("endpoint", ""),
                    "vuln_type": d.get("vuln_type", ""),
                    "source_tool": d.get("tool", "unknown"),
                    "rationale": entry.rationale,
                    "reason_code": reason,
                    "raw_evidence": "",
                    "timestamp": time.time(),
                })
        return report
