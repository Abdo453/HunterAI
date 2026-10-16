"""Nuclei Pilot — L2 AI Analyzer + L5 Verification
Finding Normalizer + Duplicate Detector + Evidence Reviewer (rule-based، لا LLM لكل خطوة)
"""
from __future__ import annotations

import logging
import re
from typing import List, Dict, Any, Optional
from collections import defaultdict

from core.nuclei.schemas import (
    NucleiFindingRecord, DuplicateGroup,
    NucleiEvidenceLevel, FindingStatus,
)

log = logging.getLogger("nuclei.analyzer")


class FindingNormalizer:
    """
    L2: يحول مخرجات Nuclei JSON إلى NucleiFindingRecord موحد،
    مع استخراج الحقول الهامة وتطبيعها.
    """

    @staticmethod
    def normalize_nuclei_json_line(line: str) -> Optional[NucleiFindingRecord]:
        """
        يُحط سطر JSON واحد من مخرجات nuclei (-json) إلى سجل موحد.
        nuclei يُخرج كل نتيجة كسطر JSON منفصل (NDJSON).
        """
        import json
        line = line.strip()
        if not line:
            return None
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        # استخراج الحقول وفق هيكل nuclei result
        info = data.get("info", {}) or {}
        template_id = info.get("template_id", data.get("template-id", "unknown"))
        template_name = info.get("name", template_id)
        severity = str(info.get("severity", "info")).lower()
        matcher_name = data.get("matcher-name", data.get("matcher_name", "unknown"))

        # matched_at: الرابط الذي وُجدت فيه النتيجة
        matched_at = (
            data.get("matched-at")
            or data.get("matched_at")
            or data.get("host", "")
            or data.get("url", "")
        )

        # extracted results
        extracted = data.get("extracted-results", data.get("extracted_results", []))
        if isinstance(extracted, str):
            extracted = [extracted]

        # request / response (قد تكون موجودة في بعض الإصدارات)
        req = data.get("request")
        resp = data.get("response")

        digest_src = f"{template_id}:{matched_at}:{matcher_name}"
        record_id = f"nf_{__import__('hashlib').md5(digest_src.encode()).hexdigest()[:10]}"

        return NucleiFindingRecord(
            record_id=record_id,
            template_id=template_id,
            template_name=template_name,
            severity=severity,
            matcher_name=matcher_name,
            matched_at=matched_at,
            extracted_results=extracted,
            request=req,
            response=resp,
            evidence_level=NucleiEvidenceLevel.E0,
            status=FindingStatus.PENDING,
            source_tool="nuclei",
            raw_match_json=data,
            validation_note=f"Template: {template_id} | Matcher: {matcher_name}",
        )

    def normalize_batch(self, nuclei_stdout: str) -> List[NucleiFindingRecord]:
        """يحول مخرجات nuclei NDJSON إلى قائمة سجلات."""
        records: List[NucleiFindingRecord] = []
        for line in nuclei_stdout.splitlines():
            rec = self.normalize_nuclei_json_line(line)
            if rec:
                records.append(rec)
        return records


class DuplicateDetector:
    """
    L2: يكتشف النتائج المكررة (نفس القالب + نفس الهدف) ويجمعها في مجموعة واحدة،
    مع الاحتفاظ بسجل ممثل للمجموعة.
    """

    def __init__(self):
        self._groups: Dict[str, DuplicateGroup] = {}

    def add(self, record: NucleiFindingRecord) -> Optional[DuplicateGroup]:
        key = record.canonical_key
        if key in self._groups:
            group = self._groups[key]
            group.members.append(record)
            record.status = FindingStatus.DUPLICATE
            record.duplicate_group = group.group_id
            return group
        else:
            group = DuplicateGroup(
                group_id="",
                template_id=record.template_id,
                members=[record],
                representative=record,
                reason=f"Same template {record.template_id} on {record.matched_at}",
            )
            self._groups[key] = group
            record.status = FindingStatus.PENDING
            return None  # مجموعة جديدة، لا تكرارًا بعد

    def flush(self) -> List[DuplicateGroup]:
        groups = list(self._groups.values())
        self._groups.clear()
        return groups


class EvidenceReviewer:
    """
    L5 Verification: يراجع الأدلة المرتبطة بكل نتيجة ويحدد:
      - هل الأدلة كافية لدعم الاستنتاج؟ (evidence_status)
      - هل النتيجة تحتاج تحقق إضافي؟ (needs_verification)
      - فحص النطاق (scope_check)
      - درجة الثقة المبدئية (بدون LLM)
    """

    def __init__(self, in_scope: bool = True):
        self.in_scope = in_scope

    def review(self, record: NucleiFindingRecord) -> Dict[str, Any]:
        """
        يُرجع تقرير مراجعة للسجل.
        """
        issues: List[str] = []
        evidence_status = "insufficient"
        needs_verification = True
        confidence = 0.3  # قاعدة: nuclei match وحده غير كافٍ للإثبات

        # التحقق من وجود استجابة HTTP كاملة (دليل أقوى)
        if record.response:
            evidence_status = "partial"
            confidence += 0.2
        else:
            issues.append("لا توجد استجابة HTTP كاملة مرفقة بالنتيجة")

        # التحقق من وجود طلب كامل
        if record.request:
            confidence += 0.1
        else:
            issues.append("لا يوجد طلب HTTP كامل مرفق")

        # severity 영향을 على الثقة (لا ترفعها إلى "مؤكدة"، فقط توحي بأهمية التحقق)
        sev_boost = {
            "critical": 0.15,
            "high": 0.10,
            "medium": 0.05,
            "low": 0.02,
            "info": 0.01,
        }
        confidence += sev_boost.get(record.severity, 0.0)

        # فحص النطاق
        scope_check = "passed" if self.in_scope else "required"
        if not self.in_scope:
            issues.append("الهدف خارج نطاق التفويض المصرح به (P0)")

        # إذا كانت الأدلة مكتملة والهدف داخل النطاق → يمكن ترقيتها إلى E1
        if record.response and record.request and self.in_scope:
            evidence_status = "sufficient"
            needs_verification = False
            record.evidence_level = NucleiEvidenceLevel.E1
            record.status = FindingStatus.NEEDS_VERIFICATION  # ما زالت تحتاج تحقق فعلي (E2) خارج nuclei

        return {
            "record_id": record.record_id,
            "template_id": record.template_id,
            "evidence_status": evidence_status,
            "confidence": round(min(confidence, 1.0), 2),
            "needs_verification": needs_verification,
            "scope_check": scope_check,
            "evidence_level": record.evidence_level,
            "status": record.status,
            "issues": issues,
            "recommendation": (
                "راجع الاستجابة الأصلية وتحقق يدويًا من خلال Browser Worker قبل اعتماد النتيجة."
                if needs_verification else
                "الأداة أولية كافية — يمكن تضمينها في التقرير كإشارة (E1)."
            ),
        }
