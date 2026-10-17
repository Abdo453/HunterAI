"""Soft-404 Detector — L2 AI Analyzer + L5 Evidence Reviewer
Finding Normalizer + Duplicate Detector + Evidence Reviewer (rule-based، لا LLM لكل خطوة)
"""
from __future__ import annotations

import json
import logging
from typing import List, Dict, Any, Optional
from collections import defaultdict

from core.soft_404.schemas import (
    Soft404Record, Soft404Profile,
    Soft404EvidenceLevel,
)

log = logging.getLogger("soft_404.analyzer")


class Soft404Normalizer:
    """
    L2: يحول مخرجات soft-404-detector إلى Soft404Record موحد،
    مع تقييم تشابه الصفحة (similarity score) وتطبيع الحقول.
    """

    @staticmethod
    def normalize_soft_404_line(line: str) -> Optional[Soft404Record]:
        """
        يُحط سطر واحد من مخرجات soft-404-detector إلى سجل موحد.
        soft-404-detector قد يُخرج JSON أو نصًا بسيطًا.
        """
        line = line.strip()
        if not line:
            return None

        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return Soft404Normalizer._parse_text_line(line)

        url = data.get("url", "") or ""
        status_code = data.get("status_code", 0) or 0
        content_length = data.get("content_length", 0) or 0
        content_type = data.get("content_type", "")
        title = data.get("title", "")
        is_soft_404 = data.get("is_soft_404", False) or False
        similarity_score = data.get("similarity_score", 0.0) or 0.0

        digest_src = f"{url}:{status_code}:{content_length}"
        record_id = f"s404_{__import__('hashlib').md5(digest_src.encode()).hexdigest()[:10]}"

        return Soft404Record(
            record_id=record_id,
            url=url,
            status_code=status_code,
            content_length=content_length,
            content_type=content_type,
            title=title,
            is_soft_404=is_soft_404,
            similarity_score=similarity_score,
            evidence_level=Soft404EvidenceLevel.E0,
            source_tool="soft-404-detector",
            raw_json=data,
            validation_note=f"URL: {url} | Status: {status_code} | Length: {content_length} | Soft-404: {is_soft_404}",
        )

    @staticmethod
    def _parse_text_line(line: str) -> Optional[Soft404Record]:
        """
        محلل نصي بسيط لـ soft-404-detector (إذا لم يكن مخرج JSON).
        """
        # مثال: url | status_code | content_length | content_type | title | is_soft_404 | similarity_score
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 3:
            return None

        url = parts[0] or ""
        status_code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        content_length = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0
        content_type = parts[3] if len(parts) > 3 else ""
        title = parts[4] if len(parts) > 4 else ""
        is_soft_404 = parts[5].lower() == "true" if len(parts) > 5 else False
        similarity_score = float(parts[6]) if len(parts) > 6 and parts[6].replace(".", "", 1).isdigit() else 0.0

        digest_src = f"{url}:{status_code}:{content_length}"
        record_id = f"s404_{__import__('hashlib').md5(digest_src.encode()).hexdigest()[:10]}"

        return Soft404Record(
            record_id=record_id,
            url=url,
            status_code=status_code,
            content_length=content_length,
            content_type=content_type,
            title=title,
            is_soft_404=is_soft_404,
            similarity_score=similarity_score,
            evidence_level=Soft404EvidenceLevel.E0,
            source_tool="soft-404-detector",
            raw_json={},
            validation_note=f"URL: {url} | Status: {status_code} | Length: {content_length} | Soft-404: {is_soft_404}",
        )

    def normalize_batch(self, soft_404_stdout: str) -> List[Soft404Record]:
        """يحول مخرجات soft-404-detector إلى قائمة سجلات."""
        records: List[Soft404Record] = []
        for line in soft_404_stdout.splitlines():
            rec = self.normalize_soft_404_line(line)
            if rec:
                records.append(rec)
        return records


class DuplicateDetector:
    """
    L2: يكتشف الصفحات المكررة (نفس url) ويجمعها في مجموعة واحدة.
    """

    def __init__(self):
        self._groups: Dict[str, List[Soft404Record]] = defaultdict(list)

    def add(self, record: Soft404Record) -> Optional[List[Soft404Record]]:
        key = record.canonical_key
        self._groups[key].append(record)
        if len(self._groups[key]) > 1:
            return self._groups[key]
        return None

    def flush(self) -> Dict[str, List[Soft404Record]]:
        groups = dict(self._groups)
        self._groups.clear()
        return groups


class EvidenceReviewer:
    """
    L5 Verification: يراجع الأدلة المرتبطة بكل صفحة ويحدد:
      - هل الأدلة كافية لدعم وجود Soft-404؟ (evidence_status)
      - هل الصفحة تحتاج تحقق إضافي؟ (needs_verification)
      - درجة الثقة المبدئية (بدون LLM)
    """

    def __init__(self):
        pass

    def review(self, record: Soft404Record) -> Dict[str, Any]:
        """
        يُرجع تقرير مراجعة للسجل.
        """
        issues: List[str] = []
        confidence = 0.2  # قاعدة: نتيجة soft-404-detector واحدة غير كافية للإثبات الكامل

        # وجود status code = دليل أقوى
        if record.status_code is not None:
            confidence += 0.2
        else:
            issues.append("لا يوجد رمز حالة HTTP")

        # وجود content_length = دليل أقوى
        if record.content_length is not None and record.content_length > 0:
            confidence += 0.15
        else:
            issues.append("لا يوجد حجم محتوى (content_length)")

        # وجود عنوان (title) = دليل أقوى
        if record.title:
            confidence += 0.1
        else:
            issues.append("لا يوجد عنوان صفحة (title)")

        # إذا كانت الصفحة Soft-404 فعلاً = دليل أقوى
        if record.is_soft_404:
            confidence += 0.25
        else:
            issues.append("الصفحة ليست Soft-404 مؤكدة")

        # similarity score = دليل إضافي
        if record.similarity_score > 0.7:
            confidence += 0.1
            issues.append("تشابه عالٍ مع صفحة 404 الحقيقية")
        elif record.similarity_score > 0.4:
            confidence += 0.05
            issues.append("تشابه متوسط مع صفحة 404 الحقيقية")

        # إذا كانت الأدلة مكتملة → E1
        if record.status_code is not None and record.content_length is not None and record.is_soft_404:
            record.evidence_level = Soft404EvidenceLevel.E1

        confidence = max(0.0, min(confidence, 1.0))
        label = self._label(confidence)

        return {
            "record_id": record.record_id,
            "url": record.url,
            "status_code": record.status_code,
            "content_length": record.content_length,
            "content_type": record.content_type,
            "title": record.title,
            "is_soft_404": record.is_soft_404,
            "similarity_score": record.similarity_score,
            "evidence_level": record.evidence_level,
            "evidence_status": "sufficient" if record.evidence_level == Soft404EvidenceLevel.E1 else "insufficient",
            "confidence": round(confidence, 2),
            "confidence_label": label,
            "is_true_soft_404": record.is_soft_404,
            "needs_verification": record.evidence_level != Soft404EvidenceLevel.E1,
            "issues": issues,
            "recommendation": (
                "صفحة Soft-404 مؤكدة (E1) — يُنصح بإصلاح الصفحة أو إعادة توجيهها (redirect)."
                if record.evidence_level == Soft404EvidenceLevel.E1 else
                "الصفحة تحتاج أدلة إضافية قبل اعتبارها Soft-404."
            ),
        }

    @staticmethod
    def _label(score: float) -> str:
        if score >= 0.75:
            return "strong"
        elif score >= 0.50:
            return "probable"
        elif score >= 0.25:
            return "possible"
        return "weak"
