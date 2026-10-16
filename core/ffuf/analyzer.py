"""ffuf Response Intelligence — L2 AI Analyzer + L5 Evidence Reviewer
Result Normalizer + Duplicate Detector + Soft-404 Detector + Evidence Reviewer (rule-based، لا LLM لكل خطوة)
"""
from __future__ import annotations

import json
import logging
from typing import List, Dict, Any, Optional
from collections import defaultdict

from core.ffuf.schemas import (
    FfufResultRecord, ResponseCluster,
    FfufEvidenceLevel, ResponseCategory,
)

log = logging.getLogger("ffuf.analyzer")


class FfufNormalizer:
    """
    L2: يحول مخرجات ffuf JSON إلى FfufResultRecord موحد،
    مع تصنيف الاستجابة وتطبيع الحقول.
    """

    @staticmethod
    def normalize_ffuf_json_line(line: str) -> Optional[FfufResultRecord]:
        """
        يُحط سطر JSON واحد من مخرجات ffuf (-o - -of json) إلى سجل موحد.
        ffuf يُخرج كائن JSON واحد يحتوي على مصفوفة النتائج، أو NDJSON.
        """
        line = line.strip()
        if not line:
            return None
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        # ffuf قد يُخرج {"results": [...]} أو سطر واحد لكل نتيجة
        results = data.get("results", [data]) if isinstance(data, dict) else [data]

        records: List[FfufResultRecord] = []
        for item in results:
            if not isinstance(item, dict):
                continue

            url = item.get("url", "") or ""
            method = item.get("method", "GET") or "GET"
            status_code = item.get("status", 0) or 0
            content_length = item.get("length", 0) or 0
            content_words = item.get("words", 0) or 0
            content_lines = item.get("lines", 0) or 0
            redirect_location = item.get("redirectlocation") or item.get("redirect_location")

            # تصنيف الاستجابة مبدئي (L2)
            category = FfufNormalizer._classify_response(
                status_code, content_length, content_words, redirect_location
            )

            digest_src = f"{url}:{method}:{status_code}:{content_length}"
            record_id = f"ff_{__import__('hashlib').md5(digest_src.encode()).hexdigest()[:10]}"

            records.append(FfufResultRecord(
                record_id=record_id,
                url=url,
                method=method,
                status_code=status_code,
                content_length=content_length,
                content_words=content_words,
                content_lines=content_lines,
                redirect_location=redirect_location,
                category=category,
                evidence_level=FfufEvidenceLevel.E0,
                source_tool="ffuf",
                raw_json=item,
                validation_note=f"HTTP {status_code} | Len={content_length} | Words={content_words}",
            ))

        return records if records else None

    def normalize_batch(self, ffuf_stdout: str) -> List[FfufResultRecord]:
        """يحول مخرجات ffuf JSON إلى قائمة سجلات."""
        records: List[FfufResultRecord] = []
        #ffuf قد يُخرج JSON واحد كبير أو عدة أسطر
        try:
            data = json.loads(ffuf_stdout)
            if isinstance(data, dict) and "results" in data:
                for item in data["results"]:
                    recs = self.normalize_ffuf_json_line(json.dumps(item))
                    if recs:
                        records.extend(recs)
            else:
                recs = self.normalize_ffuf_json_line(ffuf_stdout)
                if recs:
                    records.extend(recs)
        except json.JSONDecodeError:
            # محاولة سطر بسطر (NDJSON)
            for line in ffuf_stdout.splitlines():
                recs = self.normalize_ffuf_json_line(line)
                if recs:
                    records.extend(recs)
        return records

    @staticmethod
    def _classify_response(
        status_code: int,
        content_length: int,
        content_words: int,
        redirect_location: Optional[str],
    ) -> str:
        """يحدد فئة الاستجابة مبدئياً."""
        if redirect_location:
            return ResponseCategory.REDIRECT
        if status_code in (401, 403):
            return ResponseCategory.AUTH_REQUIRED
        if status_code in (301, 302, 307, 308):
            return ResponseCategory.REDIRECT
        if status_code >= 400 and status_code < 500:
            if status_code == 404:
                return ResponseCategory.ERROR
            return ResponseCategory.ERROR
        if status_code >= 500:
            return ResponseCategory.ERROR
        if status_code == 200:
            return ResponseCategory.NORMAL
        return ResponseCategory.NORMAL


class DuplicateDetector:
    """
    L2: يكتشف النتائج المكررة (نفس url + status_code) ويجمعها.
    """

    def __init__(self):
        self._groups: Dict[str, List[FfufResultRecord]] = defaultdict(list)

    def add(self, record: FfufResultRecord) -> Optional[List[FfufResultRecord]]:
        key = record.canonical_key
        self._groups[key].append(record)
        if len(self._groups[key]) > 1:
            return self._groups[key]
        return None

    def flush(self) -> Dict[str, List[FfufResultRecord]]:
        groups = dict(self._groups)
        self._groups.clear()
        return groups


class Soft404Detector:
    """
    L5: يكتشف حالات Soft-404 — صفحات تُعيد 200 لكنها تحتوي على محتوى "غير موجود".
    يعتمد على تحليل طول المحتوى وعدد الكلمات مقارنةً بالنتائج الطبيعية.
    """

    def __init__(self, length_tolerance: float = 0.10, word_tolerance: float = 0.10):
        self.length_tolerance = length_tolerance
        self.word_tolerance = word_tolerance

    def detect(
        self,
        records: List[FfufResultRecord],
    ) -> List[FfufResultRecord]:
        """
        يُحدد السجلات التي تُحتمل أنها Soft-404 بناءً على التشابه في طول المحتوى
        مع الاستجابات السائدة (modal response).
        """
        if not records:
            return records

        # إيجاد الطول السائد والكلمات السائدة
        length_counts: Dict[int, int] = defaultdict(int)
        word_counts: Dict[int, int] = defaultdict(int)
        for r in records:
            length_counts[r.content_length] += 1
            word_counts[r.content_words] += 1

        modal_length = max(length_counts, key=length_counts.get)
        modal_words = max(word_counts, key=word_counts.get)
        modal_count = length_counts[modal_length]

        # إذا كان أكثر من 70% من النتائج بنفس الطول → قد يكون Soft-404 شائع
        if modal_count / len(records) > 0.70:
            for r in records:
                if (
                    r.status_code == 200
                    and abs(r.content_length - modal_length) / max(modal_length, 1) <= self.length_tolerance
                    and abs(r.content_words - modal_words) / max(modal_words, 1) <= self.word_tolerance
                ):
                    r.category = ResponseCategory.SOFT_404
                    r.validation_note += " | suspected_soft_404"
        return records

    @staticmethod
    def _estimate_words(content_length: int) -> int:
        """تقدير عدد الكلمات بناءً على طول المحتوى (تقريبي)."""
        return max(content_length // 6, 1)


class EvidenceReviewer:
    """
    L5 Verification: يراجع الأدلة المرتبطة بكل نتيجة ويحدد:
      - هل النتيجة مثيرة للاهتمام (Interesting) أم عادية؟
      - هل تحتاج إلى تحقق إضافي؟ (needs_verification)
      - درجة الثقة المبدئية (بدون LLM)
    """

    INTERESTING_STATUSES = {200, 201, 202, 301, 302, 307, 308, 401, 403}

    def __init__(self):
        pass

    def review(self, record: FfufResultRecord) -> Dict[str, Any]:
        """
        يُرجع تقرير مراجعة للنتيجة.
        """
        issues: List[str] = []
        confidence = 0.2  # قاعدة: نتيجة ffuf واحدة غير كافية للإثبات
        interesting = False

        # حالة الاستجابة
        if record.status_code in self.INTERESTING_STATUSES:
            confidence += 0.25
            interesting = True
        else:
            issues.append(f"حالة استجابة غير مثيرة ({record.status_code})")

        # حجم المحتوى
        if record.content_length > 0:
            confidence += 0.15
        else:
            issues.append("حجم المحتوى صفر — قد يكون استجابة فارغة")

        # وجود إعادة توجيه
        if record.redirect_location:
            confidence += 0.1
            interesting = True

        # Soft-404 يقلل الثقة بشدة
        if record.category == ResponseCategory.SOFT_404:
            confidence -= 0.40
            issues.append("تُحتمل Soft-404 — النتيجة غير موثوقة")
        elif record.category == ResponseCategory.AUTH_REQUIRED:
            confidence += 0.10
            interesting = True
            issues.append("يطلب مصادقة — قد يكون مساراً محمياً")

        # إذا كانت مثيرة للاهتمام وليست Soft-404 → E1
        if interesting and record.category != ResponseCategory.SOFT_404:
            record.evidence_level = FfufEvidenceLevel.E1

        confidence = max(0.0, min(confidence, 1.0))
        label = self._label(confidence)

        return {
            "record_id": record.record_id,
            "url": record.url,
            "status_code": record.status_code,
            "category": record.category,
            "evidence_status": "sufficient" if record.evidence_level == FfufEvidenceLevel.E1 else "insufficient",
            "confidence": round(confidence, 2),
            "confidence_label": label,
            "evidence_level": record.evidence_level,
            "is_interesting": interesting,
            "needs_verification": record.evidence_level != FfufEvidenceLevel.E1 or record.category == ResponseCategory.SOFT_404,
            "issues": issues,
            "recommendation": (
                "النتيجة مثيرة للاهتمام (E1) — يُنصح بالتحقق اليدوي من الاستجابة الأصلية."
                if interesting and record.category != ResponseCategory.SOFT_404 else
                "النتيجة عادية أو مُشتبهة (Soft-404) — لا تُعتبر دليلاً كافياً."
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
