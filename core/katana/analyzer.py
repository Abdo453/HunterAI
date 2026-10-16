"""Katana Endpoint Intelligence — L2 AI Analyzer + L5 Evidence Reviewer
Endpoint Normalizer + Duplicate Detector + Evidence Reviewer (rule-based، لا LLM لكل خطوة)
"""
from __future__ import annotations

import json
import logging
import re
from typing import List, Dict, Any, Optional
from collections import defaultdict

from core.katana.schemas import (
    KatanaEndpointRecord, EndpointProfile,
    KatanaEvidenceLevel, EndpointCategory,
)

log = logging.getLogger("katana.analyzer")


class KatanaNormalizer:
    """
    L2: يحول مخرجات Katana JSON إلى KatanaEndpointRecord موحد،
    مع تصنيف نقطة النهاية وتطبيع الحقول.
    """

    @staticmethod
    def normalize_katana_json_line(line: str) -> Optional[KatanaEndpointRecord]:
        """
        يُحط سطر JSON واحد من مخرجات katana (-jc -oj) إلى سجل موحد.
        """
        line = line.strip()
        if not line:
            return None
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        url = data.get("url", "") or ""
        method = data.get("method", "GET") or "GET"
        status_code = data.get("status_code")
        content_length = data.get("content_length")
        content_type = data.get("content_type")

        # تصنيف نقطة النهاية مبدئي (L2)
        category = KatanaNormalizer._classify_endpoint(url, content_type)

        # استخراج المعلمات من URL
        parameters = KatanaNormalizer._extract_parameters(url)

        # كشف JS ونماذج
        is_js = url.lower().endswith(".js")
        is_form = data.get("is_form", False)

        digest_src = f"{url}:{method}"
        record_id = f"kt_{__import__('hashlib').md5(digest_src.encode()).hexdigest()[:10]}"

        return KatanaEndpointRecord(
            record_id=record_id,
            url=url,
            method=method,
            status_code=status_code,
            content_length=content_length,
            content_type=content_type,
            category=category,
            is_js=is_js,
            is_form=is_form,
            parameters=parameters,
            evidence_level=KatanaEvidenceLevel.E0,
            source_tool="katana",
            raw_json=data,
            validation_note=f"HTTP {status_code or '?'} | {category} | {len(parameters)} param(s)",
        )

    def normalize_batch(self, katana_stdout: str) -> List[KatanaEndpointRecord]:
        """يحول مخرجات katana JSON إلى قائمة سجلات."""
        records: List[KatanaEndpointRecord] = []
        for line in katana_stdout.splitlines():
            rec = self.normalize_katana_json_line(line)
            if rec:
                records.append(rec)
        return records

    @staticmethod
    def _classify_endpoint(url: str, content_type: Optional[str]) -> str:
        """يحدد فئة نقطة النهاية مبدئياً."""
        url_lower = url.lower()

        # API
        if any(k in url_lower for k in ["/api/", "/graphql", "/rest/", "/v1/", "/v2/", "/webhook"]):
            return EndpointCategory.API

        # مصادقة
        if any(k in url_lower for k in ["/login", "/auth", "/signin", "/token", "/oauth", "/sso", "/register", "/password"]):
            return EndpointCategory.AUTH

        # إدارة
        if any(k in url_lower for k in ["/admin", "/administrator", "/manage", "/dashboard", "/panel", "/config", "/setup", "/root"]):
            return EndpointCategory.ADMIN

        # ملف
        if re.search(r"\.(php|asp|aspx|jsp|py|cgi|pl|json|xml|zip|pdf|doc|xls|bak|old|sql|db|log|conf|ini)$", url_lower):
            return EndpointCategory.FILE

        return EndpointCategory.STATIC

    @staticmethod
    def _extract_parameters(url: str) -> List[str]:
        """يستخرج معاملات الاستعلام من URL."""
        if "?" not in url:
            return []
        query = url.split("?", 1)[1]
        params = []
        for part in query.split("&"):
            if "=" in part:
                params.append(part.split("=", 1)[0])
        return params


class DuplicateDetector:
    """
    L2: يكتشف نقاط النهاية المكررة (نفس url + method) ويجمعها.
    """

    def __init__(self):
        self._groups: Dict[str, List[KatanaEndpointRecord]] = defaultdict(list)

    def add(self, record: KatanaEndpointRecord) -> Optional[List[KatanaEndpointRecord]]:
        key = record.canonical_key
        self._groups[key].append(record)
        if len(self._groups[key]) > 1:
            return self._groups[key]
        return None

    def flush(self) -> Dict[str, List[KatanaEndpointRecord]]:
        groups = dict(self._groups)
        self._groups.clear()
        return groups


class EvidenceReviewer:
    """
    L5 Verification: يراجع الأدلة المرتبطة بكل نقطة نهاية ويحدد:
      - هل الأدلة كافية لدعم الملف التقني؟ (evidence_status)
      - هل النقطة تحتاج تحقق إضافي؟ (needs_verification)
      - هل هي حساسة (مصادقة/إدارة/API)؟
      - درجة الثقة المبدئية (بدون LLM)
    """

    def __init__(self):
        pass

    def review(self, record: KatanaEndpointRecord) -> Dict[str, Any]:
        """
        يُرجع تقرير مراجعة لنقطة النهاية.
        """
        issues: List[str] = []
        confidence = 0.2  # قاعدة: نتيجة Katana واحدة غير كافية للإثبات

        # حالة الاستجابة
        if record.status_code is not None:
            confidence += 0.2
        else:
            issues.append("لا توجد حالة استجابة HTTP")

        # حجم المحتوى
        if record.content_length is not None and record.content_length > 0:
            confidence += 0.15

        # وجود معلمات = سياق richer
        if record.parameters:
            confidence += 0.15

        # تصنيف النقطة
        is_auth = record.category == EndpointCategory.AUTH
        is_admin = record.category == EndpointCategory.ADMIN
        is_api = record.category == EndpointCategory.API

        if is_auth:
            confidence += 0.1
            issues.append("نقطة مصادقة — زيادة أولوية التحليل الأمني")
        if is_admin:
            confidence += 0.1
            issues.append("نقطة إدارة — تأثير محتمل أعلى")
        if is_api:
            confidence += 0.05

        # JS file = سياق تقني إضافي
        if record.is_js:
            confidence += 0.05

        # إذا كانت الأدلة مكتملة → E1
        if record.status_code is not None and (record.parameters or record.category != EndpointCategory.UNKNOWN):
            record.evidence_level = KatanaEvidenceLevel.E1

        confidence = max(0.0, min(confidence, 1.0))
        label = self._label(confidence)

        return {
            "record_id": record.record_id,
            "url": record.url,
            "method": record.method,
            "category": record.category,
            "evidence_status": "sufficient" if record.evidence_level == KatanaEvidenceLevel.E1 else "insufficient",
            "confidence": round(confidence, 2),
            "confidence_label": label,
            "evidence_level": record.evidence_level,
            "is_auth_sensitive": is_auth,
            "is_admin_sensitive": is_admin,
            "is_api": is_api,
            "needs_verification": record.evidence_level != KatanaEvidenceLevel.E1,
            "issues": issues,
            "recommendation": (
                "نقطة نهاية موثقة (E1) — يُنصح بالفحص العميق عبر Nuclei أوBrowser Worker."
                if record.evidence_level == KatanaEvidenceLevel.E1 else
                "النقطة تحتاج أدلة إضافية قبل اعتمادها في التحقيق."
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
