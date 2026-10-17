"""LinkFinder JS Endpoints — L2 AI Analyzer + L5 Evidence Reviewer
Finding Normalizer + Duplicate Detector + Evidence Reviewer (rule-based، لا LLM لكل خطوة)
"""
from __future__ import annotations

import json
import logging
from typing import List, Dict, Any, Optional
from collections import defaultdict

from core.linkfinder.schemas import (
    JSFindingRecord, JSEndpointProfile,
    LinkFinderEvidenceLevel,
)

log = logging.getLogger("linkfinder.analyzer")


class LinkFinderNormalizer:
    """
    L2: يحول مخرجات linkfinder JSON إلى JSFindingRecord موحد،
    مع تصنيف نقطة النهاية وتطبيع الحقول.
    """

    @staticmethod
    def normalize_linkfinder_json_line(line: str) -> Optional[JSFindingRecord]:
        """
        يُحط سطر JSON واحد من مخرجات linkfinder إلى سجل موحد.
        linkfinder قد يُخرج كائن JSON واحد لكل نتيجة.
        """
        line = line.strip()
        if not line:
            return None
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        endpoint = data.get("endpoint", "") or ""
        source_file = data.get("source_file", "") or ""
        line_number = data.get("line_number", 0) or 0
        method = data.get("method", "GET") or "GET"
        parameter = data.get("parameter", "") or ""
        code_snippet = data.get("code_snippet", "") or ""

        digest_src = f"{endpoint}:{source_file}:{line_number}"
        record_id = f"js_{__import__('hashlib').md5(digest_src.encode()).hexdigest()[:10]}"

        return JSFindingRecord(
            record_id=record_id,
            endpoint=endpoint,
            source_file=source_file,
            line_number=line_number,
            method=method,
            parameter=parameter,
            code_snippet=code_snippet,
            evidence_level=LinkFinderEvidenceLevel.E0,
            source_tool="linkfinder",
            raw_json=data,
            validation_note=f"Endpoint: {endpoint} | Source: {source_file}:{line_number} | Method: {method}",
        )

    def normalize_batch(self, linkfinder_stdout: str) -> List[JSFindingRecord]:
        """يحول مخرجات linkfinder JSON إلى قائمة سجلات."""
        records: List[JSFindingRecord] = []
        for line in linkfinder_stdout.splitlines():
            rec = self.normalize_linkfinder_json_line(line)
            if rec:
                records.append(rec)
        return records


class DuplicateDetector:
    """
    L2: يكتشف الأصول المكررة (نفس endpoint + source_file) ويجمعها في مجموعة واحدة.
    """

    def __init__(self):
        self._groups: Dict[str, List[JSFindingRecord]] = defaultdict(list)

    def add(self, record: JSFindingRecord) -> Optional[List[JSFindingRecord]]:
        key = record.canonical_key
        self._groups[key].append(record)
        if len(self._groups[key]) > 1:
            return self._groups[key]
        return None

    def flush(self) -> Dict[str, List[JSFindingRecord]]:
        groups = dict(self._groups)
        self._groups.clear()
        return groups


class EvidenceReviewer:
    """
    L5 Verification: يراجع الأدلة المرتبطة بكل نقطة نهاية ويحدد:
      - هل الأدلة كافية لدعم الملف؟ (evidence_status)
      - هل النتيجة تحتاج تحقق إضافي؟ (needs_verification)
      - درجة الثقة المبدئية (بدون LLM)
    """

    def __init__(self):
        pass

    def review(self, record: JSFindingRecord) -> Dict[str, Any]:
        """
        يُرجع تقرير مراجعة للسجل.
        """
        issues: List[str] = []
        confidence = 0.2  # قاعدة: نتيجة linkfinder واحدة غير كافية للإثبات الكامل

        # وجود endpoint = دليل أقوى
        if record.endpoint:
            confidence += 0.25
        else:
            issues.append("لا يوجد نقطة نهاية (endpoint)")

        # وجود source_file = دليل أقوى
        if record.source_file:
            confidence += 0.15
        else:
            issues.append("لا يوجد ملف مصدر (source_file)")

        # وجود معلمة = دليل أقوى
        if record.parameter:
            confidence += 0.15
        else:
            issues.append("لا توجد معلمة (parameter)")

        # وجود كود المصدر = دليل أقوى
        if record.code_snippet:
            confidence += 0.15
        else:
            issues.append("لا يوجد كود مصدر (code_snippet)")

        # تحديد إن كانت النقطة حساسة (auth, admin, api)
        endpoint_lower = record.endpoint.lower()
        source_lower = record.source_file.lower()
        auth_keywords = ["login", "auth", "signin", "token", "oauth", "sso", "password", "register"]
        admin_keywords = ["admin", "administrator", "manage", "dashboard", "panel", "config", "setup", "root"]
        api_keywords = ["api", "graphql", "rest", "webhook", "svc", "service"]

        is_auth = any(k in endpoint_lower or k in source_lower for k in auth_keywords)
        is_admin = any(k in endpoint_lower or k in source_lower for k in admin_keywords)
        is_api = any(k in endpoint_lower or k in source_lower for k in api_keywords)

        if is_auth:
            confidence += 0.1
            issues.append("نقطة مصادقة — أولوية أعلى")
        if is_admin:
            confidence += 0.1
            issues.append("نقطة إدارة — تأثير محتمل أعلى")
        if is_api:
            confidence += 0.05
            issues.append("نقطة API — قد تكشف بيانات منظمة")

        # إذا كانت الأدلة مكتملة → E1
        if record.endpoint and record.source_file and record.code_snippet:
            record.evidence_level = LinkFinderEvidenceLevel.E1

        confidence = max(0.0, min(confidence, 1.0))
        label = self._label(confidence)

        return {
            "record_id": record.record_id,
            "endpoint": record.endpoint,
            "source_file": record.source_file,
            "line_number": record.line_number,
            "method": record.method,
            "parameter": record.parameter,
            "code_snippet": record.code_snippet,
            "evidence_level": record.evidence_level,
            "evidence_status": "sufficient" if record.evidence_level == LinkFinderEvidenceLevel.E1 else "insufficient",
            "confidence": round(confidence, 2),
            "confidence_label": label,
            "is_auth_endpoint": is_auth,
            "is_admin_endpoint": is_admin,
            "is_api_endpoint": is_api,
            "needs_verification": record.evidence_level != LinkFinderEvidenceLevel.E1,
            "issues": issues,
            "recommendation": (
                "نقطة نهاية موثقة (E1) — يُنصح بالتحقق اليدوي من النقطة."
                if record.evidence_level == LinkFinderEvidenceLevel.E1 else
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
