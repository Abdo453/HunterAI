"""Subfinder Asset Coverage — L2 AI Analyzer + L5 Evidence Reviewer
Finding Normalizer + Duplicate Detector + Evidence Reviewer (rule-based، لا LLM لكل خطوة)
"""
from __future__ import annotations

import json
import logging
from typing import List, Dict, Any, Optional
from collections import defaultdict

from core.subfinder.schemas import (
    SubfinderAssetRecord, AssetCoverageProfile,
    SubfinderEvidenceLevel, SourceType,
)

log = logging.getLogger("subfinder.analyzer")


class SubfinderNormalizer:
    """
    L2: يحول مخرجات subfinder JSON إلى SubfinderAssetRecord موحد،
    مع تطبيع الحقول واستخراج مصدر الاكتشاف.
    """

    @staticmethod
    def normalize_subfinder_json_line(line: str) -> Optional[SubfinderAssetRecord]:
        """
        يُحط سطر JSON واحد من مخرجات subfinder (-json -silent) إلى سجل موحد.
        """
        line = line.strip()
        if not line:
            return None
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        subdomain = data.get("subdomain", "") or data.get("host", "") or ""
        source = data.get("source", "") or ""
        ip = data.get("ip", "") or ""
        raw_cdn = data.get("cdn", "")
        cdn = str(raw_cdn) if raw_cdn not in (None, "", False, 0) else None
        # source-type mapping → SourceType
        st_raw = str(data.get("source-type", "") or "").lower().strip()
        known = {
            "certificate": SourceType.CERTIFICATE,
            "cert": SourceType.CERTIFICATE,
            "dns": SourceType.DNS,
            "passive": SourceType.PASSIVE,
            "active": SourceType.ACTIVE,
            "api": SourceType.API,
        }
        source_type = known.get(st_raw, SourceType.UNKNOWN)

        digest_src = f"{subdomain}:{source}"
        record_id = f"sf_{__import__('hashlib').md5(digest_src.encode()).hexdigest()[:10]}"

        return SubfinderAssetRecord(
            record_id=record_id,
            subdomain=subdomain,
            source=source,
            source_type=source_type,
            ip=ip,
            cdn=cdn,
            evidence_level=SubfinderEvidenceLevel.E0,
            source_tool="subfinder",
            raw_json=data,
            validation_note=f"Subdomain: {subdomain} | Source: {source} | Type: {source_type} | IP: {ip or '—'}",
        )

    def normalize_batch(self, subfinder_stdout: str) -> List[SubfinderAssetRecord]:
        """يحول مخرجات subfinder JSON إلى قائمة سجلات."""
        records: List[SubfinderAssetRecord] = []
        for line in subfinder_stdout.splitlines():
            rec = self.normalize_subfinder_json_line(line)
            if rec:
                records.append(rec)
        return records


class DuplicateDetector:
    """
    L2: يكتشف الأصول المكررة (نفس subdomain) ويجمعها في مجموعة واحدة.
    """

    def __init__(self):
        self._groups: Dict[str, List[SubfinderAssetRecord]] = defaultdict(list)

    def add(self, record: SubfinderAssetRecord) -> Optional[List[SubfinderAssetRecord]]:
        key = record.canonical_key
        self._groups[key].append(record)
        if len(self._groups[key]) > 1:
            return self._groups[key]
        return None

    def flush(self) -> Dict[str, List[SubfinderAssetRecord]]:
        groups = dict(self._groups)
        self._groups.clear()
        return groups


class EvidenceReviewer:
    """
    L5 Verification: يراجع الأدلة المرتبطة بكل أصل فرعي ويحدد:
      - هل الأدلة كافية لدعم الملف؟ (evidence_status)
      - هل الأصل يحتاج تحقق إضافي؟ (needs_verification)
      - درجة الثقة المبدئية (بدون LLM)
    """

    HIGH_VALUE_SUBDOMAINS = {
        "admin", "api", "dev", "staging", "test", "internal", "vpn", "mail",
        "webmail", "portal", "backup", "git", "jenkins", "gitlab",
    }

    def __init__(self):
        pass

    def review(self, record: SubfinderAssetRecord) -> Dict[str, Any]:
        """
        يُرجع تقرير مراجعة للسجل.
        """
        issues: List[str] = []
        confidence = 0.2  # قاعدة: نتيجة subfinder واحدة غير كافية للإثبات الكامل

        # وجود مصدر 발견 = دليل أقوى
        if record.source:
            confidence += 0.15
        else:
            issues.append("لا يوجد مصدر اكتشاف (source)")

        # وجود IP = دليل أقوى
        if record.ip:
            confidence += 0.15
        else:
            issues.append("لا يوجد عنوان IP")

        # وجود CDN = دليل أقوى
        if record.cdn:
            confidence += 0.1
            issues.append("الدلو محمي بـ CDN")

        # التحقق من الفرع عالي القيمة
        subdomain_lower = record.subdomain.lower()
        is_high_value = any(kw in subdomain_lower for kw in self.HIGH_VALUE_SUBDOMAINS)
        if is_high_value:
            confidence += 0.15
            issues.append("نطاق فرعي عالي القيمة — أولوية أعلى")

        # إذا كانت الأدلة مكتملة → E1
        if record.source and record.ip:
            record.evidence_level = SubfinderEvidenceLevel.E1

        confidence = max(0.0, min(confidence, 1.0))
        label = self._label(confidence)

        return {
            "record_id": record.record_id,
            "subdomain": record.subdomain,
            "source": record.source,
            "ip": record.ip,
            "cdn": record.cdn,
            "evidence_level": record.evidence_level,
            "evidence_status": "sufficient" if record.evidence_level == SubfinderEvidenceLevel.E1 else "insufficient",
            "confidence": round(confidence, 2),
            "confidence_label": label,
            "is_high_value": is_high_value,
            "needs_verification": record.evidence_level != SubfinderEvidenceLevel.E1,
            "issues": issues,
            "recommendation": (
                "أصل فرعي موثق (E1) — يُنصح بالفحص عبر HTTPx و Nmap للتأكيد على الخدمة."
                if record.evidence_level == SubfinderEvidenceLevel.E1 else
                "الأصل يحتاج أدلة إضافية قبل اعتباره is valid."
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
