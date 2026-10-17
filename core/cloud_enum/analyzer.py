"""Cloud-Enum Cloud Storage — L2 AI Analyzer + L5 Evidence Reviewer
Finding Normalizer + Duplicate Detector + Evidence Reviewer (rule-based، لا LLM لكل خطوة)
"""
from __future__ import annotations

import json
import logging
from typing import List, Dict, Any, Optional
from collections import defaultdict

from core.cloud_enum.schemas import (
    CloudBucketRecord, CloudBucketProfile,
    CloudEnumEvidenceLevel,
)

log = logging.getLogger("cloud_enum.analyzer")


class CloudEnumNormalizer:
    """
    L2: يحول مخرجات cloud-enum إلى CloudBucketRecord موحد،
    مع تصنيف الدلو (bucket) وتطبيع الحقول.
    """

    @staticmethod
    def normalize_cloud_enum_line(line: str) -> Optional[CloudBucketRecord]:
        """
        يُحط سطر واحد من مخرجات cloud-enum إلى سجل موحد.
        cloud-enum قد يُخرج سطور نصية أو JSON.
        """
        line = line.strip()
        if not line:
            return None

        # محاولة parse JSON
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            # محاولة parse نصي (cloud-enum قد يُخرج نصًا بسيطًا)
            return CloudEnumNormalizer._parse_text_line(line)

        bucket_name = data.get("bucket_name", "") or data.get("bucket", "") or ""
        provider = data.get("provider", "") or ""
        access_level = data.get("access_level", "") or "unknown"
        region = data.get("region", "")
        url = data.get("url", "") or ""

        digest_src = f"{bucket_name}:{provider}"
        record_id = f"cb_{__import__('hashlib').md5(digest_src.encode()).hexdigest()[:10]}"

        return CloudBucketRecord(
            record_id=record_id,
            bucket_name=bucket_name,
            provider=provider,
            access_level=access_level,
            region=region,
            url=url,
            evidence_level=CloudEnumEvidenceLevel.E0,
            source_tool="cloud-enum",
            raw_json=data,
            validation_note=f"Bucket: {bucket_name} | Provider: {provider} | Access: {access_level}",
        )

    @staticmethod
    def _parse_text_line(line: str) -> Optional[CloudBucketRecord]:
        """
        محلل نصي بسيط لـ cloud-enum (إذا لم يكن مخرج JSON).
        """
        # مثال: bucket_name | provider | access_level | region | url
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 2:
            return None

        bucket_name = parts[0] or ""
        provider = parts[1] if len(parts) > 1 else ""
        access_level = parts[2] if len(parts) > 2 else "unknown"
        region = parts[3] if len(parts) > 3 else ""
        url = parts[4] if len(parts) > 4 else ""

        digest_src = f"{bucket_name}:{provider}"
        record_id = f"cb_{__import__('hashlib').md5(digest_src.encode()).hexdigest()[:10]}"

        return CloudBucketRecord(
            record_id=record_id,
            bucket_name=bucket_name,
            provider=provider,
            access_level=access_level,
            region=region,
            url=url,
            evidence_level=CloudEnumEvidenceLevel.E0,
            source_tool="cloud-enum",
            raw_json={},
            validation_note=f"Bucket: {bucket_name} | Provider: {provider} | Access: {access_level}",
        )

    def normalize_batch(self, cloud_enum_stdout: str) -> List[CloudBucketRecord]:
        """يحول مخرجات cloud-enum إلى قائمة سجلات."""
        records: List[CloudBucketRecord] = []
        for line in cloud_enum_stdout.splitlines():
            rec = self.normalize_cloud_enum_line(line)
            if rec:
                records.append(rec)
        return records


class DuplicateDetector:
    """
    L2: يكتشف الدلاء المكررة (نفس bucket_name) ويجمعها في مجموعة واحدة.
    """

    def __init__(self):
        self._groups: Dict[str, List[CloudBucketRecord]] = defaultdict(list)

    def add(self, record: CloudBucketRecord) -> Optional[List[CloudBucketRecord]]:
        key = record.canonical_key
        self._groups[key].append(record)
        if len(self._groups[key]) > 1:
            return self._groups[key]
        return None

    def flush(self) -> Dict[str, List[CloudBucketRecord]]:
        groups = dict(self._groups)
        self._groups.clear()
        return groups


class EvidenceReviewer:
    """
    L5 Verification: يراجع الأدلة المرتبطة بكل دلو ويحدد:
      - هل الأدلة كافية لدعم الملف؟ (evidence_status)
      - هل الدلو يحتاج تحقق إضافي؟ (needs_verification)
      - درجة الثقة المبدئية (بدون LLM)
    """

    def __init__(self):
        pass

    def review(self, record: CloudBucketRecord) -> Dict[str, Any]:
        """
        يُرجع تقرير مراجعة للسجل.
        """
        issues: List[str] = []
        confidence = 0.2  # قاعدة: نتيجة cloud-enum واحدة غير كافية للإثبات الكامل

        # وجود اسم الدلو = دليل أقوى
        if record.bucket_name:
            confidence += 0.2
        else:
            issues.append("لا يوجد اسم دلو (bucket_name)")

        # وجود موفر (provider) = دليل أقوى
        if record.provider:
            confidence += 0.15
        else:
            issues.append("لا يوجد موفر سحابي (provider)")

        # وجود منطقة (region) = دليل أقوى
        if record.region:
            confidence += 0.1
        else:
            issues.append("لا توجد منطقة (region)")

        # وجود URL = دليل أقوى
        if record.url:
            confidence += 0.15
        else:
            issues.append("لا يوجد رابط (url)")

        # تقييم الوصول العام (public) = خطر أعلى
        if record.access_level.lower() == "public":
            confidence += 0.15
            issues.append("الدلو عام (public) — خطر عالي للتعرض للبيانات")
        elif record.access_level.lower() == "private":
            confidence += 0.05
            issues.append("الدلو خاص (private) — خطر أقل")
        else:
            issues.append("لم يتم تحديد مستوى الوصول (access_level)")

        # إذا كانت الأدلة مكتملة → E1
        if record.bucket_name and record.provider:
            record.evidence_level = CloudEnumEvidenceLevel.E1

        confidence = max(0.0, min(confidence, 1.0))
        label = self._label(confidence)

        return {
            "record_id": record.record_id,
            "bucket_name": record.bucket_name,
            "provider": record.provider,
            "access_level": record.access_level,
            "region": record.region,
            "url": record.url,
            "evidence_level": record.evidence_level,
            "evidence_status": "sufficient" if record.evidence_level == CloudEnumEvidenceLevel.E1 else "insufficient",
            "confidence": round(confidence, 2),
            "confidence_label": label,
            "is_public": record.access_level.lower() == "public",
            "needs_verification": record.evidence_level != CloudEnumEvidenceLevel.E1,
            "issues": issues,
            "recommendation": (
                "دلو عام (E1) — يُنصح بإغلاق الوصول العام وتشفير البيانات."
                if record.evidence_level == CloudEnumEvidenceLevel.E1 else
                "الدلو يحتاج أدلة إضافية قبل اعتباره-threat."
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
