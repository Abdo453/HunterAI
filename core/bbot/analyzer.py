"""BBOT Asset Relationship Analyzer — L2 AI Analyzer + L5 Evidence Reviewer"""
from __future__ import annotations

import json
import logging
from typing import List, Dict, Any, Optional
from collections import defaultdict

from core.bbot.schemas import BBOTAssetRecord, BBOTEvidenceLevel

log = logging.getLogger("bbot.analyzer")


class BBOTNormalizer:
    @staticmethod
    def normalize_bbot_json_line(line: str) -> Optional[BBOTAssetRecord]:
        line = line.strip()
        if not line:
            return None
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        digest_src = f"{data.get('type', '')}:{data.get('value', '')}"
        record_id = f"bb_{__import__('hashlib').md5(digest_src.encode()).hexdigest()[:10]}"

        return BBOTAssetRecord(
            record_id=record_id,
            asset_type=data.get("type", "") or "",
            asset_value=data.get("value", "") or "",
            source_module=data.get("module", "unknown"),
            relationship=data.get("relationship"),
            related_asset=data.get("related_to"),
            evidence_level=BBOTEvidenceLevel.E0,
            source_tool="bbot",
            raw_json=data,
            validation_note=f"Type: {data.get('type', '')} | Module: {data.get('module', 'unknown')}",
        )

    def normalize_batch(self, bbot_stdout: str) -> List[BBOTAssetRecord]:
        records: List[BBOTAssetRecord] = []
        for line in bbot_stdout.splitlines():
            rec = self.normalize_bbot_json_line(line)
            if rec:
                records.append(rec)
        return records


class DuplicateDetector:
    def __init__(self):
        self._seen: set = set()

    def add(self, record: BBOTAssetRecord) -> bool:
        key = record.canonical_key
        if key in self._seen:
            return True
        self._seen.add(key)
        return False

    def flush(self) -> int:
        count = len(self._seen)
        self._seen.clear()
        return count


class EvidenceReviewer:
    def __init__(self):
        pass

    def review(self, record: BBOTAssetRecord) -> Dict[str, Any]:
        issues: List[str] = []
        confidence = 0.2

        if record.source_module != "unknown":
            confidence += 0.2
        else:
            issues.append("وحدة مصدر غير معروفة")

        if record.relationship:
            confidence += 0.2
        else:
            issues.append("لا توجد علاقة محددة")

        if record.related_asset:
            confidence += 0.2
        else:
            issues.append("لا يوجد أصل مرتبط")

        if record.asset_value:
            confidence += 0.15
        else:
            issues.append("قيمة أصل غير محددة")

        if record.source_module != "unknown" and (record.relationship or record.related_asset):
            record.evidence_level = BBOTEvidenceLevel.E1

        confidence = max(0.0, min(confidence, 1.0))

        return {
            "record_id": record.record_id,
            "asset_type": record.asset_type,
            "asset_value": record.asset_value,
            "source_module": record.source_module,
            "relationship": record.relationship,
            "related_asset": record.related_asset,
            "evidence_level": record.evidence_level,
            "evidence_status": "sufficient" if record.evidence_level == BBOTEvidenceLevel.E1 else "insufficient",
            "confidence": round(confidence, 2),
            "confidence_label": "strong" if confidence >= 0.75 else "probable" if confidence >= 0.50 else "possible" if confidence >= 0.25 else "weak",
            "needs_verification": record.evidence_level != BBOTEvidenceLevel.E1,
            "issues": issues,
            "recommendation": "تحقق من العلاقة بين الأصول يدويًا قبل Adoptionها في نطاق التحقيق.",
        }
