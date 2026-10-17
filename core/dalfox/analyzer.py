"""Dalfox XSS Context Analyzer — L2 AI Analyzer + L5 Evidence Reviewer"""
from __future__ import annotations

import json
import logging
from typing import List, Dict, Any, Optional
from collections import defaultdict

from core.dalfox.schemas import (
    DalfoxFindingRecord, DalfoxEvidenceLevel,
)

log = logging.getLogger("dalfox.analyzer")


class DalfoxNormalizer:
    @staticmethod
    def normalize_dalfox_json_line(line: str) -> Optional[DalfoxFindingRecord]:
        line = line.strip()
        if not line:
            return None
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        digest_src = f"{data.get('url', '')}:{data.get('injection_point', '')}:{data.get('payload', '')}"
        record_id = f"dl_{__import__('hashlib').md5(digest_src.encode()).hexdigest()[:10]}"

        return DalfoxFindingRecord(
            record_id=record_id,
            url=data.get("url", "") or "",
            injection_point=data.get("injection_point", "") or "",
            payload=data.get("payload", "") or "",
            type=data.get("type", "") or "",
            evidence=data.get("evidence", "") or "",
            evidence_level=DalfoxEvidenceLevel.E0,
            source_tool="dalfox",
            raw_json=data,
            validation_note=f"Type: {data.get('type', '')} | Point: {data.get('injection_point', '')}",
        )

    def normalize_batch(self, dalfox_stdout: str) -> List[DalfoxFindingRecord]:
        records: List[DalfoxFindingRecord] = []
        for line in dalfox_stdout.splitlines():
            rec = self.normalize_dalfox_json_line(line)
            if rec:
                records.append(rec)
        return records


class DuplicateDetector:
    def __init__(self):
        self._seen: set = set()

    def add(self, record: DalfoxFindingRecord) -> bool:
        key = f"{record.url}:{record.injection_point}:{record.type}"
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

    def review(self, record: DalfoxFindingRecord) -> Dict[str, Any]:
        issues: List[str] = []
        confidence = 0.2

        if record.evidence:
            confidence += 0.3
        else:
            issues.append("لا توجد أدلة انعكاس")

        if record.payload:
            confidence += 0.2
        else:
            issues.append("لا يوجد حمولة")

        if record.type:
            confidence += 0.15
        else:
            issues.append("نوع الثغرة غير محدد")

        if record.url:
            confidence += 0.1

        if record.evidence and record.payload:
            record.evidence_level = DalfoxEvidenceLevel.E1

        confidence = max(0.0, min(confidence, 1.0))

        return {
            "record_id": record.record_id,
            "url": record.url,
            "injection_point": record.injection_point,
            "type": record.type,
            "payload": record.payload,
            "evidence": record.evidence,
            "evidence_level": record.evidence_level,
            "evidence_status": "sufficient" if record.evidence_level == DalfoxEvidenceLevel.E1 else "insufficient",
            "confidence": round(confidence, 2),
            "confidence_label": "strong" if confidence >= 0.75 else "probable" if confidence >= 0.50 else "possible" if confidence >= 0.25 else "weak",
            "is_vulnerable": record.type in ("reflected", "stored"),
            "needs_verification": record.evidence_level != DalfoxEvidenceLevel.E1,
            "issues": issues,
            "recommendation": (
                "تحقق من انعكاس XSS يدويًا في المتصفح قبل التبليغ."
                if record.evidence_level == DalfoxEvidenceLevel.E1 else
                "تحقق من انعكاس XSS يدويًا قبل التبليغ."
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
