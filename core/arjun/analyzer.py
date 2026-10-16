"""Arjun Parameter Intelligence — L2 AI Analyzer + L5 Evidence Reviewer"""
from __future__ import annotations

import json
import logging
from typing import List, Dict, Any, Optional
from collections import defaultdict

from core.arjun.schemas import ArjunParameterRecord, ArjunEvidenceLevel

log = logging.getLogger("arjun.analyzer")


class ArjunNormalizer:
    @staticmethod
    def normalize_arjun_json_line(line: str) -> Optional[ArjunParameterRecord]:
        line = line.strip()
        if not line:
            return None
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        digest_src = f"{data.get('url', '')}:{data.get('parameter', '')}"
        record_id = f"arj_{__import__('hashlib').md5(digest_src.encode()).hexdigest()[:10]}"

        return ArjunParameterRecord(
            record_id=record_id,
            parameter=data.get("parameter", "") or "",
            url=data.get("url", "") or "",
            method=data.get("method", "GET") or "GET",
            evidence_level=ArjunEvidenceLevel.E0,
            source_tool="arjun",
            raw_json=data,
            validation_note=f"Parameter: {data.get('parameter', '')} | Method: {data.get('method', 'GET')}",
        )

    def normalize_batch(self, arjun_stdout: str) -> List[ArjunParameterRecord]:
        records: List[ArjunParameterRecord] = []
        for line in arjun_stdout.splitlines():
            rec = self.normalize_arjun_json_line(line)
            if rec:
                records.append(rec)
        return records


class DuplicateDetector:
    def __init__(self):
        self._seen: set = set()

    def add(self, record: ArjunParameterRecord) -> bool:
        key = f"{record.url}:{record.parameter}:{record.method}"
        if key in self._seen:
            return True
        self._seen.add(key)
        return False

    def flush(self) -> int:
        count = len(self._seen)
        self._seen.clear()
        return count


class EvidenceReviewer:
    SENSITIVE_PARAMETERS = {"id", "user", "username", "email", "token", "session", "password", "auth", "key", "secret"}

    def __init__(self):
        pass

    def review(self, record: ArjunParameterRecord) -> Dict[str, Any]:
        issues: List[str] = []
        confidence = 0.2

        if record.parameter:
            confidence += 0.25
        else:
            issues.append("لا يوجد معلمة")

        if record.url:
            confidence += 0.2
        else:
            issues.append("لا يوجد رابط")

        if record.method in ("GET", "POST", "PUT", "DELETE", "PATCH"):
            confidence += 0.15
        else:
            issues.append("طريقة HTTP غير عادية")

        if record.parameter.lower() in self.SENSITIVE_PARAMETERS:
            confidence += 0.2
            issues.append("معلمة حساسة — قد تكون عرضة للاستغلال")

        if record.parameter and record.url:
            record.evidence_level = ArjunEvidenceLevel.E1

        confidence = max(0.0, min(confidence, 1.0))

        return {
            "record_id": record.record_id,
            "parameter": record.parameter,
            "url": record.url,
            "method": record.method,
            "evidence_level": record.evidence_level,
            "evidence_status": "sufficient" if record.evidence_level == ArjunEvidenceLevel.E1 else "insufficient",
            "confidence": round(confidence, 2),
            "confidence_label": "strong" if confidence >= 0.75 else "probable" if confidence >= 0.50 else "possible" if confidence >= 0.25 else "weak",
            "needs_verification": record.evidence_level != ArjunEvidenceLevel.E1,
            "issues": issues,
            "recommendation": "اختبار المعلمة المكتشفة يدويًا للكشف عن الثغرات المحتملة.",
        }
