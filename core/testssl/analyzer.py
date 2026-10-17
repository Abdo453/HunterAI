"""testssl.sh TLS Configuration Intelligence — L2 AI Analyzer + L5 Evidence Reviewer"""
from __future__ import annotations

import json
import logging
from typing import List, Dict, Any, Optional
from collections import defaultdict

from core.testssl.schemas import (
    TestsslFindingRecord, TestsslEvidenceLevel,
)

log = logging.getLogger("testssl.analyzer")


class TestsslNormalizer:
    @staticmethod
    def normalize_testssl_json_line(line: str) -> Optional[TestsslFindingRecord]:
        line = line.strip()
        if not line:
            return None
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        digest_src = f"{data.get('severity', '')}:{data.get('title', '')}:{data.get('description', '')}"
        record_id = f"ts_{__import__('hashlib').md5(digest_src.encode()).hexdigest()[:10]}"

        return TestsslFindingRecord(
            record_id=record_id,
            severity=data.get("severity", "") or "",
            title=data.get("title", "") or "",
            description=data.get("description", "") or "",
            cve=data.get("cve"),
            evidence_level=TestsslEvidenceLevel.E0,
            source_tool="testssl.sh",
            raw_json=data,
            validation_note=f"Severity: {data.get('severity', '')} | Title: {data.get('title', '')}",
        )

    def normalize_batch(self, testssl_stdout: str) -> List[TestsslFindingRecord]:
        records: List[TestsslFindingRecord] = []
        for line in testssl_stdout.splitlines():
            rec = self.normalize_testssl_json_line(line)
            if rec:
                records.append(rec)
        return records


class DuplicateDetector:
    def __init__(self):
        self._seen: set = set()

    def add(self, record: TestsslFindingRecord) -> bool:
        key = f"{record.severity}:{record.title}"
        if key in self._seen:
            return True
        self._seen.add(key)
        return False

    def flush(self) -> int:
        count = len(self._seen)
        self._seen.clear()
        return count


class EvidenceReviewer:
    HIGH_SEVERITY = {"CRITICAL", "HIGH", "ERROR", "WARNING"}

    def __init__(self):
        pass

    def review(self, record: TestsslFindingRecord) -> Dict[str, Any]:
        issues: List[str] = []
        confidence = 0.2

        if record.severity:
            confidence += 0.2
        else:
            issues.append("لا توجد درجة خطورة")

        if record.title:
            confidence += 0.2
        else:
            issues.append("لا يوجد عنوان")

        if record.description:
            confidence += 0.2
        else:
            issues.append("لا يوجد وصف")

        if record.cve:
            confidence += 0.2
        else:
            issues.append("لا يوجد معرف CVE")

        if record.severity in self.HIGH_SEVERITY and record.description:
            record.evidence_level = TestsslEvidenceLevel.E1

        confidence = max(0.0, min(confidence, 1.0))

        return {
            "record_id": record.record_id,
            "severity": record.severity,
            "title": record.title,
            "description": record.description,
            "cve": record.cve,
            "evidence_level": record.evidence_level,
            "evidence_status": "sufficient" if record.evidence_level == TestsslEvidenceLevel.E1 else "insufficient",
            "confidence": round(confidence, 2),
            "confidence_label": "strong" if confidence >= 0.75 else "probable" if confidence >= 0.50 else "possible" if confidence >= 0.25 else "weak",
            "needs_verification": record.evidence_level != TestsslEvidenceLevel.E1,
            "issues": issues,
            "recommendation": (
                "مراجعة إعدادات TLS وتطبيق التوصيات الأمنية المقترحة."
                if record.evidence_level == TestsslEvidenceLevel.E1 else
                "الثغرة تحتاج أدلة إضافية قبل اعتمادها."
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
