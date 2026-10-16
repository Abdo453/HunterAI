"""SQLmap Result Interpreter — L2 AI Analyzer + L5 Evidence Reviewer"""
from __future__ import annotations

import json
import logging
from typing import List, Dict, Any, Optional
from collections import defaultdict

from core.sqlmap.schemas import SQLmapFindingRecord, SQLmapEvidenceLevel

log = logging.getLogger("sqlmap.analyzer")


class SQLmapNormalizer:
    @staticmethod
    def normalize_sqlmap_json_line(line: str) -> Optional[SQLmapFindingRecord]:
        line = line.strip()
        if not line:
            return None
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        digest_src = f"{data.get('parameter', '')}:{data.get('payload', '')}"
        record_id = f"sq_{__import__('hashlib').md5(digest_src.encode()).hexdigest()[:10]}"

        return SQLmapFindingRecord(
            record_id=record_id,
            parameter=data.get("parameter", "") or "",
            payload=data.get("payload", "") or "",
            technique=data.get("technique", "unknown"),
            dbms=data.get("dbms"),
            evidence=data.get("evidence", "") or "",
            evidence_level=SQLmapEvidenceLevel.E0,
            source_tool="sqlmap",
            raw_json=data,
            validation_note=f"Parameter: {data.get('parameter', '')} | Technique: {data.get('technique', 'unknown')}",
        )

    def normalize_batch(self, sqlmap_stdout: str) -> List[SQLmapFindingRecord]:
        records: List[SQLmapFindingRecord] = []
        for line in sqlmap_stdout.splitlines():
            rec = self.normalize_sqlmap_json_line(line)
            if rec:
                records.append(rec)
        return records


class DuplicateDetector:
    def __init__(self):
        self._seen: set = set()

    def add(self, record: SQLmapFindingRecord) -> bool:
        key = f"{record.parameter}:{record.technique}"
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

    def review(self, record: SQLmapFindingRecord) -> Dict[str, Any]:
        issues: List[str] = []
        confidence = 0.2

        if record.evidence:
            confidence += 0.3
        else:
            issues.append("لا توجد أدلة استجابة")

        if record.dbms:
            confidence += 0.2
        else:
            issues.append("لم يتم تحديد نظام إدارة قواعد البيانات")

        if record.technique in ("boolean-based", "time-based", "error-based", "union-query"):
            confidence += 0.2
        else:
            issues.append("تقنية حقن غير محددة أو ضعيفة")

        if record.parameter:
            confidence += 0.1
        else:
            issues.append("لا يوجد معلمة مستهدفة")

        confidence = max(0.0, min(confidence, 1.0))
        if confidence >= 0.5:
            record.evidence_level = SQLmapEvidenceLevel.E1

        return {
            "record_id": record.record_id,
            "parameter": record.parameter,
            "technique": record.technique,
            "dbms": record.dbms,
            "evidence_level": record.evidence_level,
            "evidence_status": "sufficient" if confidence >= 0.5 else "insufficient",
            "confidence": round(confidence, 2),
            "confidence_label": "strong" if confidence >= 0.75 else "probable" if confidence >= 0.50 else "possible" if confidence >= 0.25 else "weak",
            "needs_verification": confidence < 0.75,
            "issues": issues,
            "recommendation": "تحقق من الحقن يدويًا باستخدام sqlmap مع مستوى أعلى من المخاطرة والتأكيد على الاستجابة.",
        }
