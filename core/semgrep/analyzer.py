"""Semgrep Code Finding Analyzer — L2 AI Analyzer + L5 Evidence Reviewer"""
from __future__ import annotations

import json
import logging
from typing import List, Dict, Any, Optional
from collections import defaultdict

from core.semgrep.schemas import SemgrepFindingRecord, SemgrepEvidenceLevel

log = logging.getLogger("semgrep.analyzer")


class SemgrepNormalizer:
    @staticmethod
    def normalize_semgrep_json_line(line: str) -> Optional[SemgrepFindingRecord]:
        line = line.strip()
        if not line:
            return None
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        results = data.get("results", []) if isinstance(data, dict) else []
        records: List[SemgrepFindingRecord] = []
        for item in results:
            digest_src = f"{item.get('rule_id', '')}:{item.get('path', '')}:{item.get('start', {}).get('line', 0)}"
            record_id = f"sm_{__import__('hashlib').md5(digest_src.encode()).hexdigest()[:10]}"

            records.append(SemgrepFindingRecord(
                record_id=record_id,
                rule_id=item.get("rule_id", "") or "",
                rule_message=item.get("extra", {}).get("message", "") or "",
                file_path=item.get("path", "") or "",
                line_number=item.get("start", {}).get("line", 0),
                severity=item.get("extra", {}).get("severity", "INFO"),
                code_snippet=item.get("extra", {}).get("lines"),
                evidence_level=SemgrepEvidenceLevel.E0,
                source_tool="semgrep",
                raw_json=item,
                validation_note=f"Rule: {item.get('rule_id', '')} | Severity: {item.get('extra', {}).get('severity', 'INFO')}",
            ))
        return records if records else None

    def normalize_batch(self, semgrep_stdout: str) -> List[SemgrepFindingRecord]:
        records: List[SemgrepFindingRecord] = []
        try:
            data = json.loads(semgrep_stdout)
            results = data.get("results", []) if isinstance(data, dict) else []
            for item in results:
                digest_src = f"{item.get('rule_id', '')}:{item.get('path', '')}:{item.get('start', {}).get('line', 0)}"
                record_id = f"sm_{__import__('hashlib').md5(digest_src.encode()).hexdigest()[:10]}"
                records.append(SemgrepFindingRecord(
                    record_id=record_id,
                    rule_id=item.get("rule_id", "") or "",
                    rule_message=item.get("extra", {}).get("message", "") or "",
                    file_path=item.get("path", "") or "",
                    line_number=item.get("start", {}).get("line", 0),
                    severity=item.get("extra", {}).get("severity", "INFO"),
                    code_snippet=item.get("extra", {}).get("lines"),
                    evidence_level=SemgrepEvidenceLevel.E0,
                    source_tool="semgrep",
                    raw_json=item,
                    validation_note=f"Rule: {item.get('rule_id', '')} | Severity: {item.get('extra', {}).get('severity', 'INFO')}",
                ))
        except json.JSONDecodeError:
            for line in semgrep_stdout.splitlines():
                recs = self.normalize_semgrep_json_line(line)
                if recs:
                    records.extend(recs)
        return records


class DuplicateDetector:
    def __init__(self):
        self._seen: set = set()

    def add(self, record: SemgrepFindingRecord) -> bool:
        key = f"{record.rule_id}:{record.file_path}:{record.line_number}"
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

    def review(self, record: SemgrepFindingRecord) -> Dict[str, Any]:
        issues: List[str] = []
        confidence = 0.2

        if record.rule_message:
            confidence += 0.2
        else:
            issues.append("لا توجد رسالة قاعدة")

        if record.code_snippet:
            confidence += 0.2
        else:
            issues.append("لا توجد مقتطف كودي")

        if record.severity in ("ERROR", "WARNING", "HIGH", "CRITICAL"):
            confidence += 0.2
        elif record.severity in ("INFO", "LOW"):
            confidence += 0.1
        else:
            issues.append("خطورة غير محددة")

        if record.file_path:
            confidence += 0.1

        if record.code_snippet and record.rule_message:
            record.evidence_level = SemgrepEvidenceLevel.E1

        confidence = max(0.0, min(confidence, 1.0))

        return {
            "record_id": record.record_id,
            "rule_id": record.rule_id,
            "file_path": record.file_path,
            "line_number": record.line_number,
            "severity": record.severity,
            "evidence_level": record.evidence_level,
            "evidence_status": "sufficient" if record.evidence_level == SemgrepEvidenceLevel.E1 else "insufficient",
            "confidence": round(confidence, 2),
            "confidence_label": "strong" if confidence >= 0.75 else "probable" if confidence >= 0.50 else "possible" if confidence >= 0.25 else "weak",
            "needs_verification": record.evidence_level != SemgrepEvidenceLevel.E1,
            "issues": issues,
            "recommendation": "راجع المقتطف الكودي يدويًا وتحقق من وجود الثغرة الفعلية قبل التبليغ.",
        }
