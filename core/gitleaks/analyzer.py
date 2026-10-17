"""Gitleaks Secret Context Analyzer — L2 AI Analyzer + L5 Evidence Reviewer"""
from __future__ import annotations

import json
import logging
from typing import List, Dict, Any, Optional
from collections import defaultdict

from core.gitleaks.schemas import (
    GitleaksFindingRecord, GitleaksEvidenceLevel,
)

log = logging.getLogger("gitleaks.analyzer")


class GitleaksNormalizer:
    @staticmethod
    def normalize_gitleaks_json_line(line: str) -> Optional[GitleaksFindingRecord]:
        line = line.strip()
        if not line:
            return None
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        digest_src = f"{data.get('RuleID', '')}:{data.get('File', '')}:{data.get('StartLine', 0)}"
        record_id = f"gl_{__import__('hashlib').md5(digest_src.encode()).hexdigest()[:10]}"

        return GitleaksFindingRecord(
            record_id=record_id,
            rule_id=data.get("RuleID", "") or "",
            secret_type=data.get("SecretType", "") or "",
            file_path=data.get("File", "") or "",
            start_line=data.get("StartLine", 0),
            end_line=data.get("EndLine", 0),
            secret_value=data.get("Secret"),
            evidence_level=GitleaksEvidenceLevel.E0,
            source_tool="gitleaks",
            raw_json=data,
            validation_note=f"Rule: {data.get('RuleID', '')} | File: {data.get('File', '')}:{data.get('StartLine', 0)}",
        )

    def normalize_batch(self, gitleaks_stdout: str) -> List[GitleaksFindingRecord]:
        records: List[GitleaksFindingRecord] = []
        for line in gitleaks_stdout.splitlines():
            rec = self.normalize_gitleaks_json_line(line)
            if rec:
                records.append(rec)
        return records


class DuplicateDetector:
    def __init__(self):
        self._seen: set = set()

    def add(self, record: GitleaksFindingRecord) -> bool:
        key = f"{record.rule_id}:{record.file_path}:{record.start_line}"
        if key in self._seen:
            return True
        self._seen.add(key)
        return False

    def flush(self) -> int:
        count = len(self._seen)
        self._seen.clear()
        return count


class EvidenceReviewer:
    HIGH_RISK_TYPES = {"api_key", "aws_access_key", "private_key", "password", "token", "database_url"}

    def __init__(self):
        pass

    def review(self, record: GitleaksFindingRecord) -> Dict[str, Any]:
        issues: List[str] = []
        confidence = 0.2

        if record.secret_value:
            confidence += 0.3
        else:
            issues.append("لا توجد قيمة سرية مرئية")

        if record.rule_id:
            confidence += 0.2
        else:
            issues.append("لا يوجد معرف قاعدة")

        if record.secret_type.lower() in self.HIGH_RISK_TYPES:
            confidence += 0.2
        else:
            issues.append("نوع سر غير مصنف كخطر عالٍ")

        if record.file_path:
            confidence += 0.1

        if record.secret_value and record.secret_type:
            record.evidence_level = GitleaksEvidenceLevel.E1

        confidence = max(0.0, min(confidence, 1.0))

        return {
            "record_id": record.record_id,
            "rule_id": record.rule_id,
            "secret_type": record.secret_type,
            "file_path": record.file_path,
            "start_line": record.start_line,
            "end_line": record.end_line,
            "secret_value": record.secret_value,
            "evidence_level": record.evidence_level,
            "evidence_status": "sufficient" if record.evidence_level == GitleaksEvidenceLevel.E1 else "insufficient",
            "confidence": round(confidence, 2),
            "confidence_label": "strong" if confidence >= 0.75 else "probable" if confidence >= 0.50 else "possible" if confidence >= 0.25 else "weak",
            "needs_verification": record.evidence_level != GitleaksEvidenceLevel.E1,
            "issues": issues,
            "recommendation": (
                "إزالة السر من المستودع وتدوير جميع بيانات الاعتماد المكشوفة فورًا."
                if record.evidence_level == GitleaksEvidenceLevel.E1 else
                "السر يحتاج إخفاء وتعديل بعد التأكيد."
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
