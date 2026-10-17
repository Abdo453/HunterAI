"""Trivy Dependency Risk Analyzer — L2 AI Analyzer + L5 Evidence Reviewer"""
from __future__ import annotations

import json
import logging
from typing import List, Dict, Any, Optional
from collections import defaultdict

from core.trivy.schemas import (
    TrivyVulnerabilityRecord, TrivyEvidenceLevel,
)

log = logging.getLogger("trivy.analyzer")


class TrivyNormalizer:
    @staticmethod
    def normalize_trivy_json_line(line: str) -> Optional[TrivyVulnerabilityRecord]:
        line = line.strip()
        if not line:
            return None
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        digest_src = f"{data.get('VulnerabilityID', '')}:{data.get('PkgName', '')}:{data.get('InstalledVersion', '')}"
        record_id = f"tr_{__import__('hashlib').md5(digest_src.encode()).hexdigest()[:10]}"

        return TrivyVulnerabilityRecord(
            record_id=record_id,
            vulnerability_id=data.get("VulnerabilityID", "") or "",
            package_name=data.get("PkgName", "") or "",
            installed_version=data.get("InstalledVersion", "") or "",
            fixed_version=data.get("FixedVersion"),
            severity=data.get("Severity", "") or "",
            title=data.get("Title", "") or "",
            evidence_level=TrivyEvidenceLevel.E0,
            source_tool="trivy",
            raw_json=data,
            validation_note=f"Package: {data.get('PkgName', '')} | Version: {data.get('InstalledVersion', '')}",
        )

    def normalize_batch(self, trivy_stdout: str) -> List[TrivyVulnerabilityRecord]:
        records: List[TrivyVulnerabilityRecord] = []
        for line in trivy_stdout.splitlines():
            rec = self.normalize_trivy_json_line(line)
            if rec:
                records.append(rec)
        return records


class DuplicateDetector:
    def __init__(self):
        self._seen: set = set()

    def add(self, record: TrivyVulnerabilityRecord) -> bool:
        key = f"{record.vulnerability_id}:{record.package_name}"
        if key in self._seen:
            return True
        self._seen.add(key)
        return False

    def flush(self) -> int:
        count = len(self._seen)
        self._seen.clear()
        return count


class EvidenceReviewer:
    HIGH_SEVERITY = {"CRITICAL", "HIGH"}

    def __init__(self):
        pass

    def review(self, record: TrivyVulnerabilityRecord) -> Dict[str, Any]:
        issues: List[str] = []
        confidence = 0.2

        if record.vulnerability_id:
            confidence += 0.2
        else:
            issues.append("لا يوجد معرف ثغرة")

        if record.package_name:
            confidence += 0.2
        else:
            issues.append("لا يوجد اسم حزمة")

        if record.severity:
            confidence += 0.2
        else:
            issues.append("لا توجد درجة خطورة")

        if record.fixed_version:
            confidence += 0.2
        else:
            issues.append("لا يوجد إصدار مصحح")

        if record.severity in self.HIGH_SEVERITY and record.fixed_version:
            record.evidence_level = TrivyEvidenceLevel.E1

        confidence = max(0.0, min(confidence, 1.0))

        return {
            "record_id": record.record_id,
            "vulnerability_id": record.vulnerability_id,
            "package_name": record.package_name,
            "installed_version": record.installed_version,
            "fixed_version": record.fixed_version,
            "severity": record.severity,
            "title": record.title,
            "evidence_level": record.evidence_level,
            "evidence_status": "sufficient" if record.evidence_level == TrivyEvidenceLevel.E1 else "insufficient",
            "confidence": round(confidence, 2),
            "confidence_label": "strong" if confidence >= 0.75 else "probable" if confidence >= 0.50 else "possible" if confidence >= 0.25 else "weak",
            "needs_verification": record.evidence_level != TrivyEvidenceLevel.E1,
            "issues": issues,
            "recommendation": (
                "تحديث الحزمة إلى الإصدار المصحح في أقرب وقت ممكن."
                if record.evidence_level == TrivyEvidenceLevel.E1 else
                "الثغرة تحتاج أدلة إضافية قبل الاعتماد عليها."
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
