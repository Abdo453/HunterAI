"""Subjack Subdomain Takeover — L2 AI Analyzer + L5 Evidence Reviewer"""
from __future__ import annotations

import json
import logging
from typing import List, Dict, Any, Optional
from collections import defaultdict

from core.subjack.schemas import (
    SubdomainTakeoverRecord, TakeoverProfile,
    SubjackEvidenceLevel,
)

log = logging.getLogger("subjack.analyzer")


class SubjackNormalizer:
    @staticmethod
    def normalize_subjack_json_line(line: str) -> Optional[SubdomainTakeoverRecord]:
        line = line.strip()
        if not line:
            return None
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        subdomain = data.get("subdomain", "") or ""
        cname = data.get("cname", "")
        status_code = data.get("status_code")
        fingerprint = data.get("fingerprint", "")
        takeover_risk = data.get("takeover_risk", "low")

        digest_src = f"{subdomain}:{cname or ''}"
        record_id = f"sj_{__import__('hashlib').md5(digest_src.encode()).hexdigest()[:10]}"

        return SubdomainTakeoverRecord(
            record_id=record_id,
            subdomain=subdomain,
            cname=cname,
            status_code=status_code,
            fingerprint=fingerprint,
            takeover_risk=takeover_risk,
            evidence_level=SubjackEvidenceLevel.E0,
            source_tool="subjack",
            raw_json=data,
            validation_note=f"Subdomain: {subdomain} | CNAME: {cname or '—'} | Risk: {takeover_risk}",
        )

    def normalize_batch(self, subjack_stdout: str) -> List[SubdomainTakeoverRecord]:
        records: List[SubdomainTakeoverRecord] = []
        for line in subjack_stdout.splitlines():
            rec = self.normalize_subjack_json_line(line)
            if rec:
                records.append(rec)
        return records


class DuplicateDetector:
    def __init__(self):
        self._groups: Dict[str, List[SubdomainTakeoverRecord]] = defaultdict(list)

    def add(self, record: SubdomainTakeoverRecord) -> Optional[List[SubdomainTakeoverRecord]]:
        key = record.canonical_key
        self._groups[key].append(record)
        if len(self._groups[key]) > 1:
            return self._groups[key]
        return None

    def flush(self) -> Dict[str, List[SubdomainTakeoverRecord]]:
        groups = dict(self._groups)
        self._groups.clear()
        return groups


class EvidenceReviewer:
    def __init__(self):
        pass

    def review(self, record: SubdomainTakeoverRecord) -> Dict[str, Any]:
        issues: List[str] = []
        confidence = 0.2

        if record.cname:
            confidence += 0.2
        else:
            issues.append("لا يوجد CNAME مسجل للنطاق الفرعي")

        if record.status_code is not None:
            confidence += 0.15
        else:
            issues.append("لا يوجد رمز حالة HTTP")

        risk_scores = {"high": 0.25, "medium": 0.15, "low": 0.05, "none": 0.0}
        risk_score = risk_scores.get(record.takeover_risk.lower(), 0.0)
        confidence += risk_score

        if record.takeover_risk.lower() == "high":
            issues.append("خطر takeover عالٍ — النطاق الفرعي معلق且 لا يُوجَّه لخدمة فعلية")
        elif record.takeover_risk.lower() == "medium":
            issues.append("خطر takeover متوسط — يحتاج تحقق إضافي")

        if record.cname and record.status_code is not None:
            record.evidence_level = SubjackEvidenceLevel.E1

        confidence = max(0.0, min(confidence, 1.0))
        label = self._label(confidence)

        return {
            "record_id": record.record_id,
            "subdomain": record.subdomain,
            "cname": record.cname,
            "status_code": record.status_code,
            "fingerprint": record.fingerprint,
            "takeover_risk": record.takeover_risk,
            "evidence_level": record.evidence_level,
            "evidence_status": "sufficient" if record.evidence_level == SubjackEvidenceLevel.E1 else "insufficient",
            "confidence": round(confidence, 2),
            "confidence_label": label,
            "is_vulnerable": record.takeover_risk.lower() in ("high", "medium"),
            "needs_verification": record.evidence_level != SubjackEvidenceLevel.E1,
            "issues": issues,
            "recommendation": (
                "نطاق فرعي معلق (E1) — يُنصح باستعادة النطاق أو حذف سجل DNS الخاطئ."
                if record.evidence_level == SubjackEvidenceLevel.E1 else
                "النطاق يحتاج أدلة إضافية قبل اعتباره-threat."
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
