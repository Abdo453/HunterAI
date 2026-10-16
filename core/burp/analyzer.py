"""Burp Suite Traffic Intelligence — L2 AI Analyzer + L5 Evidence Reviewer"""
from __future__ import annotations

import json
import logging
from typing import List, Dict, Any, Optional
from collections import defaultdict

from core.burp.schemas import BurpTrafficRecord, BurpEvidenceLevel

log = logging.getLogger("burp.analyzer")


class BurpNormalizer:
    @staticmethod
    def normalize_burp_json_line(line: str) -> Optional[BurpTrafficRecord]:
        line = line.strip()
        if not line:
            return None
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        digest_src = f"{data.get('url', '')}:{data.get('method', '')}"
        record_id = f"bp_{__import__('hashlib').md5(digest_src.encode()).hexdigest()[:10]}"

        return BurpTrafficRecord(
            record_id=record_id,
            request_url=data.get("url", "") or "",
            request_method=data.get("method", "GET") or "GET",
            request_headers=data.get("request_headers", {}) or {},
            request_body=data.get("request_body"),
            response_status=data.get("response_status"),
            response_headers=data.get("response_headers", {}) or {},
            response_body=data.get("response_body"),
            evidence_level=BurpEvidenceLevel.E0,
            source_tool="burp",
            raw_json=data,
            validation_note=f"{data.get('method', 'GET')} {data.get('url', '')} → {data.get('response_status', '?')}",
        )

    def normalize_batch(self, burp_stdout: str) -> List[BurpTrafficRecord]:
        records: List[BurpTrafficRecord] = []
        for line in burp_stdout.splitlines():
            rec = self.normalize_burp_json_line(line)
            if rec:
                records.append(rec)
        return records


class DuplicateDetector:
    def __init__(self):
        self._seen: set = set()

    def add(self, record: BurpTrafficRecord) -> bool:
        key = f"{record.request_method}:{record.request_url}"
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

    def review(self, record: BurpTrafficRecord) -> Dict[str, Any]:
        issues: List[str] = []
        confidence = 0.2

        if record.response_status is not None:
            confidence += 0.3
        else:
            issues.append("لا توجد حالة استجابة")

        if record.response_body:
            confidence += 0.2
        if record.request_body:
            confidence += 0.1
        if record.request_headers:
            confidence += 0.1
        if record.response_headers:
            confidence += 0.1

        confidence = max(0.0, min(confidence, 1.0))

        return {
            "record_id": record.record_id,
            "url": record.request_url,
            "method": record.request_method,
            "status": record.response_status,
            "evidence_level": record.evidence_level,
            "evidence_status": "sufficient" if confidence >= 0.5 else "insufficient",
            "confidence": round(confidence, 2),
            "confidence_label": "strong" if confidence >= 0.75 else "probable" if confidence >= 0.50 else "possible" if confidence >= 0.25 else "weak",
            "needs_verification": confidence < 0.75,
            "issues": issues,
            "recommendation": "راجع حركة المرور يدويًا عبر Burp Repeater للتحقق من السلوك.",
        }
