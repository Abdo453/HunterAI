"""Subfinder Asset Coverage — L2 AI Analyzer + L5 Evidence Reviewer"""
from __future__ import annotations

import json
import logging
from typing import List, Dict, Any, Optional
from collections import defaultdict

from core.subfinder.schemas import (
    SubfinderAssetRecord, SubfinderEvidenceLevel, SourceType,
)

log = logging.getLogger("subfinder.analyzer")


class SubfinderNormalizer:
    @staticmethod
    def normalize_subfinder_json_line(line: str) -> Optional[SubfinderAssetRecord]:
        line = line.strip()
        if not line:
            return None
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        subdomain = data.get("host", "") or data.get("subdomain", "") or ""
        source = data.get("source", "unknown")
        source_type = data.get("source-type", SourceType.PASSIVE)
        ip = data.get("ip")
        cdn = data.get("cdn", False)

        digest_src = f"{subdomain}:{source}"
        record_id = f"sf_{__import__('hashlib').md5(digest_src.encode()).hexdigest()[:10]}"

        return SubfinderAssetRecord(
            record_id=record_id,
            subdomain=subdomain,
            source=source,
            source_type=source_type,
            ip=ip,
            cdn=cdn,
            evidence_level=SubfinderEvidenceLevel.E0,
            source_tool="subfinder",
            raw_json=data,
            validation_note=f"Source: {source} | Type: {source_type}",
        )

    def normalize_batch(self, subfinder_stdout: str) -> List[SubfinderAssetRecord]:
        records: List[SubfinderAssetRecord] = []
        for line in subfinder_stdout.splitlines():
            rec = self.normalize_subfinder_json_line(line)
            if rec:
                records.append(rec)
        return records


class DuplicateDetector:
    def __init__(self):
        self._groups: Dict[str, List[SubfinderAssetRecord]] = defaultdict(list)

    def add(self, record: SubfinderAssetRecord) -> Optional[List[SubfinderAssetRecord]]:
        key = record.canonical_key
        self._groups[key].append(record)
        if len(self._groups[key]) > 1:
            return self._groups[key]
        return None

    def flush(self) -> Dict[str, List[SubfinderAssetRecord]]:
        groups = dict(self._groups)
        self._groups.clear()
        return groups


class EvidenceReviewer:
    HIGH_VALUE_SUBDOMAINS = {"admin", "dev", "staging", "test", "api", "internal", "vpn", "mail"}

    def __init__(self):
        pass

    def review(self, record: SubfinderAssetRecord) -> Dict[str, Any]:
        issues: List[str] = []
        confidence = 0.2

        if record.source != "unknown":
            confidence += 0.2
        else:
            issues.append("مصدر غير معروف")

        if record.source_type in (SourceType.CERTIFICATE, SourceType.DNS):
            confidence += 0.2

        if record.ip:
            confidence += 0.15
        else:
            issues.append("لا يوجد عنوان IP مرتبط")

        if record.cdn:
            confidence += 0.05
            issues.append("محفوظة خلف CDN — قد تكون المخفية")

        label = record.subdomain.split(".")[0] if "." in record.subdomain else record.subdomain
        if label in self.HIGH_VALUE_SUBDOMAINS:
            confidence += 0.15
            issues.append("نطابق فرعية عالية القيمة — أولوية أعلى")

        if record.source != "unknown" and (record.ip or record.source_type in (SourceType.CERTIFICATE, SourceType.DNS)):
            record.evidence_level = SubfinderEvidenceLevel.E1

        confidence = max(0.0, min(confidence, 1.0))

        return {
            "record_id": record.record_id,
            "subdomain": record.subdomain,
            "source": record.source,
            "source_type": record.source_type,
            "ip": record.ip,
            "cdn": record.cdn,
            "evidence_level": record.evidence_level,
            "evidence_status": "sufficient" if record.evidence_level == SubfinderEvidenceLevel.E1 else "insufficient",
            "confidence": round(confidence, 2),
            "confidence_label": "strong" if confidence >= 0.75 else "probable" if confidence >= 0.50 else "possible" if confidence >= 0.25 else "weak",
            "needs_verification": record.evidence_level != SubfinderEvidenceLevel.E1,
            "issues": issues,
            "recommendation": (
                "أصل فرعي موثق (E1) — يُنصح بالفحص عبر HTTPx و Nmap للتأكيد على الخدمة."
                if record.evidence_level == SubfinderEvidenceLevel.E1 else
                "الأصل يحتاج أدلة إضافية قبل اعتماده في نطاق التحقيق."
            ),
        }
