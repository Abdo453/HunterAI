"""Masscan Port Discovery — L2 AI Analyzer + L5 Evidence Reviewer
Finding Normalizer + Duplicate Detector + Evidence Reviewer (rule-based، لا LLM لكل خطوة)
"""
from __future__ import annotations

import json
import logging
from typing import List, Dict, Any, Optional
from collections import defaultdict

from core.masscan.schemas import (
    MasscanPortRecord, PortScanProfile,
    MasscanEvidenceLevel, PortConfidence,
)

log = logging.getLogger("masscan.analyzer")


class MasscanNormalizer:
    """
    L2: يحوّل مخرجات masscan JSON إلى MasscanPortRecord موحد.
    يتعامل مع الصيغتين:
      - مصفوفة JSON صحيحة (--output-format json)
      - تدفّق كائنات JSON يفصلها فاصلة/سطر جديد (-oJ)
    """

    @staticmethod
    def _parse_payload(stdout: str) -> List[Dict[str, Any]]:
        text = (stdout or "").strip()
        if not text:
            return []

        # 1) مصفوفة JSON كاملة
        try:
            data = json.loads(text)
            if isinstance(data, list):
                return [d for d in data if isinstance(d, dict)]
            if isinstance(data, dict):
                return [data]
        except json.JSONDecodeError:
            pass

        # 2) تدفّق كائنات: نلفّه بين [ ] بعد إزالة الفاصلة الأخيرة
        try:
            wrapped = "[" + text.rstrip().rstrip(",") + "]"
            data = json.loads(wrapped)
            return [d for d in data if isinstance(d, dict)]
        except json.JSONDecodeError:
            pass

        # 3) أسطر مستقلة
        entries: List[Dict[str, Any]] = []
        for line in text.splitlines():
            line = line.strip().rstrip(",")
            if not line or line in ("[", "]"):
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    entries.append(obj)
            except json.JSONDecodeError:
                continue
        return entries

    @classmethod
    def normalize_batch(cls, stdout: str) -> List[MasscanPortRecord]:
        records: List[MasscanPortRecord] = []
        for entry in cls._parse_payload(stdout):
            host = entry.get("ip") or entry.get("host") or ""
            if not host:
                continue
            ports = entry.get("ports") or []
            for p in ports:
                if not isinstance(p, dict):
                    continue
                port = p.get("port")
                if port is None:
                    continue
                proto = (p.get("proto") or "tcp").lower()
                state = (p.get("status") or "open").lower()
                reason = p.get("reason")
                ttl = p.get("ttl")
                records.append(MasscanPortRecord(
                    record_id="",
                    host=host,
                    port=int(port),
                    protocol=proto,
                    state=state,
                    reason=reason,
                    ttl=int(ttl) if isinstance(ttl, (int, float, str)) and str(ttl).isdigit() else None,
                    evidence_level=MasscanEvidenceLevel.E0,
                    source_tool="masscan",
                    raw_json=p,
                    validation_note=f"masscan {host}:{port}/{proto} {state} ({reason or 'n/a'})",
                ))
        return records


class DuplicateDetector:
    """
    L2: يكتشف المنافذ المكررة (نفس host:port:proto) ويجمعها في مجموعة واحدة.
    """

    def __init__(self):
        self._groups: Dict[str, List[MasscanPortRecord]] = defaultdict(list)

    def add(self, record: MasscanPortRecord) -> Optional[List[MasscanPortRecord]]:
        key = record.canonical_key
        self._groups[key].append(record)
        if len(self._groups[key]) > 1:
            return self._groups[key]
        return None

    def flush(self) -> Dict[str, List[MasscanPortRecord]]:
        groups = dict(self._groups)
        self._groups.clear()
        return groups


class EvidenceReviewer:
    """
    L5 Verification: يراجع أدلة كل منفذ ويحدد درجة الثقة ومستوى الدليل.
    قاعدة صارمة: منفذ مفتوح ≠ ثغرة — الحد الأقصى E1 ولا يُرفع أي اكتشاف إلى مؤكد هنا.
    """

    def review(self, record: MasscanPortRecord) -> Dict[str, Any]:
        notes: List[str] = []
        confidence = 0.3  # قاعدة: إشارة masscan وحدها ضعيفة نسبيًا (بلا banner)

        reason = (record.reason or "").lower()
        if reason == "syn-ack":
            confidence += 0.3
            record.confidence = PortConfidence.PROBABLE
        elif reason:
            confidence += 0.1
            record.confidence = PortConfidence.POSSIBLE

        if record.ttl:
            confidence += 0.1
        if record.banner:
            confidence += 0.2

        if reason == "syn-ack" and record.ttl:
            record.evidence_level = MasscanEvidenceLevel.E1
            evidence_status = "sufficient"
        else:
            evidence_status = "raw"

        confidence = max(0.0, min(confidence, 1.0))
        if record.state != "open":
            notes.append(f"المنفذ ليس في حالة open ({record.state})")

        return {
            "record_id": record.record_id,
            "host": record.host,
            "port": record.port,
            "protocol": record.protocol,
            "state": record.state,
            "reason": record.reason,
            "ttl": record.ttl,
            "evidence_status": evidence_status,
            "evidence_level": record.evidence_level,
            "confidence": round(confidence, 2),
            "confidence_label": self._label(confidence),
            "needs_verification": record.evidence_level != MasscanEvidenceLevel.E1,
            "notes": notes,
            "recommendation": (
                "منفذ مفتوح مؤكّد مبدئيًا — يجب تأكيد الخدمة عبر nmap -sV قبل أي تصنيف لثغرة."
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
