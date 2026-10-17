"""OT / ICS intelligence — L2 AI Analyzer + L5 Evidence Reviewer
Normalizer (nmap ICS scripts / modbus poll) + Duplicate Detector + Evidence Reviewer.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from core.ot.schemas import OTAssetRecord, OTEvidenceLevel, OTProtocol

log = logging.getLogger("ot.analyzer")


def _normalize_protocol(raw: Any) -> str:
    text = str(raw or "").strip().lower()
    if any(k in text for k in ("modbus", "mbap")):
        return OTProtocol.MODBUS
    if any(k in text for k in ("s7", "siemens")):
        return OTProtocol.S7
    if any(k in text for k in ("ethernet-ip", "cip", "ethernetip")):
        return OTProtocol.ETHERNET_IP
    if any(k in text for k in ("profinet",)):
        return OTProtocol.PROFINET
    return OTProtocol.UNKNOWN


class OTNormalizer:
    """L2: يحوّل مخرجات nmap ICS scripts / modbus poll إلى OTAssetRecord موحد."""

    @staticmethod
    def _parse_json(text: str) -> List[Dict[str, Any]]:
        text = (text or "").strip()
        if not text:
            return []
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return []
        if isinstance(data, list):
            return [d for d in data if isinstance(d, dict)]
        if isinstance(data, dict):
            for key in ("assets", "results", "hosts"):
                val = data.get(key)
                if isinstance(val, list):
                    return [d for d in val if isinstance(d, dict)]
            return [data]
        return []

    def normalize(self, text: str, source: str = "auto") -> List[OTAssetRecord]:
        entries = self._parse_json(text)
        records: List[OTAssetRecord] = []
        for entry in entries:
            ip = str(entry.get("ip") or entry.get("address") or "").strip()
            if not ip:
                continue
            port = entry.get("port") or entry.get("portid")
            try:
                port = int(port) if port is not None else 502
            except (TypeError, ValueError):
                port = 502

            protocol = _normalize_protocol(
                entry.get("protocol") or entry.get("proto") or entry.get("service")
            )
            vendor = entry.get("vendor") or entry.get("mac_vendor")
            model = entry.get("model") or entry.get("product")
            unit_id = entry.get("unit_id") or entry.get("slave_id")
            try:
                unit_id = int(unit_id) if unit_id is not None else None
            except (TypeError, ValueError):
                unit_id = None
            fcs = entry.get("function_codes") or []
            if isinstance(fcs, str):
                fcs = [int(x) for x in fcs.split(",") if x.strip().isdigit()]

            records.append(
                OTAssetRecord(
                    record_id="",
                    ip=ip,
                    port=port,
                    protocol=protocol,
                    vendor=vendor,
                    model=model,
                    unit_id=unit_id,
                    function_codes=[int(x) for x in fcs if str(x).isdigit()],
                    unauthenticated=bool(entry.get("unauthenticated")),
                    write_access=bool(entry.get("write_access")),
                    source_tool=source if source != "auto" else "ot_discovery",
                    raw_json=entry,
                    validation_note=f"{source} {ip}:{port} {protocol}",
                )
            )
        return records


class DuplicateDetector:
    """L2: يدمج السجلات المكررة لنفس IP:Port."""

    def __init__(self) -> None:
        self._by_endpoint: Dict[str, OTAssetRecord] = {}

    def add(self, record: OTAssetRecord) -> OTAssetRecord:
        key = record.canonical_key
        existing = self._by_endpoint.get(key)
        if existing is None:
            self._by_endpoint[key] = record
            return record
        existing.vendor = existing.vendor or record.vendor
        existing.model = existing.model or record.model
        existing.unit_id = existing.unit_id or record.unit_id
        existing.function_codes = sorted(set(existing.function_codes) | set(record.function_codes))
        existing.unauthenticated = existing.unauthenticated or record.unauthenticated
        existing.write_access = existing.write_access or record.write_access
        if record.evidence_level == OTEvidenceLevel.E1:
            existing.evidence_level = OTEvidenceLevel.E1
        return existing

    def flush(self) -> List[OTAssetRecord]:
        out = list(self._by_endpoint.values())
        self._by_endpoint.clear()
        return out


class EvidenceReviewer:
    """L5 Verification: يراجع أدلة الأصول OT ويحدد مستوى الدليل والثقة.

    ملاحظة أمنية: وصول غير مصادق عليه / كتابة في PLC ≠ تأثير مؤكد —
    النتيجة remain candidate حتى يُتوّقق الأثر على العملية الصناعية فعلياً.
    """

    def review(self, record: OTAssetRecord) -> Dict[str, Any]:
        notes: List[str] = []
        confidence = 0.2

        if record.vendor:
            confidence += 0.1
        if record.model:
            confidence += 0.1
        if record.unit_id is not None:
            confidence += 0.1
        if record.function_codes:
            confidence += 0.1
            notes.append(f"رموز الدالة: {record.function_codes[:5]}")

        if record.unauthenticated:
            notes.append("وصول غير مصادق عليه إلى PLC — أعلى خطر للقطاع الصناعي")
            confidence += 0.3
        if record.write_access:
            notes.append("صلاحية كتابة — يمكن تغيير قيم الإindoor/process")
            confidence += 0.25
        if record.protocol == OTProtocol.MODBUS:
            notes.append("Modbus TCP — عادة بدون تشفير/مصادقة تلقائية")
            confidence += 0.1
        if record.protocol == OTProtocol.S7:
            notes.append("S7comm — بروتوكول سيمنز الصناعي")
            confidence += 0.1

        if record.is_high_risk:
            record.evidence_level = OTEvidenceLevel.E1
            evidence_status = "sufficient"
        else:
            evidence_status = "raw"
            notes.append("أصل OT مرصود أوليًا — يُنصح بالتأكد عبر سكريبتات ICS")

        confidence = max(0.0, min(confidence, 1.0))
        return {
            "record_id": record.record_id,
            "ip": record.ip,
            "port": record.port,
            "protocol": record.protocol,
            "vendor": record.vendor,
            "model": record.model,
            "unit_id": record.unit_id,
            "unauthenticated": record.unauthenticated,
            "write_access": record.write_access,
            "is_high_risk": record.is_high_risk,
            "evidence_status": evidence_status,
            "evidence_level": record.evidence_level,
            "confidence": round(confidence, 2),
            "confidence_label": self._label(confidence),
            "needs_verification": not record.is_high_risk,
            "notes": notes,
            "recommendation": (
                "أصل OT مرصود (E0/E1) — مؤشر سطح هجوم صناعي، وليس إثبات تأثير على "
                "العملية دون تدقيق سلامة فعلي."
            ),
        }

    @staticmethod
    def _label(score: float) -> str:
        if score >= 0.75:
            return "strong"
        if score >= 0.50:
            return "probable"
        if score >= 0.25:
            return "possible"
        return "weak"
