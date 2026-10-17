"""IoT device intelligence — L2 AI Analyzer + L5 Evidence Reviewer
Normalizer (zigbee2mqtt / nmap IoT scripts) + Duplicate Detector + Evidence Reviewer.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from core.iot.schemas import IoTDeviceRecord, IoTEvidenceLevel, IoTProtocol

log = logging.getLogger("iot.analyzer")


def _normalize_protocol(raw: Any) -> str:
    text = str(raw or "").strip().lower()
    if any(k in text for k in ("mqtt",)):
        return IoTProtocol.MQTT
    if any(k in text for k in ("zigbee",)):
        return IoTProtocol.ZIGBEE
    if any(k in text for k in ("ble", "bluetooth")):
        return IoTProtocol.BLE
    if any(k in text for k in ("coap",)):
        return IoTProtocol.COAP
    if any(k in text for k in ("upnp", "ssdp")):
        return IoTProtocol.UPNP
    return IoTProtocol.UNKNOWN


class IoTNormalizer:
    """L2: يحوّل مخرجات zigbee2mqtt / nmap IoT scripts إلى IoTDeviceRecord موحد."""

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
            for key in ("devices", "results", "hosts"):
                val = data.get(key)
                if isinstance(val, list):
                    return [d for d in val if isinstance(d, dict)]
            return [data]
        return []

    def normalize(self, text: str, source: str = "auto") -> List[IoTDeviceRecord]:
        entries = self._parse_json(text)
        records: List[IoTDeviceRecord] = []
        for entry in entries:
            mac = str(entry.get("mac") or entry.get("MAC") or entry.get("address") or "").strip().upper()
            if not mac:
                continue
            ip = entry.get("ip") or entry.get("address") or None
            vendor = entry.get("vendor") or entry.get("mac_vendor")
            protocol = _normalize_protocol(
                entry.get("protocol") or entry.get("proto") or entry.get("device_type")
            )
            fingerprint = entry.get("fingerprint") or entry.get("fingerprint_json")
            ports = entry.get("ports") or []
            if isinstance(ports, str):
                ports = [int(p) for p in ports.split(",") if p.strip().isdigit()]
            elif not isinstance(ports, list):
                ports = []

            records.append(
                IoTDeviceRecord(
                    record_id="",
                    mac=mac,
                    ip=ip,
                    vendor=vendor,
                    protocol=protocol,
                    fingerprint=str(fingerprint) if fingerprint else None,
                    ports=[int(p) for p in ports if str(p).isdigit()],
                    default_creds=bool(entry.get("default_creds")),
                    unauthenticated=bool(entry.get("unauthenticated")),
                    source_tool=source if source != "auto" else "iot_discovery",
                    raw_json=entry,
                    validation_note=f"{source} {mac}:{protocol}",
                )
            )
        return records


class DuplicateDetector:
    """L2: يدمج السجلات المكررة لنفس MAC."""

    def __init__(self) -> None:
        self._by_mac: Dict[str, IoTDeviceRecord] = {}

    def add(self, record: IoTDeviceRecord) -> IoTDeviceRecord:
        key = record.canonical_key
        existing = self._by_mac.get(key)
        if existing is None:
            self._by_mac[key] = record
            return record
        existing.ip = existing.ip or record.ip
        existing.vendor = existing.vendor or record.vendor
        existing.ports = sorted(set(existing.ports) | set(record.ports))
        existing.default_creds = existing.default_creds or record.default_creds
        existing.unauthenticated = existing.unauthenticated or record.unauthenticated
        if record.evidence_level == IoTEvidenceLevel.E1:
            existing.evidence_level = IoTEvidenceLevel.E1
        return existing

    def flush(self) -> List[IoTDeviceRecord]:
        out = list(self._by_mac.values())
        self._by_mac.clear()
        return out


class EvidenceReviewer:
    """L5 Verification: يراجع أدلة أجهزة IoT ويحدد مستوى الدليل والثقة.

    ملاحظة أمنية: بيانات اعتماد افتراضية / غير مصادق عليها ≠ اختراق مؤكد —
    النتيجة remain candidate حتى يُتوّقق الوصول فعلياً.
    """

    def review(self, record: IoTDeviceRecord) -> Dict[str, Any]:
        notes: List[str] = []
        confidence = 0.2

        if record.vendor:
            confidence += 0.1
        if record.ip:
            confidence += 0.1
        if record.protocol != IoTProtocol.UNKNOWN:
            confidence += 0.1
        if record.ports:
            confidence += 0.1
            notes.append(f"{len(record.ports)} منفذ مفتوح: {record.ports[:5]}")

        if record.default_creds:
            notes.append("بيانات اعتماد افتراضية — أعلى خطر للاستيلاء")
            confidence += 0.3
        if record.unauthenticated:
            notes.append("وصول غير مصادق عليه — سطح هجوم مفتوح")
            confidence += 0.25
        if record.protocol == IoTProtocol.MQTT:
            notes.append("بروتوكول MQTT — قد يكشف بيانات حساسة بدون مصادقة")
            confidence += 0.1
        if record.protocol == IoTProtocol.UPNP:
            notes.append("بروتوكول UPNP — surface للاختراق عبر الشبكة المحلية")
            confidence += 0.1

        if record.is_high_risk:
            record.evidence_level = IoTEvidenceLevel.E1
            evidence_status = "sufficient"
        else:
            evidence_status = "raw"
            notes.append("بصمة IoT أولية — يُنصح بالتأكيد عبر nmap/scripts")

        confidence = max(0.0, min(confidence, 1.0))
        return {
            "record_id": record.record_id,
            "mac": record.mac,
            "ip": record.ip,
            "vendor": record.vendor,
            "protocol": record.protocol,
            "ports": record.ports,
            "default_creds": record.default_creds,
            "unauthenticated": record.unauthenticated,
            "is_high_risk": record.is_high_risk,
            "evidence_status": evidence_status,
            "evidence_level": record.evidence_level,
            "confidence": round(confidence, 2),
            "confidence_label": self._label(confidence),
            "needs_verification": not record.is_high_risk,
            "notes": notes,
            "recommendation": (
                "جهاز IoT مرصود (E0/E1) — مؤشر سطح هجوم، وليس إثبات استيلاء دون "
                "إثبات وصول فعلي."
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
