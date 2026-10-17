"""Wireless / WiFi intelligence — L2 AI Analyzer + L5 Evidence Reviewer
Normalizer (kismet JSON / airodump-ng CSV) + Duplicate Detector + Evidence Reviewer.
"""
from __future__ import annotations

import csv
import io
import json
import logging
from typing import Any, Dict, List, Optional

from core.wireless.schemas import (
    EncryptionStrength,
    WiFiNetworkRecord,
    WirelessEvidenceLevel,
)

log = logging.getLogger("wireless.analyzer")


def _normalize_encryption(raw: Any) -> str:
    """يُعيد تشفير network إلى واحدة من فئات EncryptionStrength."""
    text = str(raw or "").strip().lower()
    if not text or text in ("none", "open", "unknown"):
        return EncryptionStrength.NONE
    if any(k in text for k in ("wep",)):
        return EncryptionStrength.WEP
    if any(k in text for k in ("wpa3",)):
        return EncryptionStrength.WPA3
    if any(k in text for k in ("wpa",)):
        return EncryptionStrength.WPA
    return EncryptionStrength.UNKNOWN


class WirelessNormalizer:
    """L2: يحوّل مخرجات kismet JSON / airodump-ng CSV إلى WiFiNetworkRecord موحد."""

    @staticmethod
    def _parse_kismet_json(text: str) -> List[Dict[str, Any]]:
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
            # kismet may wrap results under 'results' or 'networks'
            for key in ("results", "networks", "wifi_networks"):
                val = data.get(key)
                if isinstance(val, list):
                    return [d for d in val if isinstance(d, dict)]
            return [data]
        return []

    @staticmethod
    def _parse_airodump_csv(text: str) -> List[Dict[str, Any]]:
        text = (text or "").strip()
        if not text:
            return []
        reader = csv.DictReader(io.StringIO(text))
        out: List[Dict[str, Any]] = []
        for row in reader:
            # Normalize common airodump-ng header variants.
            bssid = row.get("BSSID") or row.get("bssid") or ""
            if not bssid:
                continue
            out.append(
                {
                    "bssid": bssid,
                    "ssid": row.get("ESSID") or row.get("ssid") or "",
                    "channel": row.get("CH") or row.get("channel") or None,
                    "signal": row.get("Power") or row.get("signal") or None,
                    "encryption": row.get("Enc") or row.get("encryption") or "",
                    "cipher": row.get("Cipher") or row.get("cipher") or None,
                    "auth": row.get("Auth") or row.get("auth") or None,
                }
            )
        return out

    def normalize(self, text: str, source: str = "auto") -> List[WiFiNetworkRecord]:
        """يُخرج قائمة سجلات WiFi موحّدة.

        source: "kismet" | "airodump" | "auto" (يخمن بناءً على المحتوى).
        """
        text = (text or "").strip()
        if not text:
            return []

        if source == "kismet" or (source == "auto" and text.lstrip().startswith("{")):
            entries = self._parse_kismet_json(text)
        elif source == "airodump" or (source == "auto" and "," in text.splitlines()[0]):
            entries = self._parse_airodump_csv(text)
        else:
            entries = self._parse_kismet_json(text) or self._parse_airodump_csv(text)

        records: List[WiFiNetworkRecord] = []
        for entry in entries:
            bssid = str(entry.get("bssid") or entry.get("BSSID") or "").strip().upper()
            ssid = str(entry.get("ssid") or entry.get("ESSID") or "").strip()
            if not bssid:
                continue

            channel = entry.get("channel")
            try:
                channel = int(channel) if channel is not None else None
            except (TypeError, ValueError):
                channel = None

            signal = entry.get("signal_dbm") or entry.get("signal") or entry.get("Power")
            try:
                signal = int(signal) if signal is not None else None
            except (TypeError, ValueError):
                signal = None

            enc = _normalize_encryption(
                entry.get("encryption") or entry.get("Enc") or entry.get("enc")
            )

            records.append(
                WiFiNetworkRecord(
                    record_id="",
                    ssid=ssid,
                    bssid=bssid,
                    channel=channel,
                    frequency=entry.get("frequency"),
                    signal_dbm=signal,
                    encryption=enc,
                    cipher=entry.get("cipher"),
                    auth=entry.get("auth"),
                    wps=bool(entry.get("wps")),
                    hidden=bool(entry.get("hidden")),
                    vendor=entry.get("vendor"),
                    source_tool=source if source != "auto" else "wireless_scan",
                    raw_json=entry,
                    validation_note=f"{source} {bssid}:{channel} {enc}",
                )
            )
        return records


class DuplicateDetector:
    """L2: يدمج السجلات المكررة لنفس BSSID:Canal."""

    def __init__(self) -> None:
        self._by_key: Dict[str, WiFiNetworkRecord] = {}

    def add(self, record: WiFiNetworkRecord) -> WiFiNetworkRecord:
        key = record.canonical_key
        existing = self._by_key.get(key)
        if existing is None:
            self._by_key[key] = record
            return record
        # احتفظ بأغنى البيانات.
        existing.ssid = existing.ssid or record.ssid
        existing.channel = existing.channel or record.channel
        existing.signal_dbm = existing.signal_dbm or record.signal_dbm
        existing.cipher = existing.cipher or record.cipher
        existing.auth = existing.auth or record.auth
        existing.wps = existing.wps or record.wps
        existing.hidden = existing.hidden or record.hidden
        existing.vendor = existing.vendor or record.vendor
        if record.evidence_level == WirelessEvidenceLevel.E1:
            existing.evidence_level = WirelessEvidenceLevel.E1
        return existing

    def flush(self) -> List[WiFiNetworkRecord]:
        out = list(self._by_key.values())
        self._by_key.clear()
        return out


class EvidenceReviewer:
    """L5 Verification: يراجع أدلة الشبكة اللاسلكية ويحدد مستوى الدليل والثقة.

    ملاحظة أمنية: شبكة مفتوحة / WEP ≠ اختراق مؤكد — النتيجة remain candidate
    حتى يُتوّقق الأثر فعلياً (مثلاً capturar handshake و Krack).
    """

    def review(self, record: WiFiNetworkRecord) -> Dict[str, Any]:
        notes: List[str] = []
        confidence = 0.2

        if record.ssid:
            confidence += 0.1
        if record.signal_dbm is not None:
            confidence += 0.1
        if record.channel is not None:
            confidence += 0.05
        if record.cipher:
            confidence += 0.1

        if record.is_open:
            notes.append("شبكة مفتوحة (لا تشفير) — أعلى خطر للتعرض")
            confidence += 0.2
        elif record.encryption == EncryptionStrength.WEP:
            notes.append("تشفير WEP — قابل للكسر بسهولة")
            confidence += 0.25
        elif record.encryption == EncryptionStrength.WPA:
            notes.append("تشفير WPA/WPA2 — surface لهجمات القاموس (dictionary)")
            confidence += 0.1
        elif record.encryption == EncryptionStrength.WPA3:
            notes.append("تشفير WPA3 — المعيار الحالي")
        else:
            notes.append("نوع التشفير غير محدد — يحتاج تأكيد")

        if record.hidden:
            notes.append("SSID مخفي — security by obscurity (لا يُعتبر حماية)")
        if record.wps:
            notes.append("WPS مفعّل — surface لهجوم PixieDust / brute-force PIN")
            confidence += 0.1

        if record.is_weak:
            record.evidence_level = WirelessEvidenceLevel.E1
            evidence_status = "sufficient"
        else:
            evidence_status = "raw"
            notes.append("بصمة لاسلكية أولية — يُنصح بالتأكيد عبر aircrack-ng / wifite")

        confidence = max(0.0, min(confidence, 1.0))
        return {
            "record_id": record.record_id,
            "ssid": record.ssid,
            "bssid": record.bssid,
            "channel": record.channel,
            "encryption": record.encryption,
            "encryption_strength": record.encryption_strength,
            "signal_dbm": record.signal_dbm,
            "wps": record.wps,
            "hidden": record.hidden,
            "evidence_status": evidence_status,
            "evidence_level": record.evidence_level,
            "confidence": round(confidence, 2),
            "confidence_label": self._label(confidence),
            "needs_verification": not record.is_weak,
            "notes": notes,
            "recommendation": (
                "شبكة لاسلكية مرصودة (E0/E1) — مؤشر سطح هجوم، وليس إثبات اختراق بدونHandshake/"
                "التقاط فعلي."
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
