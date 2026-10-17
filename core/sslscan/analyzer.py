"""SSLScan TLS Cipher & Protocol Intelligence — L2 AI Analyzer + L5 Evidence Reviewer
Normalizer (XML parse) + Duplicate Detector + Evidence Reviewer (rule-based، لا LLM لكل خطوة)
"""
from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

from core.sslscan.schemas import (
    SSLCertRecord,
    SSLCipherRecord,
    SSLAssetRecord,
    SSLEvidenceLevel,
    SSLProtocolRecord,
)

log = logging.getLogger("sslscan.analyzer")


def _bool(text: Optional[str]) -> bool:
    return (text or "").strip().lower() in ("yes", "true", "1", "enabled")


class SSLScanNormalizer:
    """L2: يحوّل مخرجات sslscan XML إلى SSLAssetRecord موحد."""

    def normalize_xml(self, xml_text: str) -> List[SSLAssetRecord]:
        xml_text = (xml_text or "").strip()
        if not xml_text:
            return []
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            # محاولة استخراج جزء XML من وسط المخرجات
            start = xml_text.find("<sslscan")
            if start < 0:
                return []
            try:
                root = ET.fromstring(xml_text[start:])
            except ET.ParseError:
                return []

        target = root.find("target")
        host = target.get("host", "") if target is not None else ""
        port_str = target.get("port", "443") if target is not None else "443"
        try:
            port = int(port_str)
        except (TypeError, ValueError):
            port = 443

        record = SSLAssetRecord(host=host, port=port, raw_xml=xml_text)

        # بروتوكولات
        ssltls = root.find("ssltls")
        if ssltls is not None:
            for proto in ssltls.findall("protocol"):
                record.protocols.append(
                    SSLProtocolRecord(
                        version=proto.get("version", "unknown"),
                        enabled=_bool(proto.get("enabled")),
                    )
                )

        # تشفيرات
        ciphers = root.find("ciphers")
        if ciphers is not None:
            for cipher in ciphers.findall("cipher"):
                bits_str = cipher.get("bits")
                try:
                    bits = int(bits_str) if bits_str is not None else None
                except (TypeError, ValueError):
                    bits = None
                record.ciphers.append(
                    SSLCipherRecord(
                        name=cipher.get("name", "unknown"),
                        bits=bits,
                        used=_bool(cipher.get("used")),
                        export=_bool(cipher.get("export")),
                        anonymous=_bool(cipher.get("anonymous")),
                    )
                )

        # شهادات
        cert = root.find("certificate")
        if cert is not None:
            record.certificates.append(
                SSLCertRecord(
                    subject=self._text(cert, "subject"),
                    issuer=self._text(cert, "issuer"),
                    not_before=self._text(cert, "not_before"),
                    not_after=self._text(cert, "not_after"),
                    sig_alg=self._text(cert, "sig_alg"),
                )
            )

        # ثغرات معروفة
        hb = root.find("heartbleed")
        if hb is not None:
            v = hb.find("vulnerable")
            if v is not None:
                record.heartbleed = _bool(v.text)

        pd = root.find("poodle")
        if pd is not None:
            v = pd.find("vulnerable")
            if v is not None:
                record.poodle = _bool(v.text)

        record.validation_note = (
            f"sslscan {host}:{port}: {len(record.protocols)} protocols, "
            f"{len(record.ciphers)} ciphers"
        )
        return [record]

    @staticmethod
    def _text(parent: ET.Element, tag: str) -> Optional[str]:
        el = parent.find(tag)
        return el.text.strip() if el is not None and el.text else None


class DuplicateDetector:
    """L2: يدمج السجلات المكررة لنفس host:port."""

    def __init__(self) -> None:
        self._by_key: Dict[str, SSLAssetRecord] = {}

    def add(self, record: SSLAssetRecord) -> SSLAssetRecord:
        key = record.canonical_key
        existing = self._by_key.get(key)
        if existing is None:
            self._by_key[key] = record
            return record
        existing.protocols = record.protocols or existing.protocols
        existing.ciphers = record.ciphers or existing.ciphers
        existing.certificates = record.certificates or existing.certificates
        existing.heartbleed = existing.heartbleed or record.heartbleed
        existing.poodle = existing.poodle or record.poodle
        return existing

    def flush(self) -> List[SSLAssetRecord]:
        out = list(self._by_key.values())
        self._by_key.clear()
        return out


class EvidenceReviewer:
    """L5 Verification: يراجع أدلة TLS ويحدد مستوى الدليل والثقة.

    ملاحظة أمنية: بروتوكول/Tشفير ضعيف ≠ ثغرة مؤكدة — النتيجة remain candidate
    حتى يُتوّثق الأثر الفعلي عبرcourt الأدلة.
    """

    def review(self, record: SSLAssetRecord) -> Dict[str, Any]:
        notes: List[str] = []
        confidence = 0.2

        if record.protocols:
            confidence += 0.2
            notes.append(f"{len(record.protocols)} بروتوكول مسجل")
        if record.ciphers:
            confidence += 0.2
            notes.append(f"{len(record.ciphers)} تشفير مسجل")
        if record.certificates:
            confidence += 0.1
            notes.append("شهادة TLS موجودة")

        weak = record.weak_ciphers
        legacy = [p for p in record.enabled_protocols if SSLProtocolRecord(version=p).is_legacy]
        if weak:
            confidence += 0.1
            notes.append(f"{len(weak)} تشفير ضعيف: {', '.join(weak[:5])}")
        if legacy:
            confidence += 0.1
            notes.append(f"بروتوكولات قديمة مفعلة: {', '.join(legacy)}")
        if record.heartbleed:
            notes.append("Heartbleed محتمل — يحتاج تأكيد")
        if record.poodle:
            notes.append("POODLE محتمل — يحتاج تأكيد")

        if record.protocols or record.ciphers:
            record.evidence_level = SSLEvidenceLevel.E1
            evidence_status = "sufficient"
        else:
            evidence_status = "raw"
            notes.append("لم يُخرج sslscan بروتوكولات/تشفيرات — قد يكون المنفذ مغلقًا")

        confidence = max(0.0, min(confidence, 1.0))
        return {
            "record_id": record.record_id,
            "host": record.host,
            "port": record.port,
            "enabled_protocols": record.enabled_protocols,
            "legacy_protocols": legacy,
            "cipher_count": len(record.ciphers),
            "weak_cipher_count": len(weak),
            "heartbleed": record.heartbleed,
            "poodle": record.poodle,
            "evidence_status": evidence_status,
            "evidence_level": record.evidence_level,
            "confidence": round(confidence, 2),
            "confidence_label": self._label(confidence),
            "needs_verification": not (record.heartbleed or record.poodle or weak),
            "notes": notes,
            "recommendation": (
                "تكوين TLS مرصود (E0/E1) — البروتوكولات/التشفيرات الضعيفة مؤشرات، "
                "وليس إثباتًا لثغرة دون فحص فعلي (مثلاً sslscan --heartbleed)."
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
