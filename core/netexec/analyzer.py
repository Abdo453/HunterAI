"""NetExec (nxc) — L2 AI Analyzer + L5 Evidence Reviewer
Normalizer (text → records) + Duplicate Detector + Evidence Reviewer.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

from core.netexec.schemas import (
    NetExecEvidenceLevel,
    NetExecHostRecord,
    NetExecProfile,
)

log = logging.getLogger("netexec.analyzer")

_LINE_RE = re.compile(
    r"^(?P<proto>[A-Za-z][A-Za-z0-9]*)\s+"
    r"(?P<host>[0-9A-Za-z_.\-:]+)\s+"
    r"(?P<port>\d+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<rest>.*)$"
)
_DOMAIN_RE = re.compile(r"\(domain:([^)]+)\)")
_NAME_RE = re.compile(r"\(name:([^)]+)\)")
_SIGNING_RE = re.compile(r"\(signing:([A-Za-z]+)\)")
_SMBV1_RE = re.compile(r"\(SMBv1:([A-Za-z]+)\)")
_OS_RE = re.compile(r"(Windows[^()]*)")
_CRED_RE = re.compile(r"([^\s\\]+)\\([^\s:]+):(\S+)")


def _to_bool(value: Optional[str]) -> Optional[bool]:
    if value is None:
        return None
    return value.strip().lower() in ("true", "yes", "1")


class NetExecNormalizer:
    """L2: يحوّل مخرجات netexec النصية إلى NetExecHostRecord موحد."""

    def normalize_text(self, text: str) -> List[NetExecHostRecord]:
        records: List[NetExecHostRecord] = []
        for raw_line in (text or "").splitlines():
            line = raw_line.rstrip()
            m = _LINE_RE.match(line.strip())
            if not m:
                continue
            rest = m.group("rest") or ""
            hostname = m.group("hostname")
            domain = self._first(_DOMAIN_RE, rest)
            name = self._first(_NAME_RE, rest)
            signing = _to_bool(self._first(_SIGNING_RE, rest))
            smbv1 = _to_bool(self._first(_SMBV1_RE, rest))
            os_match = _OS_RE.search(rest)
            pwned = "Pwn3d!" in rest
            cred = _CRED_RE.search(rest)
            username = None
            domain_from_cred = None
            if cred:
                domain_from_cred, username = cred.group(1), cred.group(2)

            records.append(NetExecHostRecord(
                host=m.group("host"),
                protocol=m.group("proto").lower(),
                port=int(m.group("port")),
                hostname=name or (hostname if hostname not in (".", "-") else None),
                domain=domain or domain_from_cred,
                os_family=os_match.group(1).strip() if os_match else None,
                signing=signing,
                smbv1=smbv1,
                pwned=pwned,
                credentials_valid=("[+]" in rest) or pwned or bool(cred),
                username=username,
                message=rest.strip(),
                evidence_level=(
                    NetExecEvidenceLevel.E1 if (pwned or cred) else NetExecEvidenceLevel.E0
                ),
                raw_line=line,
            ))
        return records

    @staticmethod
    def _first(rx: re.Pattern, text: str) -> Optional[str]:
        m = rx.search(text)
        return m.group(1).strip() if m else None


class DuplicateDetector:
    """L2: يدمج سجلات نفس endpoint (protocol://host:port) مع أغنى البيانات."""

    def __init__(self) -> None:
        self._by_key: Dict[str, NetExecHostRecord] = {}

    def add(self, record: NetExecHostRecord) -> NetExecHostRecord:
        key = record.canonical_key
        existing = self._by_key.get(key)
        if existing is None:
            self._by_key[key] = record
            return record
        existing.hostname = existing.hostname or record.hostname
        existing.domain = existing.domain or record.domain
        existing.os_family = existing.os_family or record.os_family
        if existing.signing is None:
            existing.signing = record.signing
        if existing.smbv1 is None:
            existing.smbv1 = record.smbv1
        existing.pwned = existing.pwned or record.pwned
        existing.credentials_valid = existing.credentials_valid or record.credentials_valid
        existing.username = existing.username or record.username
        if record.evidence_level == NetExecEvidenceLevel.E1:
            existing.evidence_level = NetExecEvidenceLevel.E1
        return existing

    def flush(self) -> List[NetExecHostRecord]:
        out = list(self._by_key.values())
        self._by_key.clear()
        return out


class EvidenceReviewer:
    """L5 Verification: يراجع أدلة netexec ويحدد مستوى الدليل والثقة.

    ملاحظة أمنية: علامة (Pwn3d!) تعني أن بيانات الاعتماد مكّنت من صلاحيات إدارية —
    لكنها تبقى E1 (مرصودة) وليست "اختراقًا مؤكدًا" حتى يُوثّق أثرها بإثبات قابل للتكرار.
    """

    def review(self, record: NetExecHostRecord) -> Dict[str, Any]:
        notes: List[str] = []
        confidence = 0.3

        if record.domain:
            confidence += 0.15
        if record.hostname:
            confidence += 0.1
        if record.os_family:
            confidence += 0.05
        if record.signing is not None or record.smbv1 is not None:
            confidence += 0.1
        if record.credentials_valid:
            confidence += 0.2
        if record.pwned:
            confidence += 0.1

        if record.signing is False:
            notes.append("SMB signing غير مفعّل — Relay ممكن")
        if record.smbv1 is True:
            notes.append("SMBv1 مفعّل — سطح EternalBlue")
        if record.pwned:
            notes.append("بيانات اعتماد إدارية (Pwn3d!) — تحتاج توثيق أثر فعلي")

        confidence = max(0.0, min(confidence, 1.0))
        return {
            "record_id": record.record_id,
            "host": record.host,
            "protocol": record.protocol,
            "credentials_valid": record.credentials_valid,
            "pwned": record.pwned,
            "signing": record.signing,
            "smbv1": record.smbv1,
            "evidence_status": "sufficient" if record.domain or record.pwned else "raw",
            "evidence_level": record.evidence_level,
            "confidence": round(confidence, 2),
            "confidence_label": self._label(confidence),
            "needs_verification": not record.pwned,
            "notes": notes,
            "recommendation": (
                "نتيجة netexec = سطح/وصول مرصود (E0/E1). توثيق الأثر الفعلي شرط أي تأكيد لاحق."
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
