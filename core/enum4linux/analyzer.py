"""enum4linux-ng — L2 AI Analyzer + L5 Evidence Reviewer
Normalizer + Duplicate Detector + Evidence Reviewer (rule-based، لا LLM لكل خطوة)
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from core.enum4linux.schemas import (
    ADHostProfile,
    Enum4LinuxAssetRecord,
    Enum4LinuxEvidenceLevel,
    SMBShareRecord,
    SMBUserRecord,
)

log = logging.getLogger("enum4linux.analyzer")


class Enum4LinuxNormalizer:
    """L2: يحوّل مخرجات enum4linux-ng JSON إلى Enum4LinuxAssetRecord موحد."""

    @staticmethod
    def _parse_payload(text: str) -> List[Dict[str, Any]]:
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
            return [data]
        return []

    @staticmethod
    def _host_of(entry: Dict[str, Any]) -> str:
        target = entry.get("target")
        if isinstance(target, dict):
            return target.get("host") or target.get("ip") or ""
        if isinstance(target, str):
            return target
        return entry.get("host") or entry.get("ip") or ""

    @staticmethod
    def _os_string(entry: Dict[str, Any]) -> Optional[str]:
        os_info = entry.get("os_info") or entry.get("os") or entry.get("OS")
        if isinstance(os_info, dict):
            parts = [str(v) for v in os_info.values() if v]
            return " ".join(parts) or None
        return str(os_info) if os_info else None

    def _users(self, host: str, entry: Dict[str, Any]) -> List[SMBUserRecord]:
        raw = entry.get("users") or {}
        out: List[SMBUserRecord] = []
        if isinstance(raw, dict):
            for name, attrs in raw.items():
                attrs = attrs if isinstance(attrs, dict) else {}
                rid = attrs.get("rid")
                try:
                    rid_int = int(rid) if rid is not None else None
                except (TypeError, ValueError):
                    rid_int = None
                out.append(SMBUserRecord(
                    host=host,
                    username=attrs.get("username") or name,
                    rid=rid_int,
                    full_name=attrs.get("name"),
                    description=attrs.get("description"),
                    evidence_level=Enum4LinuxEvidenceLevel.E0,
                ))
        elif isinstance(raw, list):
            for item in raw:
                if isinstance(item, str):
                    out.append(SMBUserRecord(host=host, username=item))
                elif isinstance(item, dict):
                    out.append(SMBUserRecord(
                        host=host,
                        username=item.get("username") or item.get("name") or "",
                        description=item.get("description"),
                    ))
        return [u for u in out if u.username]

    def _shares(self, host: str, entry: Dict[str, Any], anonymous: bool) -> List[SMBShareRecord]:
        raw = entry.get("shares") or {}
        out: List[SMBShareRecord] = []
        if isinstance(raw, dict):
            for name, attrs in raw.items():
                attrs = attrs if isinstance(attrs, dict) else {}
                access = attrs.get("access")
                is_anon = anonymous and "READ" in (access or "").upper()
                out.append(SMBShareRecord(
                    host=host,
                    name=attrs.get("share") or name,
                    access=access,
                    comment=attrs.get("comment"),
                    is_anonymous=is_anon,
                ))
        elif isinstance(raw, list):
            for item in raw:
                if isinstance(item, str):
                    out.append(SMBShareRecord(host=host, name=item))
                elif isinstance(item, dict):
                    out.append(SMBShareRecord(
                        host=host,
                        name=item.get("share") or item.get("name") or "",
                        access=item.get("access"),
                        comment=item.get("comment"),
                    ))
        return [s for s in out if s.name]

    def normalize(self, text: str) -> List[Enum4LinuxAssetRecord]:
        records: List[Enum4LinuxAssetRecord] = []
        for entry in self._parse_payload(text):
            host = self._host_of(entry)
            if not host:
                continue
            target = entry.get("target") if isinstance(entry.get("target"), dict) else {}
            anonymous = bool(
                entry.get("null_session")
                or entry.get("anonymous")
                or (entry.get("users") and not (target.get("username")))
            )
            domain = entry.get("domain") or target.get("domain")
            hostname = entry.get("hostname") or entry.get("netbios")
            os_str = self._os_string(entry)
            is_dc = bool(entry.get("is_dc")) or (
                bool(domain) and bool(hostname) and str(hostname).upper().startswith("DC")
            ) or ("domain controller" in (os_str or "").lower())

            record = Enum4LinuxAssetRecord(
                host=host,
                domain=domain,
                netbios=hostname,
                os_info=os_str,
                is_dc=is_dc,
                anonymous_access=anonymous,
                users=self._users(host, entry),
                shares=self._shares(host, entry, anonymous),
                groups=entry.get("groups") or {},
                policy=entry.get("policy") or {},
                raw_json=entry,
                validation_note=f"enum4linux-ng {host}: {len(self._users(host, entry))} users",
            )
            records.append(record)
        return records


class DuplicateDetector:
    """L2: يجمع السجلات المكررة (نفس المضيف) ويدمج مستخدميها/مشاركاتها."""

    def __init__(self) -> None:
        self._by_host: Dict[str, Enum4LinuxAssetRecord] = {}

    def add(self, record: Enum4LinuxAssetRecord) -> Enum4LinuxAssetRecord:
        key = record.canonical_key
        existing = self._by_host.get(key)
        if existing is None:
            self._by_host[key] = record
            return record
        # Merge users/shares uniquely.
        existing_users = {u.canonical_key for u in existing.users}
        for u in record.users:
            if u.canonical_key not in existing_users:
                existing.users.append(u)
                existing_users.add(u.canonical_key)
        existing_shares = {s.canonical_key for s in existing.shares}
        for s in record.shares:
            if s.canonical_key not in existing_shares:
                existing.shares.append(s)
                existing_shares.add(s.canonical_key)
        existing.anonymous_access = existing.anonymous_access or record.anonymous_access
        existing.is_dc = existing.is_dc or record.is_dc
        existing.domain = existing.domain or record.domain
        return existing

    def flush(self) -> List[Enum4LinuxAssetRecord]:
        out = list(self._by_host.values())
        self._by_host.clear()
        return out


class EvidenceReviewer:
    """L5 Verification: يراجع أدلة التعداد ويحدد مستوى الدليل والثقة."""

    def review(self, record: Enum4LinuxAssetRecord) -> Dict[str, Any]:
        notes: List[str] = []
        confidence = 0.2  # القاعدة: بلا بيانات، لا شيء مؤكد

        if record.users:
            confidence += 0.3
        if record.shares:
            confidence += 0.2
        if record.domain:
            confidence += 0.15
        if record.os_info:
            confidence += 0.1

        if record.anonymous_access:
            notes.append("تم الوصول بدون مصادقة (null session) — سطح هجوم مرتفع")
        if record.is_dc:
            notes.append("المضيف يبدو Domain Controller — حساسية عالية")

        if record.users or record.shares:
            record.evidence_level = Enum4LinuxEvidenceLevel.E1
            evidence_status = "sufficient"
        else:
            evidence_status = "raw"
            notes.append("لم تُعد الأداة مستخدمين/مشاركات — قد تكون المصادقة مطلوبة")

        confidence = max(0.0, min(confidence, 1.0))
        return {
            "record_id": record.record_id,
            "host": record.host,
            "is_dc": record.is_dc,
            "anonymous_access": record.anonymous_access,
            "user_count": len(record.users),
            "share_count": len(record.shares),
            "evidence_status": evidence_status,
            "evidence_level": record.evidence_level,
            "confidence": round(confidence, 2),
            "confidence_label": self._label(confidence),
            "needs_verification": record.evidence_level != Enum4LinuxEvidenceLevel.E1,
            "notes": notes,
            "recommendation": (
                "بيانات تعداد أولية (E0) — صالحة لبناء خطة تعداد AD، وليست إثباتًا لأي ثغرة بذاتها."
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
