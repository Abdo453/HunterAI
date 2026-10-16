"""Evidence Normalizer — توحيد مخرجات أدوات OSINT في Schema واحد مع Dedupe"""
from __future__ import annotations

import re
import json
import logging
import hashlib
from typing import List, Dict, Any, Optional
from dataclasses import asdict

from core.osint.schemas import (
    IdentityEvidenceRecord, IdentityCluster,
    OSINTVector, EvidenceLevel, ConfidenceLabel,
)
from core.osint.platform_registry import (
    canonicalize_platform, platform_entry, all_platforms,
    extract_urls,
)

log = logging.getLogger("osint.normalizer")

# أنماط استخراج "المنصة: الرابط" من مخرجات الأدوات النصية
# أمثلة:
#   "[+] GitHub: https://github.com/user"                    (sherlock)
#   "[+] GitHub (100%): https://github.com/user"            (maigret)
#   "github (200): https://github.com/user"                  (blackbird)
PLATFORM_URL_RE = re.compile(
    r"\[?\+?\]?\s*([A-Za-z0-9_.\-]+)\s*(?:\(\s*\d+%?\s*\))?\s*:?\s*(https?://\S+)",
    re.IGNORECASE,
)
FALLBACK_URL_RE = re.compile(r"https?://[^\s\)<>\"]+", re.IGNORECASE)


class EvidenceNormalizer:
    """
    يحول ToolResult خام من أي أداة OSINT إلى قائمة IdentityEvidenceRecord
    موحدة، مع:
      - استخراج platform + match_url من النص
      - إزالة المكرر (dedupe) عبر canonical_key
      - ترقية E0 → E1 عند corroboration من أداة/مصدر ثاني
    """

    def __init__(self):
        self._seen_keys: Dict[str, IdentityEvidenceRecord] = {}
        self._corroboration_counts: Dict[str, List[str]] = {}  # canonical_key -> [tool_names]

    # ── واجهة رئيسية ──────────────────────────────────────────────────

    def normalize(
        self,
        tool_name: str,
        vector: str,
        query_value: str,
        tool_result_stdout: str,
        tool_result_stderr: str = "",
        detection_method: str = "web_status",
        min_confidence: str = "E0",
    ) -> List[IdentityEvidenceRecord]:
        """
        يُرجع قائمة السجلات الموحدة بعد dedupe.
        """
        records = self._parse_tool(
            tool_name=tool_name,
            vector=vector,
            query_value=query_value,
            stdout=tool_result_stdout,
            stderr=tool_result_stderr,
            detection_method=detection_method,
        )

        if not records:
            log.debug(f"[Normalizer] {tool_name}: no records parsed for {query_value}")
            return []

        deduped = self._dedupe(records, tool_name)
        log.debug(f"[Normalizer] {tool_name}: {len(records)} parsed → {len(deduped)} after dedupe")
        return deduped

    # ── الـ Parsers لكل أداة ─────────────────────────────────────────

    def _parse_tool(
        self,
        tool_name: str,
        vector: str,
        query_value: str,
        stdout: str,
        stderr: str,
        detection_method: str,
    ) -> List[IdentityEvidenceRecord]:
        tl = tool_name.lower()

        if tl == "sherlock":
            return self._parse_sherlock(vector, query_value, stdout, detection_method)
        if tl == "maigret":
            return self._parse_maigret(vector, query_value, stdout, detection_method)
        if tl == "blackbird":
            return self._parse_blackbird(vector, query_value, stdout, detection_method)
        if tl == "holehe":
            return self._parse_holehe(vector, query_value, stdout, detection_method)
        if tl == "ghunt":
            return self._parse_ghunt(vector, query_value, stdout, detection_method)
        if tl == "cross_scan":
            return self._parse_cross_scan(vector, query_value, stdout, detection_method)

        # fallback عام لأي أداة غير معروفة
        return self._parse_generic(tool_name, vector, query_value, stdout, detection_method)

    @staticmethod
    def _extract_platform_from_url(url: str) -> str:
        """استخراج اسم المنصة من نطاق الرابط كبديل."""
        m = re.match(r"https?://(?:www\.)?([A-Za-z0-9.\-]+)", url)
        if not m:
            return "unknown"
        host = m.group(1)
        parts = host.split(".")
        if len(parts) >= 2:
            return parts[-2]  # github.com → github
        return host

    def _parse_sherlock(self, vector, query_value, stdout, detection_method) -> List[IdentityEvidenceRecord]:
        records: List[IdentityEvidenceRecord] = []
        for line in (stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            # forms: "[+] GitHub: https://github.com/user"
            m = re.match(r"\[?\+?\]?\s*([^:]+)\s*:\s*(https?://\S+)", line)
            if m:
                platform = canonicalize_platform(m.group(1).strip())
                match_url = m.group(2).strip().rstrip("/")
                records.append(self._make_record(
                    vector, query_value, platform, match_url,
                    detection_method, "sherlock", line
                ))
                continue
            # fallback: أي رابط يحتوي على القيمة المفحوصة
            for url in extract_urls(line):
                if query_value.lower() in url.lower():
                    records.append(self._make_record(
                        vector, query_value, self._extract_platform_from_url(url), url.rstrip("/"),
                        detection_method, "sherlock", line
                    ))
        return records

    def _parse_maigret(self, vector, query_value, stdout, detection_method) -> List[IdentityEvidenceRecord]:
        records: List[IdentityEvidenceRecord] = []
        # maigret قد يُخرج JSON في stdout عند استخدام --json
        try:
            data = json.loads(stdout or "{}")
            sites = data.get("sites", {}) if isinstance(data, dict) else {}
            for plat, info in sites.items():
                if not isinstance(info, dict):
                    continue
                status = str(info.get("status", "")).lower()
                url = info.get("url", info.get("url_main", ""))
                if status in ("found", "exists", "available") and url:
                    records.append(self._make_record(
                        vector, query_value, canonicalize_platform(plat), url.rstrip("/"),
                        detection_method, "maigret", json.dumps(info)[:200]
                    ))
            return records
        except (json.JSONDecodeError, ValueError):
            pass

        # fallback النصي لـ maigret: "[+] Reddit (100%): https://..."
        for line in (stdout or "").splitlines():
            line = line.strip()
            m = PLATFORM_URL_RE.match(line)
            if m:
                platform = canonicalize_platform(m.group(1).strip())
                match_url = m.group(2).strip().rstrip("/")
                records.append(self._make_record(
                    vector, query_value, platform, match_url,
                    detection_method, "maigret", line
                ))
        return records

    def _parse_blackbird(self, vector, query_value, stdout, detection_method) -> List[IdentityEvidenceRecord]:
        records: List[IdentityEvidenceRecord] = []
        for line in (stdout or "").splitlines():
            line = line.strip()
            m = PLATFORM_URL_RE.match(line)
            if m:
                platform = canonicalize_platform(m.group(1).strip())
                match_url = m.group(2).strip().rstrip("/")
                records.append(self._make_record(
                    vector, query_value, platform, match_url,
                    detection_method, "blackbird", line
                ))
                continue
            for url in extract_urls(line):
                if query_value.lower() in url.lower():
                    records.append(self._make_record(
                        vector, query_value, self._extract_platform_from_url(url), url.rstrip("/"),
                        detection_method, "blackbird", line
                    ))
        return records

    def _parse_holehe(self, vector, query_value, stdout, detection_method) -> List[IdentityEvidenceRecord]:
        """holehe يُخرج قائمة المنصات المسجل بها البريد الإلكتروني"""
        records: List[IdentityEvidenceRecord] = []
        text = stdout or ""
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            # holehe يطبع اسم المنصة ونتيجتها؛ نبحث عن روابط أو أسماء منصات مع مؤشر وجود
            if any(kw in line.lower() for kw in ("found", "exists", "registered", "available", "[+]")):
                platform = canonicalize_platform(self._extract_platform_from_url(line)) or "unknown"
                match_url = line.split()[-1] if line.split()[-1].startswith("http") else f"https://{platform}.com"
                records.append(self._make_record(
                    vector, query_value, platform, match_url,
                    detection_method, "holehe", line
                ))
        if not records:
            # fallback: أي رابط في المخرجات
            for url in extract_urls(text):
                records.append(self._make_record(
                    vector, query_value, self._extract_platform_from_url(url), url.rstrip("/"),
                    detection_method, "holehe", text[:200]
                ))
        return records

    def _parse_ghunt(self, vector, query_value, stdout, detection_method) -> List[IdentityEvidenceRecord]:
        """ghunt يُخرج معلومات حساب غوغل من الإيميل"""
        records: List[IdentityEvidenceRecord] = []
        text = stdout or ""
        # نبحث عن أي روابط غوغل مذكورة
        for url in extract_urls(text):
            if any(d in url.lower() for d in ("google", "gmail", "accounts.google")):
                records.append(self._make_record(
                    vector, query_value, "google", url.rstrip("/"),
                    detection_method, "ghunt", text[:300]
                ))
        # حتى لو ما ظهرت روابط، وجود ghunt run معناه الإيميل موجود في نظام غوغل (إشارة)
        if text.strip() and "google" in text.lower():
            records.append(self._make_record(
                vector, query_value, "google", "https://accounts.google.com",
                detection_method, "ghunt", text[:300]
            ))
        return records

    def _parse_cross_scan(self, vector, query_value, stdout, detection_method) -> List[IdentityEvidenceRecord]:
        """cross_scan: ربط بين username و email عبر vectorين"""
        records: List[IdentityEvidenceRecord] = []
        text = stdout or ""
        for url in extract_urls(text):
            records.append(self._make_record(
                vector, query_value, self._extract_platform_from_url(url), url.rstrip("/"),
                detection_method, "cross_scan", text[:300]
            ))
        return records

    def _parse_generic(self, tool_name, vector, query_value, stdout, detection_method) -> List[IdentityEvidenceRecord]:
        """محلل عام لأي أداة: يستخرج الروابط ويخصم المنصة من النطاق."""
        records: List[IdentityEvidenceRecord] = []
        seen_urls = set()
        for url in extract_urls(stdout or ""):
            url = url.rstrip("/")
            if url in seen_urls:
                continue
            seen_urls.add(url)
            # تجاهل الروابط العامة التي لا تحتوي على القيمة المفحوصة (لـ username vector)
            if vector == OSINTVector.USERNAME and query_value.lower() not in url.lower():
                continue
            records.append(self._make_record(
                vector, query_value, self._extract_platform_from_url(url), url,
                detection_method, tool_name, stdout[:300]
            ))
        return records

    # ── المن helpers ──────────────────────────────────────────────────

    def _make_record(self, vector, query_value, platform, match_url, detection_method,
                     tool_name, raw_line) -> IdentityEvidenceRecord:
        digest = hashlib.md5(f"{tool_name}:{platform}:{match_url}:{raw_line[:80]}".encode()).hexdigest()[:16]
        return IdentityEvidenceRecord(
            record_id="",  # يُولّد تلقائيًا
            vector=vector,
            platform=platform,
            query_value=query_value,
            match_url=match_url,
            detection_method=detection_method,
            raw_response_digest=digest,
            tool_name=tool_name,
            evidence_level="E0",
            validation_note=raw_line[:120],
        )

    # ── dedupe + corroboration ────────────────────────────────────────

    def _dedupe(self, records: List[IdentityEvidenceRecord], current_tool: str) -> List[IdentityEvidenceRecord]:
        """
        يدمج السجلات المكررة (نفس canonical_key) ويترقى E0→E1 عند corroboration.
        """
        out: List[IdentityEvidenceRecord] = []
        for rec in records:
            key = rec.canonical_key
            self._corroboration_counts.setdefault(key, []).append(rec.tool_name)

            if key in self._seen_keys:
                existing = self._seen_keys[key]
                # أضف الأداة الجديدة للقائمة المساندة إن لم تكن موجودة
                if current_tool not in existing.corroborating_tools:
                    existing.corroborating_tools.append(current_tool)
                if rec.tool_name not in existing.corroborating_tools:
                    existing.corroborating_tools.append(rec.tool_name)

                # ترقية E0 → E1 لو ritrovنا مصدرين مختلفين للكشف عن نفس المنصة+الرابط
                distinct_tools = set(existing.corroborating_tools)
                if existing.evidence_level == EvidenceLevel.E0 and len(distinct_tools) >= 2:
                    existing.evidence_level = EvidenceLevel.E1
                    existing.validation_note += f" | corroborated by {len(distinct_tools)} tools"
                continue

            # سجل جديد
            rec.corroborating_tools = [current_tool]
            self._seen_keys[key] = rec
            out.append(rec)

        return out

    def flush(self) -> List[IdentityEvidenceRecord]:
        """إرجاع كل السجلات المُخزنة وإفراغ الحالة (للاستخدام مرة واحدة لكل 쿼ي)."""
        all_recs = list(self._seen_keys.values())
        self._seen_keys.clear()
        self._corroboration_counts.clear()
        return all_recs

    # ── حفظ الملف ───────────────────────────────────────────────────

    @staticmethod
    def save_evidence_file(records: List[IdentityEvidenceRecord], query_value: str, output_dir: str) -> str:
        """حفظ السجلات كملف JSON في مجلد مخرجات الأدوات."""
        import os
        os.makedirs(output_dir, exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", query_value)
        path = os.path.join(output_dir, f"osint_identity_{safe}.json")
        data = [r.to_dict() for r in records]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return path
