"""WhatWeb Technology Fingerprinting — L2 AI Analyzer + L5 Evidence Reviewer
Normalizer + Duplicate Detector + Evidence Reviewer (rule-based، لا LLM لكل خطوة)
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from core.whatweb.schemas import (
    WhatWebAssetRecord,
    WhatWebEvidenceLevel,
    WhatWebPluginRecord,
)

log = logging.getLogger("whatweb.analyzer")


class WhatWebNormalizer:
    """L2: يحوّل مخرجات whatweb JSON إلى WhatWebAssetRecord موحد.

    whatweb عبر --log-json=- يُخرج سطر JSON واحد لكل هدف، أو مصفوفة JSON.
    """

    @staticmethod
    def _parse_payload(text: str) -> List[Dict[str, Any]]:
        text = (text or "").strip()
        if not text:
            return []
        # مصفوفة JSON كاملة
        try:
            data = json.loads(text)
            if isinstance(data, list):
                return [d for d in data if isinstance(d, dict)]
            if isinstance(data, dict):
                return [data]
        except json.JSONDecodeError:
            pass
        # أسطر JSON مستقلة (JSON Lines)
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

    @staticmethod
    def _first_str(values: Any) -> Optional[str]:
        if values is None:
            return None
        if isinstance(values, list):
            for v in values:
                if v is not None:
                    return str(v)
            return None
        return str(values)

    def normalize(self, text: str) -> List[WhatWebAssetRecord]:
        records: List[WhatWebAssetRecord] = []
        for entry in self._parse_payload(text):
            target = entry.get("target") or entry.get("url") or ""
            url = entry.get("url") or target
            if not url:
                continue
            http_status = entry.get("http_status")
            try:
                http_status = int(http_status) if http_status is not None else None
            except (TypeError, ValueError):
                http_status = None

            raw_plugins = entry.get("plugins") or {}
            plugins: List[WhatWebPluginRecord] = []
            technologies: List[str] = []
            if isinstance(raw_plugins, dict):
                for name, plugin in raw_plugins.items():
                    if not isinstance(plugin, dict):
                        continue
                    p_name = plugin.get("name") or name
                    p_version = self._first_str(plugin.get("version"))
                    p_category = plugin.get("category")
                    try:
                        p_conf = int(plugin.get("confidence")) if plugin.get("confidence") is not None else None
                    except (TypeError, ValueError):
                        p_conf = None
                    p_evidence = plugin.get("evidence") or []
                    if not isinstance(p_evidence, list):
                        p_evidence = [str(p_evidence)]
                    plugins.append(
                        WhatWebPluginRecord(
                            name=p_name,
                            version=p_version,
                            category=p_category,
                            confidence=p_conf,
                            evidence=[str(e) for e in p_evidence],
                            url=url,
                        )
                    )
                    technologies.append(p_name)
                    if p_version:
                        technologies.append(f"{p_name}/{p_version}")

            record = WhatWebAssetRecord(
                target=target,
                url=url,
                http_status=http_status,
                server=entry.get("server"),
                plugins=plugins,
                technologies=sorted(set(technologies)),
                raw_json=entry,
                validation_note=f"whatweb {url}: {len(plugins)} plugins",
            )
            records.append(record)
        return records


class DuplicateDetector:
    """L2: يدمج السجلات المكررة لنفس الهدف (نفس url)."""

    def __init__(self) -> None:
        self._by_url: Dict[str, WhatWebAssetRecord] = {}

    def add(self, record: WhatWebAssetRecord) -> WhatWebAssetRecord:
        key = record.canonical_key
        existing = self._by_url.get(key)
        if existing is None:
            self._by_url[key] = record
            return record
        # دمج الإضافات بالتقنية
        existing_names = {p.name for p in existing.plugins}
        for p in record.plugins:
            if p.name not in existing_names:
                existing.plugins.append(p)
                existing_names.add(p.name)
        existing.technologies = sorted(set(existing.technologies) | set(record.technologies))
        existing.http_status = existing.http_status or record.http_status
        existing.server = existing.server or record.server
        return existing

    def flush(self) -> List[WhatWebAssetRecord]:
        out = list(self._by_url.values())
        self._by_url.clear()
        return out


class EvidenceReviewer:
    """L5 Verification: يراجع أدلة البصمة ويحدد مستوى الدليل والثقة."""

    def review(self, record: WhatWebAssetRecord) -> Dict[str, Any]:
        notes: List[str] = []
        confidence = 0.1  # القاعدة: بصمة واحدة غير كافية للإثبات الكامل

        if record.http_status is not None:
            confidence += 0.2
            notes.append(f"حالة HTTP مسجلة: {record.http_status}")
        if record.server:
            confidence += 0.1
            notes.append(f"خادم الويب: {record.server}")
        if record.plugins:
            confidence += 0.4
            notes.append(f"{len(record.plugins)} إضافة مكتشفة")
        if record.technologies:
            confidence += 0.2
        if record.http_status is not None and record.plugins:
            record.evidence_level = WhatWebEvidenceLevel.E1
            evidence_status = "sufficient"
        else:
            evidence_status = "raw"
            notes.append("بصمة أولية — يُنصح بالتأكيد عبر أداة ثانية")

        confidence = max(0.0, min(confidence, 1.0))
        return {
            "record_id": record.record_id,
            "target": record.target,
            "url": record.url,
            "http_status": record.http_status,
            "server": record.server,
            "plugin_count": len(record.plugins),
            "technologies": record.technologies,
            "evidence_status": evidence_status,
            "evidence_level": record.evidence_level,
            "confidence": round(confidence, 2),
            "confidence_label": self._label(confidence),
            "needs_verification": record.evidence_level != WhatWebEvidenceLevel.E1,
            "notes": notes,
            "recommendation": (
                "بصمة تقنية مرصودة (E0/E1) — صالحة لبناء سطح الهجوم، وليست إثباتًا لأي ثغرة بذاتها."
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
