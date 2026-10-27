"""
RAG Agent — وكيل استرجاع السياق التهديدي لـ WAF Bypass
======================================================
يسترجع سياق التهديدات من مصادر منظمة:
  1. MISP (via API) — إن كان هناك مفتاح API وإعدادات اتصال
  2. ملفات محلية (JSON/Markdown) — fallback آمن بدون اتصال خارجي

يُستخدم لربط محاولة التجاوز بمعرفة حديثة عن WAF والثغرات المعروفة،
كما في إطار AutoWAFuzzer.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class ThreatContext:
    waf_type: str
    technique: str
    source: str  # "misp" | "local" | "none"
    confidence: float
    notes: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class RAGAgent:
    """
    يسترجع سياق التهديد لنوع WAF معين وتقنية معينة.
    """

    def __init__(self, local_dir: str = "data/waf_rag_sources",
                 misp_url: Optional[str] = None,
                 misp_api_key: Optional[str] = None,
                 misp_verify_cert: bool = True):
        self.local_dir = Path(local_dir)
        self.local_dir.mkdir(parents=True, exist_ok=True)
        self.misp_url = misp_url
        self.misp_api_key = misp_api_key
        self.misp_verify_cert = misp_verify_cert
        self._local_index: Dict[str, List[Dict[str, Any]]] = {}
        self._load_local_sources()

    # ------------------------------------------------------------------ #
    # local sources
    # ------------------------------------------------------------------ #
    def _load_local_sources(self) -> None:
        """يحمل ملفات السياق التهديدي المحلّية من المجلد."""
        if not self.local_dir.is_dir():
            return
        for p in self.local_dir.glob("*.json"):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                waf_type = p.stem.lower()
                self._local_index.setdefault(waf_type, []).extend(data if isinstance(data, list) else [data])
            except Exception:
                continue
        for p in self.local_dir.glob("*.md"):
            try:
                waf_type = p.stem.lower()
                content = p.read_text(encoding="utf-8")
                self._local_index.setdefault(waf_type, []).append({
                    "source": "markdown",
                    "content": content,
                    "technique": "general",
                    "notes": f"ملف محلي: {p.name}",
                })
            except Exception:
                continue

    def add_local_source(self, waf_type: str, entries: List[Dict[str, Any]]) -> None:
        """يضيف مصادر محلية programmatically."""
        self._local_index.setdefault(waf_type, []).extend(entries)

    # ------------------------------------------------------------------ #
    # MISP integration
    # ------------------------------------------------------------------ #
    def query_misp(self, waf_type: str, technique: str, limit: int = 5) -> List[ThreatContext]:
        """
        يستعلم MISP عن أحداث تتعلق بهذا WAF والتقنية.
        يحتاج إلى misp_url و misp_api_key.
        """
        if not self.misp_url or not self.misp_api_key:
            return []

        try:
            import httpx
            headers = {
                "Authorization": self.misp_api_key,
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
            # البحث عن أحداث تحتوي على اسم WAF
            search_url = f"{self.misp_url.rstrip('/')}/attributes/restSearch"
            payload = {
                "returnFormat": "json",
                "limit": limit,
                "search": waf_type,
            }
            with httpx.Client(timeout=15, verify=self.misp_verify_cert) as client:
                resp = client.post(search_url, headers=headers, json=payload)
                if resp.status_code != 200:
                    return []
                data = resp.json()

            contexts: List[ThreatContext] = []
            for attr in data.get("response", {}).get("Attribute", []):
                contexts.append(ThreatContext(
                    waf_type=waf_type,
                    technique=technique,
                    source="misp",
                    confidence=0.8,
                    notes=f"MISP event {attr.get('Event', {}).get('id', '?')}: {attr.get('value', '')}",
                ))
            return contexts
        except Exception:
            return []

    # ------------------------------------------------------------------ #
    # public API
    # ------------------------------------------------------------------ #
    def retrieve(
        self,
        waf_type: str,
        technique: str,
        use_misp: bool = False,
    ) -> List[ThreatContext]:
        """
        يسترجع كل السياق المتاح: محلي + MISP (إن توفرت الإعدادات).
        """
        contexts: List[ThreatContext] = []
        waf_key = (waf_type or "unknown").lower()

        # محلي (بحث غير حساس لحالة الأحرف)
        local_entries = []
        for key, entries in self._local_index.items():
            if key.lower() == waf_key:
                local_entries.extend(entries)
        if not local_entries and waf_key in self._local_index:
            local_entries = self._local_index[waf_key]

        for entry in local_entries:
            contexts.append(ThreatContext(
                waf_type=waf_type,
                technique=technique,
                source=entry.get("source", "local"),
                confidence=entry.get("confidence", 0.6),
                notes=entry.get("notes", ""),
            ))

        # MISP
        if use_misp:
            contexts.extend(self.query_misp(waf_type, technique))

        return contexts

    def summary(self) -> Dict[str, Any]:
        return {
            "local_waf_types": len(self._local_index),
            "local_entries": sum(len(v) for v in self._local_index.values()),
            "misp_configured": bool(self.misp_url and self.misp_api_key),
        }


__all__ = ["RAGAgent", "ThreatContext"]
