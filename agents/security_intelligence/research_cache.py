"""
Research Cache
Prevents redundant external queries for CVEs, CWEs, and security advisories by caching verified research reports.
"""
import json
import logging
import time
from pathlib import Path
from typing import Dict, Optional
from agents.security_intelligence.schemas import ResearchReport

log = logging.getLogger("security_intelligence.research_cache")


class ResearchCache:
    """مخزن الذاكرة المؤقتة للأبحاث الأمنية: تفادي تكرار البحث عن نفس الـ CVE أو الثغرة"""

    def __init__(self, cache_file: Optional[str] = "data/memory/research_cache.json", ttl_seconds: int = 86400):
        self.cache_file = cache_file
        self.ttl_seconds = ttl_seconds
        self._cache: Dict[str, Dict] = {}
        self._load()

    def get(self, query_or_cve: str) -> Optional[ResearchReport]:
        key = query_or_cve.strip().lower()
        item = self._cache.get(key)
        if not item:
            return None

        # Check TTL
        created_at = item.get("cached_at", 0)
        if time.time() - created_at > self.ttl_seconds:
            del self._cache[key]
            self._save()
            return None

        try:
            report_data = item.get("report")
            report = ResearchReport(**report_data)
            report.cached = True
            return report
        except Exception as e:
            log.warning(f"Error deserializing cached research for {key}: {e}")
            return None

    def set(self, query_or_cve: str, report: ResearchReport):
        key = query_or_cve.strip().lower()
        self._cache[key] = {
            "cached_at": time.time(),
            "report": report.model_dump()
        }
        self._save()

    def _save(self):
        if not self.cache_file:
            return
        try:
            p = Path(self.cache_file)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(self._cache, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception as e:
            log.warning(f"Failed to save ResearchCache: {e}")

    def _load(self):
        if not self.cache_file:
            return
        try:
            p = Path(self.cache_file)
            if p.exists():
                self._cache = json.loads(p.read_text(encoding="utf-8"))
        except Exception as e:
            log.warning(f"Failed to load ResearchCache: {e}")
