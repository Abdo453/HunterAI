"""
False Positive Memory
Persistent memory for previously refuted patterns, benign anomalies, and baseline behaviors.
"""
import json
import logging
import time
from pathlib import Path
from typing import Dict, List, Any, Optional
from agents.security_intelligence.config import SecurityIntelligenceConfig

log = logging.getLogger("security_intelligence.false_positive_memory")


class FalsePositiveMemory:
    """بنك الأنماط الكاذبة السابقة: لمنع تكرار الإنذارات الكاذبة وتعلم السلوك الطبيعي للتطبيق"""

    def __init__(self, storage_file: Optional[str] = SecurityIntelligenceConfig.FALSE_POSITIVE_MEMORY_PATH):
        self.storage_file = storage_file
        self.false_positive_records: List[Dict[str, Any]] = []
        if self.storage_file:
            self._load()


    def record_false_positive(self, pattern: str, vuln_type: str, reason: str, endpoint: str):
        self.false_positive_records.append({
            "pattern": pattern,
            "vuln_type": vuln_type,
            "reason": reason,
            "endpoint": endpoint,
            "recorded_at": time.time()
        })
        self._save()

    def is_known_false_positive(self, pattern: str, vuln_type: str, endpoint: str) -> Optional[Dict[str, Any]]:
        for rec in self.false_positive_records:
            if rec["vuln_type"].lower() == vuln_type.lower():
                if rec["endpoint"] == endpoint or (rec["pattern"] and rec["pattern"] in pattern):
                    return rec
        return None

    def _save(self):
        if not self.storage_file:
            return
        try:
            p = Path(self.storage_file)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(self.false_positive_records, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception as e:
            log.warning(f"Failed to save FalsePositiveMemory: {e}")

    def _load(self):
        try:
            p = Path(self.storage_file)
            if p.exists():
                self.false_positive_records = json.loads(p.read_text(encoding="utf-8"))
        except Exception as e:
            log.warning(f"Failed to load FalsePositiveMemory: {e}")
