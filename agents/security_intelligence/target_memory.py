"""
Target Memory
Persistent target-specific observations, assets, confirmed findings, and history.
"""
import json
import logging
import time
from pathlib import Path
from typing import Dict, List, Any, Optional
from agents.security_intelligence.config import SecurityIntelligenceConfig

log = logging.getLogger("security_intelligence.target_memory")


class TargetMemory:
    """ذاكرة الهدف المحدد: التاريخ، الثغرات المؤكدة، والأنماط المكتشفة لكل هدف"""

    def __init__(self, storage_file: Optional[str] = None):
        self.storage_file = storage_file or SecurityIntelligenceConfig.TARGET_MEMORY_PATH
        self.targets: Dict[str, Dict[str, Any]] = {}
        self._load()

    def get_or_create_target(self, target_host: str) -> Dict[str, Any]:
        if target_host not in self.targets:
            self.targets[target_host] = {
                "host": target_host,
                "created_at": time.time(),
                "endpoints": [],
                "confirmed_findings": [],
                "suspected_weaknesses": [],
                "auth_patterns": {},
                "waf_detected": None
            }
            self._save()
        return self.targets[target_host]

    def record_finding(self, target_host: str, finding_id: str, vuln_type: str, confidence: float):
        t = self.get_or_create_target(target_host)
        t["confirmed_findings"].append({
            "finding_id": finding_id,
            "vuln_type": vuln_type,
            "confidence": confidence,
            "timestamp": time.time()
        })
        self._save()

    def get_findings_count(self, target_host: str) -> int:
        t = self.targets.get(target_host)
        if t:
            return len(t.get("confirmed_findings", []))
        return 0

    def _save(self):
        try:
            p = Path(self.storage_file)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(self.targets, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception as e:
            log.warning(f"Failed to save TargetMemory: {e}")

    def _load(self):
        try:
            p = Path(self.storage_file)
            if p.exists():
                self.targets = json.loads(p.read_text(encoding="utf-8"))
        except Exception as e:
            log.warning(f"Failed to load TargetMemory: {e}")
