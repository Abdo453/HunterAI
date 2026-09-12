"""
Target Memory & False Positives Knowledge Base
==============================================
Persistent memory per target:
- scope.json, endpoints.json, parameters.json, technologies.json, waf.json
- observations.json, hypotheses.json, verified_findings.json, false_positives.json
- do_not_repeat.json: Prevents repeating tests on parameters known to be benign reflections.
"""
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("hunter_ai.target_memory")


class TargetMemory:
    """Manages persistent state and false positive suppression across scans"""

    def __init__(self, target_host: str, base_dir: str = "data/scans"):
        sanitized_host = target_host.replace(":", "_").replace("/", "_")
        self.mem_dir = Path(base_dir) / sanitized_host
        self.mem_dir.mkdir(parents=True, exist_ok=True)

        self.do_not_repeat_file = self.mem_dir / "do_not_repeat.json"
        self.false_positives_file = self.mem_dir / "false_positives.json"

        self._do_not_repeat: Set[str] = self._load_set(self.do_not_repeat_file)
        self._false_positives: List[Dict[str, Any]] = self._load_list(self.false_positives_file)

    def _load_set(self, path: Path) -> Set[str]:
        if path.exists():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return set(json.load(f))
            except Exception:
                pass
        return set()

    def _load_list(self, path: Path) -> List[Dict[str, Any]]:
        if path.exists():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return []

    def should_skip_param(self, param_name: str, test_type: str = "") -> bool:
        key = f"{param_name}:{test_type}" if test_type else param_name
        return key in self._do_not_repeat or param_name in self._do_not_repeat

    def record_benign_param(self, param_name: str, test_type: str = "", reason: str = "benign_reflection"):
        key = f"{param_name}:{test_type}" if test_type else param_name
        self._do_not_repeat.add(key)
        self._false_positives.append({
            "param": param_name,
            "test_type": test_type,
            "reason": reason
        })
        self.save()

    def save(self):
        try:
            with open(self.do_not_repeat_file, "w", encoding="utf-8") as f:
                json.dump(list(self._do_not_repeat), f, indent=2)
            with open(self.false_positives_file, "w", encoding="utf-8") as f:
                json.dump(self._false_positives, f, indent=2)
        except Exception:
            logger.exception("Failed to persist TargetMemory")