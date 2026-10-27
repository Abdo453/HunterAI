"""
HunterAI WAF RL Train - تدريب سياسة التعلم المعزز (Offline)
=============================================================

تدريب سياسة offline لاختيار أفضل تقنية تجاوز WAF بناءً على
نتائج المحاولات السابقة المخزنة في الذاكرة المنظمة.

يستخدم نموذجاً بسيطاً (Multi-Armed Bandit) لاختيار التقنية
التي حققت أعلى معدل نجاح في الماضي.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class TechniquePerformance:
    technique: str
    attempts: int = 0
    successes: int = 0
    failures: int = 0
    last_success: Optional[float] = None
    last_failure: Optional[float] = None

    @property
    def success_rate(self) -> float:
        if self.attempts == 0:
            return 0.5  # محايد عند عدم وجود بيانات
        return self.successes / self.attempts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique": self.technique,
            "attempts": self.attempts,
            "successes": self.successes,
            "failures": self.failures,
            "success_rate": self.success_rate,
            "last_success": self.last_success,
            "last_failure": self.last_failure,
        }


@dataclass
class RLTrainingResult:
    target: str
    techniques_trained: int
    best_technique: Optional[str]
    best_success_rate: float
    technique_performances: List[TechniquePerformance]
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "techniques_trained": self.techniques_trained,
            "best_technique": self.best_technique,
            "best_success_rate": self.best_success_rate,
            "technique_performances": [t.to_dict() for t in self.technique_performances],
            "timestamp": self.timestamp,
        }


class WAFRLTrainer:
    """
    مدرب سياسة التعلم المعزز لـ WAF bypass.
    يستخدم البيانات المخزنة في الذاكرة المنظمة لحساب أداء كل تقنية
    وتحديد أفضل تقنية للهدف المحدد.
    """

    def __init__(self, structured_memory=None):
        self.structured_memory = structured_memory
        self.techniques = [
            "direct",
            "url_encode",
            "double_url_encode",
            "html_entity",
            "case_variation",
            "comment_insertion",
            "parameter_pollution",
            "payload_padding",
            "parser_bug",
            "semantic_pollution",
            "websocket_bypass",
            "grpc_bypass",
            "fingerprint_spoofing",
        ]

    def _load_history(self, target: str) -> Dict[str, List[Dict[str, Any]]]:
        """تحميل تاريخ المحاولات من الذاكرة المنظمة."""
        if not self.structured_memory:
            return {}
        from hunter_ai.memory.structured_memory import MemoryType
        # استرجاع جميع entradas الذاكرة للهدف
        keys = self.structured_memory.list_keys(MemoryType.SEMANTIC, target)
        history: Dict[str, List[Dict[str, Any]]] = {}
        for key in keys:
            entry = self.structured_memory.read(MemoryType.SEMANTIC, target, key)
            if entry and isinstance(entry.value, dict):
                technique = entry.value.get("technique", "unknown")
                if technique not in history:
                    history[technique] = []
                history[technique].append(entry.value)
        return history

    def train(
        self,
        target: str,
    ) -> RLTrainingResult:
        """
        تدريب السياسة بناءً على التاريخ المخزّن.

        Args:
            target: الهدف المستهدف
        """
        history = self._load_history(target)
        performances: List[TechniquePerformance] = []

        for technique in self.techniques:
            attempts = technique_history = history.get(technique, [])
            successes = sum(
                1 for h in attempts
                if h.get("success", False) or h.get("status") == "READY"
            )
            failures = len(attempts) - successes

            perf = TechniquePerformance(
                technique=technique,
                attempts=len(attempts),
                successes=successes,
                failures=failures,
            )
            if attempts:
                perf.last_success = max(
                    (h.get("timestamp", 0) for h in attempts if h.get("success", False)),
                    default=None,
                )
                perf.last_failure = max(
                    (h.get("timestamp", 0) for h in attempts if not h.get("success", False) and h.get("status") != "READY"),
                    default=None,
                )
            performances.append(perf)

        # ترتيب حسب معدل النجاح
        performances.sort(key=lambda p: p.success_rate, reverse=True)

        best = performances[0] if performances else None
        best_technique = best.technique if best else None
        best_rate = best.success_rate if best else 0.0

        return RLTrainingResult(
            target=target,
            techniques_trained=len(performances),
            best_technique=best_technique,
            best_success_rate=best_rate,
            technique_performances=performances,
        )

    def recommend_technique(self, target: str) -> Optional[str]:
        """التوصية بأفضل تقنية للهدف بناءً على التدريب."""
        result = self.train(target)
        return result.best_technique

    def record_outcome(
        self,
        target: str,
        technique: str,
        success: bool,
        evidence: Optional[Dict[str, Any]] = None,
    ) -> None:
        """تسجيل نتيجة محاولة لتحديث النموذج."""
        if not self.structured_memory:
            return
        from hunter_ai.memory.structured_memory import MemoryType
        self.structured_memory.write(
            MemoryType.SEMANTIC,
            target,
            f"rl_outcome:{technique}:{int(time.time())}",
            {
                "technique": technique,
                "success": success,
                "evidence": evidence or {},
                "timestamp": time.time(),
            },
            ttl_seconds=None,
        )
