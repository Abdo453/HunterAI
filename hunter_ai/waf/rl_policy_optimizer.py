"""
RL Policy Optimizer — وكيل تحسين السياسة بالتعلم المعزز لتجاوز WAF
======================================================================
يستخدم تعلم معزز بسيط (Q-learning محسن) لاتخاذ قرار أي تقنية من سلم التجاوز
تُستخدم لاحقاً، بناءً على سجل النجاح/الفشل المخزن في WAFGeneBank.

الحالة (state): (waf_type, technique_level) → التقنيات التي جُربت
الإجراء (action): اختيار تقنية معينة من مستوى معين
المكافأة (reward): +1 للنجاح، -0.1 للفشل، 0 للتخطي

مستوحى من أبحاث AutoWAFuzzer و RADAGAS — الحلقة التدريبية:
  2000 حلقة مبدئية → 500 حلقة مركزة (كما في الأبحاث)
"""
from __future__ import annotations

import json
import math
import os
import random
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from memory.waf_gene_bank import WAFGeneBank, GeneRecord


@dataclass
class RLPick:
    technique_level: int
    technique_name: str
    payload: str
    confidence: float  # 0.0 إلى 1.0 — مدى ثقة الوكيل في هذه الاختيار


class RLPolicyOptimizer:
    """
    يحفظ جدول Q-values per (waf_type, technique) ويحدثه بعد كل محاولة.
    لا يحتاج إلى TensorFlow/PyTorch — يمكن تشغيله على أي جهاز.
    """

    def __init__(self, gene_bank: Optional[WAFGeneBank] = None,
                 storage_dir: str = "data/waf_rl_policy",
                 alpha: float = 0.2, gamma: float = 0.9, epsilon: float = 0.15):
        self.gene_bank = gene_bank or WAFGeneBank()
        self.dir = Path(storage_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.alpha = alpha      # معدل التعلم
        self.gamma = gamma      # خصم المكافآت المستقبلية
        self.epsilon = epsilon  # معدل الاستكشاف (exploration)
        self.q_table: Dict[str, Dict[str, float]] = {}
        self._load()

    # ------------------------------------------------------------------ #
    # persistence
    # ------------------------------------------------------------------ #
    def _file_for(self, waf_type: str) -> Path:
        safe = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in waf_type).strip("_") or "unknown"
        return self.dir / f"{safe}.json"

    def _load(self) -> None:
        for p in self.dir.glob("*.json"):
            try:
                waf_type = p.stem
                self.q_table[waf_type] = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                continue

    def _save(self, waf_type: str) -> None:
        p = self._file_for(waf_type)
        p.write_text(json.dumps(self.q_table.get(waf_type, {}), indent=2, ensure_ascii=False),
                     encoding="utf-8")

    # ------------------------------------------------------------------ #
    # core RL
    # ------------------------------------------------------------------ #
    def _q(self, waf_type: str, technique: str) -> float:
        return self.q_table.get(waf_type, {}).get(technique, 0.0)

    def _set_q(self, waf_type: str, technique: str, value: float) -> None:
        self.q_table.setdefault(waf_type, {})[technique] = value

    def pick_technique(
        self,
        waf_type: str,
        available_techniques: List[Tuple[int, str, str]],  # (level, name, payload)
        explore: bool = True,
    ) -> Optional[RLPick]:
        """
        يختار أفضل تقنية بناءً على Q-table، مع استكشاف偶 (epsilon-greedy).
        """
        if not available_techniques:
            return None

        waf_key = waf_type or "unknown"

        if explore and random.random() < self.epsilon:
            level, name, payload = random.choice(available_techniques)
            return RLPick(level, name, payload, confidence=0.5)

        # استغلال: اختر التقنية ذات أعلى Q-value
        best: Optional[RLPick] = None
        best_q = -math.inf
        for level, name, payload in available_techniques:
            q = self._q(waf_key, name)
            if q > best_q:
                best_q = q
                best = RLPick(level, name, payload, confidence=min(1.0, max(0.0, (q + 1) / 2)))

        return best or RLPick(available_techniques[0][0], available_techniques[0][1],
                              available_techniques[0][2], confidence=0.5)

    def update(
        self,
        waf_type: str,
        technique_name: str,
        success: bool,
        reward: Optional[float] = None,
    ) -> None:
        """
        يحدث Q-value بعد مراقبة نتيجة المحاولة.
        """
        waf_key = waf_type or "unknown"
        old_q = self._q(waf_key, technique_name)
        r = reward if reward is not None else (1.0 if success else -0.1)

        # Q-learning update: Q(s,a) = Q(s,a) + alpha * (r + gamma * max(Q) - Q(s,a))
        max_future_q = max(
            (self._q(waf_key, t) for t in self.q_table.get(waf_key, {})),
            default=0.0,
        )
        new_q = old_q + self.alpha * (r + self.gamma * max_future_q - old_q)
        self._set_q(waf_key, technique_name, new_q)
        self._save(waf_key)

    # ------------------------------------------------------------------ #
    # training loop (offline from gene bank history)
    # ------------------------------------------------------------------ #
    def train_from_history(self, episodes: int = 2000) -> Dict[str, Any]:
        """
        يُدرّب السياسة من سجل bank التاريخي.
        episodes: عدد الحلقات التدريبية (الأبحاث توصي بـ 2000 ثم 500 مركزة).
        """
        stats = {"episodes": episodes, "updates": 0}
        all_records: List[GeneRecord] = []
        for records in self.gene_bank._index.values():
            all_records.extend(records)

        if not all_records:
            return {"message": "no history to train from", "episodes": 0}

        for _ in range(episodes):
            record = random.choice(all_records)
            self.update(record.waf_type, record.technique_name, record.success,
                        reward=1.0 if record.success else -0.1)
            stats["updates"] += 1

        # حفظ كل الجداول
        for wt in list(self.q_table.keys()):
            self._save(wt)

        return stats

    def focused_train(self, waf_type: str, episodes: int = 500) -> Dict[str, Any]:
        """
        تدريب مركز على WAF معين (مثل 500 حلقة كما في الأبحاث).
        """
        stats = {"episodes": episodes, "waf_type": waf_type, "updates": 0}
        records = self.gene_bank._index.get(waf_type, [])
        if not records:
            return {"message": f"no history for {waf_type}", "episodes": 0}

        for _ in range(episodes):
            record = random.choice(records)
            self.update(record.waf_type, record.technique_name, record.success,
                        reward=1.0 if record.success else -0.1)
            stats["updates"] += 1

        self._save(waf_type)
        return stats

    def summary(self) -> Dict[str, Any]:
        total_techniques = sum(len(v) for v in self.q_table.values())
        return {
            "waf_types": len(self.q_table),
            "total_techniques": total_techniques,
            "epsilon": self.epsilon,
            "alpha": self.alpha,
            "gamma": self.gamma,
        }


__all__ = ["RLPolicyOptimizer", "RLPick"]
