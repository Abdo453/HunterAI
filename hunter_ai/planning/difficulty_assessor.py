"""
HunterAI Difficulty-Aware Planning (TDA)
========================================

تقييم صعوبة المهمة في الوقت الفعلي لاتخاذ قرار:
- EXPLOIT: استكمال المسار الحالي (المسار واعد)
- EXPLORE: تغيير المسار (المسار ضعيف أو استهلك الكثير من السياق)

الأبعاد الأربعة للتقييم (بناءً على أبحاث 2025-2026):
1. المدى المتوقع للمهمة (expected_duration)
2. ثقة الأدلة المتاحة (evidence_confidence)
3. حجم السياق المستهلك (context_consumed)
4. نسبة النجاح التاريخية في مهام مشابهة (historical_success_rate)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class DifficultyDecision(str, Enum):
    EXPLOIT = "exploit"   # استمر في المسار الحالي
    EXPLORE = "explore"   # غيّر المسار / جرب تقنية مختلفة


class TaskDifficulty(str, Enum):
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"
    CRITICAL = "critical"


@dataclass
class DifficultyAssessment:
    task_id: str
    target: str
    technique: str
    difficulty: TaskDifficulty
    decision: DifficultyDecision
    score: float  # 0.0 = سهل جداً، 1.0 = صعب جداً
    reasons: list[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "target": self.target,
            "technique": self.technique,
            "difficulty": self.difficulty.value,
            "decision": self.decision.value,
            "score": self.score,
            "reasons": self.reasons,
            "timestamp": self.timestamp,
        }


class TaskDifficultyAssessor:
    """
    يقيم صعوبة المهمة بناءً على أربعة أبعاد ويقرر whether to EXPLOIT or EXPLORE.
    """

    # عتبات اتخاذ القرار
    EXPLOIT_MAX_SCORE = 0.55   # أقل من ذلك -> استكمل المسار
    EXPLORE_MIN_SCORE = 0.75   # أكبر من ذلك -> غيّر المسار

    def __init__(self, history_dir: str = "data/sessions/difficulty_history"):
        self.history_dir = __import__("pathlib").Path(history_dir)
        self.history_dir.mkdir(parents=True, exist_ok=True)
        self._history: Dict[str, list[float]] = {}  # technique -> [scores]

    def _load_history(self, technique: str) -> list[float]:
        """تحميل سجل النجاح التاريخي لتقنية معينة."""
        path = self.history_dir / f"{technique}.json"
        if path.exists():
            try:
                import json
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return []
        return []

    def _save_history(self, technique: str, scores: list[float]) -> None:
        path = self.history_dir / f"{technique}.json"
        try:
            import json
            with open(path, "w", encoding="utf-8") as f:
                json.dump(scores[-100:], f)  # تحتفظ بآخر 100 سجل
        except Exception:
            pass

    def assess(
        self,
        task_id: str,
        target: str,
        technique: str,
        expected_duration_min: float,
        evidence_confidence: float,
        context_consumed_pct: float,
        current_findings: int = 0,
    ) -> DifficultyAssessment:
        """
        تقييم صعوبة المهمة واتخاذ قرار EXPLOIT أو EXPLORE.

        Args:
            task_id: معرف المهمة
            target: الهدف المستهدف
            technique: التقنية المستخدمة (مثلاً: idor, sqli, ssrf)
            expected_duration_min: المدة المتوقعة بالدقائق
            evidence_confidence: ثقة الأدلة من 0.0 إلى 1.0
            context_consumed_pct: نسبة السياق المستهلك من 0.0 إلى 1.0
            current_findings: عدد الاكتشافات الحالية لهذه المهمة
        """
        reasons: list[str] = []

        # البعد 1: المدى المتوقع للمهمة
        # كلما طالت المدة المتوقعة، زادت الصعوبة
        duration_score = min(expected_duration_min / 120.0, 1.0)  # 120 دقيقة =maximum
        if duration_score > 0.6:
            reasons.append(f"مدة طويلة متوقعة ({expected_duration_min:.0f} دقيقة)")

        # البعد 2: ثقة الأدلة
        # كلما كانت الثقة منخفضة، زادت الصعوبة
        confidence_score = 1.0 - evidence_confidence
        if evidence_confidence < 0.4:
            reasons.append(f"ثقة منخفضة في الأدلة ({evidence_confidence:.2f})")

        # البعد 3: حجم السياق المستهلك
        # كلما زاد الاستهلاك، زادت الصعوبة (خطر النسيان والهلوسة)
        context_score = context_consumed_pct
        if context_consumed_pct > 0.7:
            reasons.append(f"استهلاك مرتفع للسياق ({context_consumed_pct:.0%})")

        # البعد 4: نسبة النجاح التاريخية
        history = self._load_history(technique)
        if history:
            hist_success = sum(history) / len(history)
            hist_score = 1.0 - hist_success
            if hist_success < 0.3:
                reasons.append(f"نسبة نجاح تاريخية منخفضة ({hist_success:.0%})")
        else:
            hist_score = 0.5  # محايد عند عدم وجود تاريخ
            reasons.append("لا يوجد تاريخ سابق لهذه التقنية")

        # حساب النتيجة الإجمالية (متوازن الأبعاد الأربعة)
        score = (
            0.30 * duration_score +
            0.25 * confidence_score +
            0.25 * context_score +
            0.20 * hist_score
        )
        score = max(0.0, min(1.0, score))

        # تحديد مستوى الصعوبة
        if score < 0.30:
            difficulty = TaskDifficulty.EASY
        elif score < 0.55:
            difficulty = TaskDifficulty.MEDIUM
        elif score < 0.75:
            difficulty = TaskDifficulty.HARD
        else:
            difficulty = TaskDifficulty.CRITICAL

        # اتخاذ القرار
        if score <= self.EXPLOIT_MAX_SCORE:
            decision = DifficultyDecision.EXPLOIT
        elif score >= self.EXPLORE_MIN_SCORE:
            decision = DifficultyDecision.EXPLORE
        else:
            # منطقة رمادية: اعتمد على عدد الاكتشافات الحالية
            if current_findings > 0:
                decision = DifficultyDecision.EXPLOIT
                reasons.append("مسار واعد رغم الصعوبة المتوسطة — اكتشافات موجودة")
            else:
                decision = DifficultyDecision.EXPLORE
                reasons.append("لا اكتشافات بعد والمسار متوسط الصعوبة — يُفضل التغيير")

        assessment = DifficultyAssessment(
            task_id=task_id,
            target=target,
            technique=technique,
            difficulty=difficulty,
            decision=decision,
            score=score,
            reasons=reasons,
        )

        # حفظ النتيجة في التاريخ
        history.append(1.0 if decision == DifficultyDecision.EXPLOIT else 0.0)
        self._save_history(technique, history)

        return assessment

    def record_outcome(self, technique: str, succeeded: bool) -> None:
        """تسجيل نتيجة مهمة لتحديث التاريخ."""
        history = self._load_history(technique)
        history.append(1.0 if succeeded else 0.0)
        self._save_history(technique, history)
