"""
Learning Profile & Adaptive Pedagogical Modeler
Tracks individual user concept proficiency, recurrent misconceptions, and adapts explanation complexity.
"""
import json
import logging
import time
from pathlib import Path
from typing import Dict, Optional
from agents.security_intelligence.schemas import LearningProfileData, ExplanationLevel, QuizEvaluation

log = logging.getLogger("security_intelligence.learning_profile")


class LearningProfile:
    """ملف المتدرب الأمني: التكيف التلقائي مع مستوى فهم المستخدم وتوجيه أسلوب الشرح المناسب"""

    def __init__(self, storage_file: Optional[str] = "data/memory/learning_profile.json"):
        self.storage_file = storage_file
        self.profile = LearningProfileData()
        self._load()

    def get_profile(self) -> LearningProfileData:
        return self.profile


    def record_evaluation(self, eval_result: QuizEvaluation, concept: str):
        self.profile.total_quizzes_taken += 1
        if eval_result.is_correct:
            self.profile.total_correct_quizzes += 1
            # Boost mastery score
            curr = self.profile.mastery_scores.get(concept, 0.5)
            self.profile.mastery_scores[concept] = round(min(1.0, curr + 0.20), 2)
        else:
            # Record recurring mistake
            self.profile.recurring_mistakes[concept] = self.profile.recurring_mistakes.get(concept, 0) + 1
            curr = self.profile.mastery_scores.get(concept, 0.5)
            self.profile.mastery_scores[concept] = round(max(0.0, curr - 0.20), 2)

        self.profile.last_active = time.time()
        self._adapt_preferred_level(concept)
        self._save()

    def get_optimal_explanation_level(self, concept: str) -> ExplanationLevel:
        """تحديد مستوى الشرح الأنسب للمستخدم في هذا المفهوم تحديداً"""
        score = self.profile.mastery_scores.get(concept, 0.5)
        mistakes = self.profile.recurring_mistakes.get(concept, 0)

        if mistakes >= 2 or score < 0.40:
            return ExplanationLevel.SIMPLE
        elif score < 0.70:
            return ExplanationLevel.TECHNICAL
        elif score < 0.90:
            return ExplanationLevel.PENTESTER
        else:
            return ExplanationLevel.RESEARCHER

    def _adapt_preferred_level(self, concept: str):
        self.profile.preferred_level = self.get_optimal_explanation_level(concept)

    def _save(self):
        if not self.storage_file:
            return
        try:
            p = Path(self.storage_file)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(self.profile.model_dump(), indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception as e:
            log.warning(f"Failed to save LearningProfile: {e}")

    def _load(self):
        if not self.storage_file:
            return
        try:
            p = Path(self.storage_file)
            if p.exists():
                data = json.loads(p.read_text(encoding="utf-8"))
                self.profile = LearningProfileData(**data)
        except Exception as e:
            log.warning(f"Failed to load LearningProfile: {e}")
