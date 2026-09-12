"""
Learning Memory
Persistent user progress, completed modules, quiz records, and conceptual proficiency.
"""
import json
import logging
import time
from pathlib import Path
from typing import Dict, List, Any, Optional
from agents.security_intelligence.config import SecurityIntelligenceConfig

log = logging.getLogger("security_intelligence.learning_memory")


class LearningMemory:
    """ذاكرة تقدم المستخدم التعليمي: المفاهيم المتقنة، نقاط الضعف، وسجل الاختبارات"""

    def __init__(self, storage_file: Optional[str] = None):
        self.storage_file = storage_file or SecurityIntelligenceConfig.LEARNING_MEMORY_PATH
        self.mastered_concepts: List[str] = []
        self.weak_concepts: List[str] = []
        self.quiz_history: List[Dict[str, Any]] = []
        self.lessons_completed: List[str] = []
        self.overall_score: float = 0.0
        self._load()

    def record_quiz_result(self, topic: str, is_correct: bool, concept_tested: str, score: float):
        self.quiz_history.append({
            "topic": topic,
            "is_correct": is_correct,
            "concept": concept_tested,
            "score": score,
            "timestamp": time.time()
        })
        if is_correct:
            if concept_tested not in self.mastered_concepts:
                self.mastered_concepts.append(concept_tested)
            if concept_tested in self.weak_concepts:
                self.weak_concepts.remove(concept_tested)
        else:
            if concept_tested not in self.weak_concepts:
                self.weak_concepts.append(concept_tested)
        self._save()

    def record_lesson_completed(self, lesson_id: str):
        if lesson_id not in self.lessons_completed:
            self.lessons_completed.append(lesson_id)
            self._save()

    def _save(self):
        try:
            p = Path(self.storage_file)
            p.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "mastered_concepts": self.mastered_concepts,
                "weak_concepts": self.weak_concepts,
                "quiz_history": self.quiz_history,
                "lessons_completed": self.lessons_completed,
                "overall_score": self.overall_score
            }
            p.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception as e:
            log.warning(f"Failed to save LearningMemory: {e}")

    def _load(self):
        try:
            p = Path(self.storage_file)
            if p.exists():
                data = json.loads(p.read_text(encoding="utf-8"))
                self.mastered_concepts = data.get("mastered_concepts", [])
                self.weak_concepts = data.get("weak_concepts", [])
                self.quiz_history = data.get("quiz_history", [])
                self.lessons_completed = data.get("lessons_completed", [])
                self.overall_score = data.get("overall_score", 0.0)
        except Exception as e:
            log.warning(f"Failed to load LearningMemory: {e}")
