"""
Teacher & Educational Coordinator
Transforms findings and topics into adaptive pedagogical lessons and interactive quizzes using LearningProfile.
"""
import logging
from typing import Dict, Any, Optional
from agents.security_intelligence.schemas import (
    SecurityLesson,
    QuizQuestion,
    QuizEvaluation,
    IntelligenceFinding,
    ExplanationLevel
)
from agents.security_intelligence.explanation_engine import ExplanationEngine
from agents.security_intelligence.quiz_engine import QuizEngine
from agents.security_intelligence.curriculum_engine import CurriculumEngine
from agents.security_intelligence.knowledge_engine import KnowledgeEngine
from agents.security_intelligence.learning_memory import LearningMemory
from agents.security_intelligence.learning_profile import LearningProfile

log = logging.getLogger("security_intelligence.teacher")


class TeacherAgent:
    """الوكيل التعليمي: تحويل الثغرات والنتائج إلى تجارب تعليمية متكيفة مع مستوى المتدرب"""

    def __init__(
        self,
        explanation_engine: Optional[ExplanationEngine] = None,
        quiz_engine: Optional[QuizEngine] = None,
        curriculum_engine: Optional[CurriculumEngine] = None,
        knowledge_engine: Optional[KnowledgeEngine] = None,
        learning_memory: Optional[LearningMemory] = None,
        learning_profile: Optional[LearningProfile] = None
    ):
        self.kb = knowledge_engine or KnowledgeEngine()
        self.memory = learning_memory or LearningMemory()
        self.profile = learning_profile or LearningProfile()
        self.explanation_engine = explanation_engine or ExplanationEngine(self.kb)
        self.quiz_engine = quiz_engine or QuizEngine(self.kb)
        self.curriculum = curriculum_engine or CurriculumEngine(self.memory)

    def teach_from_finding(self, finding: IntelligenceFinding) -> SecurityLesson:
        """تحويل Finding تم اكتشافه إلى درس تعليمي متكامل متعدد المستويات"""
        explanations = self.explanation_engine.generate_multi_level_explanation(
            topic_or_vuln=finding.vulnerability_type,
            finding=finding
        )
        kb_entry = self.kb.get_vulnerability(finding.vulnerability_type) or {}
        quiz = self.quiz_engine.generate_quiz_for_topic(finding.vulnerability_type)

        lesson = SecurityLesson(
            topic=finding.title,
            vuln_class=finding.vulnerability_type,
            cwe=finding.cwe_id,
            related_finding_id=finding.id,
            explanations=explanations,
            real_world_scenario=f"Observation in target {finding.target}: {finding.attack_path_summary}",
            detection_methodology=kb_entry.get("required_evidence", []),
            remediation_guide=finding.remediation_advice or kb_entry.get("remediation", ""),
            interactive_quiz_id=quiz.id
        )

        self.memory.record_lesson_completed(lesson.id)
        return lesson

    def create_topic_lesson(self, topic: str) -> SecurityLesson:
        """إنشاء درس أمني نظري حول مفهوم معين"""
        explanations = self.explanation_engine.generate_multi_level_explanation(topic_or_vuln=topic)
        kb_entry = self.kb.get_vulnerability(topic) or {}
        quiz = self.quiz_engine.generate_quiz_for_topic(topic)

        lesson = SecurityLesson(
            topic=topic,
            vuln_class=topic,
            cwe=kb_entry.get("cwe"),
            explanations=explanations,
            detection_methodology=kb_entry.get("required_evidence", []),
            remediation_guide=kb_entry.get("remediation", ""),
            interactive_quiz_id=quiz.id
        )
        self.memory.record_lesson_completed(lesson.id)
        return lesson

    def get_quiz_for_topic(self, topic: str) -> QuizQuestion:
        return self.quiz_engine.generate_quiz_for_topic(topic)

    def evaluate_quiz(self, quiz: QuizQuestion, choice_index: int) -> QuizEvaluation:
        eval_result = self.quiz_engine.evaluate_answer(quiz, choice_index)
        
        # Record in Learning Memory
        self.memory.record_quiz_result(
            topic=quiz.topic,
            is_correct=eval_result.is_correct,
            concept_tested=quiz.concept_tested,
            score=eval_result.understanding_score
        )
        
        # Record in Learning Profile for adaptive difficulty
        self.profile.record_evaluation(eval_result, quiz.concept_tested)
        
        return eval_result

    def get_recommended_explanation_level(self, topic: str) -> ExplanationLevel:
        return self.profile.get_optimal_explanation_level(topic)
