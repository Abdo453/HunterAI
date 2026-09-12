"""
Pedagogical Teacher Agent
Presents structured security scenarios from the curriculum, evaluates agent reasoning traces,
identifies misconceptions, and provides Socratic feedback.
"""
import logging
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field

from core.learning.curriculum import SecurityCurriculum, CurriculumLevel
from core.learning.knowledge_store import KnowledgeStore

log = logging.getLogger("core.learning.teacher")


class TeacherEvaluation(BaseModel):
    """تقييم المعلم لمسار استدلال المتدرب / الـ Agent"""
    level: int
    score: float                         # 0.0 to 1.0
    passed: bool
    feedback: str
    misconceptions_identified: List[str] = Field(default_factory=list)
    recommended_action: str = ""
    next_level_unlocked: bool = False


class TeacherAgent:
    """
    الوكيل المعلم (Teacher Agent):
    يطرح سيناريوهات التعلم، يراقب استدلال الـ Agent، ويصحح المسار بأسلوب سقراطي رصين
    """

    def __init__(
        self,
        curriculum: Optional[SecurityCurriculum] = None,
        knowledge_store: Optional[KnowledgeStore] = None
    ):
        self.curriculum = curriculum or SecurityCurriculum()
        self.kb = knowledge_store or KnowledgeStore()

    def present_challenge(self, level_num: int) -> Dict[str, Any]:
        """طرح التحدي أو السيناريو المعرفي الخاص بالمستوى"""
        lvl = self.curriculum.get_level(level_num)
        if not lvl:
            return {"error": f"Level {level_num} does not exist"}

        knowledge_items = [self.kb.get_item(k_id) for k_id in lvl.knowledge_ids]
        valid_items = [k.to_dict() for k in knowledge_items if k]

        return {
            "level": lvl.level,
            "title": lvl.title,
            "description": lvl.description,
            "objectives": lvl.objectives,
            "lab_scenario": lvl.lab_scenario,
            "relevant_knowledge": valid_items,
            "quiz_question": lvl.sample_question
        }

    def evaluate_reasoning_trace(
        self,
        level_num: int,
        actions_taken: List[str],
        hypotheses: Dict[str, float],
        evidence_collected: List[str]
    ) -> TeacherEvaluation:
        """
        تقييم مسار تفكير الـ Agent:
        هل أخذ خط الأساس (Baseline)؟ هل اختار فحصاً ذا عائد معلوماتي؟ هل اعتمد على دليل؟
        """
        lvl = self.curriculum.get_level(level_num)
        score = 0.0
        misconceptions = []
        feedback_notes = []

        # 1. Check hypothesis formation
        if hypotheses and max(hypotheses.values()) >= 0.50:
            score += 0.35
            feedback_notes.append("Good initial hypothesis formulation.")
        else:
            misconceptions.append("Weak or missing hypothesis prioritization.")

        # 2. Check baseline / informative testing
        has_baseline_or_probe = any(
            "baseline" in a.lower() or "probe" in a.lower() or "diff" in a.lower()
            for a in actions_taken
        )
        if has_baseline_or_probe:
            score += 0.35
            feedback_notes.append("Appropriate differential or baseline test executed.")
        else:
            misconceptions.append("Skipped baseline measurement or jumped to random scanning.")

        # 3. Check evidence backing
        if evidence_collected:
            score += 0.30
            feedback_notes.append("Conclusion supported by concrete empirical evidence.")
        else:
            misconceptions.append("Decision made without forensic evidence backing.")

        score = round(min(1.0, max(0.0, score)), 2)
        passed = score >= 0.70

        feedback = " | ".join(feedback_notes) if feedback_notes else "Reasoning requires significant improvement."
        if misconceptions:
            feedback += f" Areas for correction: {', '.join(misconceptions)}"

        return TeacherEvaluation(
            level=level_num,
            score=score,
            passed=passed,
            feedback=feedback,
            misconceptions_identified=misconceptions,
            recommended_action="Proceed to next curriculum level" if passed else "Review verification strategy and re-attempt",
            next_level_unlocked=passed
        )
