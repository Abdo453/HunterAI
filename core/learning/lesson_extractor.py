"""
Automated Lesson Extractor
Analyzes completed investigation traces from AutonomousReasoningLoop to extract
actionable lessons: useful actions (high EIG), wasteful actions (zero EIG),
and decisive evidence patterns.
"""
import uuid
import logging
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field

from core.learning.experience_store import InvestigationEpisode

log = logging.getLogger("core.learning.lesson_extractor")


class LearnedLesson(BaseModel):
    """درس مستفاد من تجربة استقصائية"""
    lesson_id: str = Field(default_factory=lambda: f"LSN-{uuid.uuid4().hex[:8]}")
    topic: str
    lesson_type: str  # DECISION_EFFICIENCY, REDUNDANT_ACTION_WARNING, DISAMBIGUATION_STRATEGY, EVIDENCE_SUFFICIENCY
    context_signals: List[str] = Field(default_factory=list)
    useful_action: Optional[str] = None
    wasteful_action: Optional[str] = None
    outcome_impact: str = ""
    confidence: float = 0.90
    advice: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class LessonExtractor:
    """
    مستخلص الدروس المستفادة:
    يحلل مسار التحقيق ويستخرج الدروس الإيجابية والتحذيرات السلبية
    """

    @staticmethod
    def extract_from_investigation(
        investigation_log: List[Dict[str, Any]],
        topic: str = "general",
        signals: Optional[List[str]] = None
    ) -> List[LearnedLesson]:
        lessons: List[LearnedLesson] = []
        observed_signals = signals or [topic]

        for step in investigation_log:
            action_name = step.get("action_taken", "")
            info_gain = step.get("information_gain_bits", 0.0)
            goal_satisfied = step.get("goal_satisfied", False)
            observed_outcome = step.get("observed_outcome", "")

            # 1. High Information Yield Action
            if info_gain >= 0.20:
                lessons.append(LearnedLesson(
                    topic=topic,
                    lesson_type="DISAMBIGUATION_STRATEGY",
                    context_signals=observed_signals,
                    useful_action=action_name,
                    outcome_impact=f"Reduced uncertainty by {info_gain:.3f} bits with outcome '{observed_outcome}'",
                    confidence=0.92,
                    advice=f"When encountering {topic} signals, prior action '{action_name}' provides high epistemic yield."
                ))

            # 2. Redundant / Zero Information Action
            elif info_gain <= 0.0 and not goal_satisfied and step.get("action_kind") != "BASELINE":
                lessons.append(LearnedLesson(
                    topic=topic,
                    lesson_type="REDUNDANT_ACTION_WARNING",
                    context_signals=observed_signals,
                    wasteful_action=action_name,
                    outcome_impact="0 bits gained, no goal contribution",
                    confidence=0.85,
                    advice=f"Avoid repetitive or redundant '{action_name}' when investigating {topic} unless needed for baseline."
                ))

            # 3. Decisive Evidence Gathering
            if goal_satisfied:
                lessons.append(LearnedLesson(
                    topic=topic,
                    lesson_type="EVIDENCE_SUFFICIENCY",
                    context_signals=observed_signals,
                    useful_action=action_name,
                    outcome_impact="Confirmed finding and fulfilled investigation goal",
                    confidence=0.98,
                    advice=f"Differential proof via '{action_name}' concluded {topic} investigation conclusively."
                ))

        return lessons
