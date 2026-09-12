"""
Adaptive Learner Agent
Consumes knowledge from KnowledgeStore, recalls past lessons from ExperienceStore via RAG,
engages in curriculum scenarios, and internalizes teacher feedback.
"""
import logging
from typing import Dict, List, Any, Optional

from core.learning.retrieval import LearningRetrievalEngine
from core.learning.experience_store import ExperienceStore, InvestigationEpisode
from core.learning.lesson_extractor import LessonExtractor
from core.reasoning.reasoning_loop import AutonomousReasoningLoop
from core.reasoning.belief_state import BeliefState
from core.reasoning.action_model import ActionDescriptor, ActionKind

log = logging.getLogger("core.learning.learner")


class LearnerAgent:
    """
    الوكيل المتدرب (Learner Agent):
    يحل التحديات مستعيناً بالـ RAG وذاكرة الخبرات، ويستفيد من ملاحظات المعلم
    """

    def __init__(
        self,
        retrieval_engine: Optional[LearningRetrievalEngine] = None,
        experience_store: Optional[ExperienceStore] = None
    ):
        self.retrieval = retrieval_engine or LearningRetrievalEngine()
        self.exp = experience_store or ExperienceStore()
        self.current_level = 0

    def tackle_challenge(
        self,
        challenge: Dict[str, Any],
        scenario_runner_callback
    ) -> Dict[str, Any]:
        """
        خوض سيناريو تدريبي:
        1. استرجاع المعرفة السابقة والتجارب المشابهة عبر الـ RAG
        2. تشغيل حلقة الاستدلال المعرفي
        3. استخراج الدروس وحفظ الحلقة في قاعدة التجارب
        """
        topic = challenge.get("title", "general")
        signals = [topic, challenge.get("lab_scenario", "lab")]

        # 1. RAG Context Recall
        rag_context = self.retrieval.retrieve_context(signals=signals, topic=topic)

        # 2. Run scenario via provided callback
        episode_result = scenario_runner_callback(rag_context)

        # 3. Extract lessons from execution
        investigation_log = episode_result.get("investigation_log", [])
        lessons = LessonExtractor.extract_from_investigation(
            investigation_log=investigation_log,
            topic=topic,
            signals=signals
        )

        # 4. Save episode to ExperienceStore
        episode = InvestigationEpisode(
            episode_id=f"EP-{challenge.get('level', 0)}-{len(self.exp.get_recent_episodes(100)) + 1}",
            target=challenge.get("lab_scenario", "lab.local"),
            topic=topic,
            initial_state={"level": challenge.get("level", 0)},
            hypotheses_evaluated=episode_result.get("hypotheses", []),
            actions_taken=episode_result.get("actions_taken", []),
            observations_recorded=episode_result.get("observations", []),
            evidence_collected=episode_result.get("evidence", []),
            final_outcome="SUCCESS_CONFIRMED" if episode_result.get("goal_achieved") else "INCONCLUSIVE",
            decision_regret_score=episode_result.get("decision_regret", 0.0),
            lessons=[l.to_dict() for l in lessons]
        )
        self.exp.save_episode(episode)

        return {
            "level": challenge.get("level", 0),
            "episode_id": episode.episode_id,
            "actions_taken": episode.actions_taken,
            "hypotheses": episode_result.get("hypotheses_dict", {}),
            "evidence_collected": episode.evidence_collected,
            "lessons_learned": [l.to_dict() for l in lessons],
            "goal_achieved": episode_result.get("goal_achieved", False)
        }
