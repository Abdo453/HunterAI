"""
Hybrid RAG Retrieval Engine
Combines Knowledge items (what it knows) and Past Experiences (what it learned)
using keyword/signal matching and cosine semantic similarity to build reasoning context.
"""
import logging
from typing import Dict, List, Any, Optional

from core.learning.knowledge_store import KnowledgeStore, KnowledgeItem
from core.learning.experience_store import ExperienceStore, InvestigationEpisode

log = logging.getLogger("core.learning.retrieval")


class LearningRetrievalEngine:
    """
    محرك استرجاع المعرفة والتجارب (RAG Retrieval Engine):
    يدمج المعرفة الأساسية مع الخبرات السابقة لبناء سياق استدلالي مركز
    """

    def __init__(
        self,
        knowledge_store: Optional[KnowledgeStore] = None,
        experience_store: Optional[ExperienceStore] = None
    ):
        self.kb = knowledge_store or KnowledgeStore()
        self.exp = experience_store or ExperienceStore()

    def retrieve_context(
        self,
        signals: List[str],
        topic: Optional[str] = None,
        limit_knowledge: int = 3,
        limit_lessons: int = 3
    ) -> Dict[str, Any]:
        """
        استرجاع السياق المعرفي والتجريبي المطابق للإشارات المدخلة
        """
        # 1. Retrieve relevant canonical knowledge
        knowledge_items = self.kb.query_by_signals(signals)
        if topic and not knowledge_items:
            knowledge_items = self.kb.get_by_topic(topic)

        selected_kb = knowledge_items[:limit_knowledge]

        # 2. Retrieve past similar experiences and lessons
        search_topic = topic or (selected_kb[0].topic if selected_kb else "general")
        past_episodes = self.exp.find_similar_episodes(topic=search_topic)

        extracted_lessons = []
        for ep in past_episodes[:3]:
            for l in ep.lessons:
                extracted_lessons.append(l)

        selected_lessons = extracted_lessons[:limit_lessons]

        # 3. Format structured RAG context summary
        context_summary = self._format_prompt_context(selected_kb, selected_lessons)

        return {
            "query_signals": signals,
            "topic": search_topic,
            "matched_knowledge_items": [k.to_dict() for k in selected_kb],
            "relevant_past_lessons": selected_lessons,
            "prompt_context": context_summary
        }

    def _format_prompt_context(
        self,
        knowledge_items: List[KnowledgeItem],
        lessons: List[Dict[str, Any]]
    ) -> str:
        lines = ["=== RELEVANT DOMAIN KNOWLEDGE ==="]
        for k in knowledge_items:
            lines.append(f"• Concept/Vuln: {k.name} ({k.topic})")
            lines.append(f"  Signals: {', '.join(k.signals)}")
            lines.append(f"  Verification Strategy: {k.verification_strategy}")
            lines.append(f"  Required Evidence: {', '.join(k.evidence_requirements)}")

        if lessons:
            lines.append("\n=== LESSONS FROM PAST INVESTIGATIONS ===")
            for l in lessons:
                useful = l.get("useful_action")
                waste = l.get("wasteful_action")
                if useful:
                    lines.append(f"  [RECOMMENDED] {useful} -> {l.get('advice')}")
                if waste:
                    lines.append(f"  [AVOID] {waste} -> {l.get('advice')}")

        return "\n".join(lines)
