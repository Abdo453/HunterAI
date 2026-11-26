"""
Hybrid RAG Retrieval Engine
Combines Knowledge items (what it knows) and Past Experiences (what it learned)
using keyword/signal matching and cosine semantic similarity to build reasoning context.
"""
import logging
from typing import Dict, List, Any, Optional

from core.ai_bridge.prompt_injection_firewall import PromptInjectionFirewall
from core.learning.knowledge_store import CANONICAL_KNOWLEDGE, KnowledgeStore, KnowledgeItem
from core.learning.experience_store import ExperienceStore, InvestigationEpisode

log = logging.getLogger("core.learning.retrieval")

_CANONICAL_IDS = {item.id for item in CANONICAL_KNOWLEDGE}


class LearningRetrievalEngine:
    """
    محرك استرجاع المعرفة والتجارب (RAG Retrieval Engine):
    يدمج المعرفة الأساسية مع الخبرات السابقة لبناء سياق استدلالي مركز
    مع عزل الإدخالات الخارجية عبر PromptInjectionFirewall ووسم مستوى الثقة (trust_tier).
    """

    def __init__(
        self,
        knowledge_store: Optional[KnowledgeStore] = None,
        experience_store: Optional[ExperienceStore] = None
    ):
        self.kb = knowledge_store or KnowledgeStore()
        self.exp = experience_store or ExperienceStore()

    @staticmethod
    def _trust_tier_for_item(item: KnowledgeItem) -> str:
        if item.id in _CANONICAL_IDS:
            return "canonical_internal"
        return "untrusted_external"

    def retrieve_context(
        self,
        signals: List[str],
        topic: Optional[str] = None,
        limit_knowledge: int = 3,
        limit_lessons: int = 3
    ) -> Dict[str, Any]:
        """
        استرجاع السياق المعرفي والتجريبي المطابق للإشارات المدخلة مع وسم trust_tier
        """
        # 1. Retrieve relevant canonical & learned knowledge
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
                tagged = dict(l)
                tagged.setdefault("trust_tier", "untrusted_external")
                extracted_lessons.append(tagged)

        selected_lessons = extracted_lessons[:limit_lessons]

        # 3. Format structured RAG context summary with PromptInjectionFirewall isolation
        context_summary = self._format_prompt_context(selected_kb, selected_lessons)

        matched_dicts = []
        for k in selected_kb:
            d = k.to_dict()
            d["trust_tier"] = self._trust_tier_for_item(k)
            matched_dicts.append(d)

        return {
            "query_signals": signals,
            "topic": search_topic,
            "matched_knowledge_items": matched_dicts,
            "relevant_past_lessons": selected_lessons,
            "prompt_context": context_summary,
        }

    def _format_prompt_context(
        self,
        knowledge_items: List[KnowledgeItem],
        lessons: List[Dict[str, Any]]
    ) -> str:
        lines = ["=== RELEVANT DOMAIN KNOWLEDGE ==="]
        for k in knowledge_items:
            tier = self._trust_tier_for_item(k)
            item_block = (
                f"• [TRUST:{tier}] Concept/Vuln: {k.name} ({k.topic})\n"
                f"  Signals: {', '.join(k.signals)}\n"
                f"  Verification Strategy: {k.verification_strategy}\n"
                f"  Required Evidence: {', '.join(k.evidence_requirements)}"
            )
            if tier == "canonical_internal":
                lines.append(item_block)
            else:
                _, isolated, _ = PromptInjectionFirewall.inspect(
                    item_block,
                    source_label=f"rag_knowledge:{k.id}",
                    trust_tier=tier,
                )
                lines.append(isolated)

        if lessons:
            lines.append("\n=== LESSONS FROM PAST INVESTIGATIONS ===")
            for idx, l in enumerate(lessons):
                tier = str(l.get("trust_tier", "untrusted_external"))
                lesson_lines = []
                useful = l.get("useful_action")
                waste = l.get("wasteful_action")
                if useful:
                    lesson_lines.append(f"[TRUST:{tier}] [RECOMMENDED] {useful} -> {l.get('advice')}")
                if waste:
                    lesson_lines.append(f"[TRUST:{tier}] [AVOID] {waste} -> {l.get('advice')}")
                if lesson_lines:
                    _, isolated_lesson, _ = PromptInjectionFirewall.inspect(
                        "\n".join(lesson_lines),
                        source_label=f"rag_lesson:{idx}",
                        trust_tier=tier,
                    )
                    lines.append(isolated_lesson)

        return "\n".join(lines)
