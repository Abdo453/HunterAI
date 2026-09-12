"""
Unit Tests for LearningRetrievalEngine (Hybrid RAG)
Tests: Context retrieval combining structured knowledge items and past lessons.
"""
import pytest

from core.learning.knowledge_store import KnowledgeStore
from core.learning.experience_store import ExperienceStore, InvestigationEpisode
from core.learning.retrieval import LearningRetrievalEngine


class TestLearningRetrievalRAG:
    def test_rag_retrieval_combines_knowledge_and_past_lessons(self, tmp_path):
        kb_file = tmp_path / "rag_kb.sqlite3"
        exp_file = tmp_path / "rag_exp.sqlite3"

        kb = KnowledgeStore(db_path=kb_file)
        exp = ExperienceStore(db_path=exp_file)

        # Seed an experience episode with a lesson
        episode = InvestigationEpisode(
            episode_id="EP-HIST-01",
            target="target.local",
            topic="authorization",
            final_outcome="SUCCESS_CONFIRMED",
            lessons=[
                {
                    "lesson_type": "DISAMBIGUATION_STRATEGY",
                    "useful_action": "cross_tenant_probe",
                    "advice": "Use differential response analysis across users"
                },
                {
                    "lesson_type": "REDUNDANT_ACTION_WARNING",
                    "wasteful_action": "nmap",
                    "advice": "Do not run port scans when evaluating endpoint authorization"
                }
            ]
        )
        exp.save_episode(episode)

        rag = LearningRetrievalEngine(knowledge_store=kb, experience_store=exp)

        # Query RAG with observed signals from Burp
        signals = ["numeric_id", "multi_tenant"]
        context = rag.retrieve_context(signals=signals, topic="authorization")

        assert len(context["matched_knowledge_items"]) > 0
        top_k = context["matched_knowledge_items"][0]
        assert top_k["id"] == "authz_001"

        assert len(context["relevant_past_lessons"]) >= 2
        prompt_txt = context["prompt_context"]
        assert "RELEVANT DOMAIN KNOWLEDGE" in prompt_txt
        assert "Object-Level Authorization Failure (BOLA / IDOR)" in prompt_txt
        assert "[RECOMMENDED] cross_tenant_probe" in prompt_txt
        assert "[AVOID] nmap" in prompt_txt
