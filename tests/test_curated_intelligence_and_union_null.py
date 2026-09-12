"""
Unit & Integration Tests for Curated Intelligence Ingestion and UNION NULL Probing
Tests:
- Dynamic discovery & ingestion of PortSwigger, HackerOne, Cypher, TryHackMe, and Bug Bounty intelligence
- Automatic synchronization into KnowledgeStore
- Hybrid RAG retrieval for UNION NULL and Cypher graph signals
- Evaluation of agent reasoning on UNION NULL column count scenarios
"""
import pytest
import httpx

from core.learning.scenario_loader import DynamicScenarioLoader
from core.learning.knowledge_store import KnowledgeStore
from core.learning.retrieval import LearningRetrievalEngine
from core.learning.sqli_evaluator import SQLiGraduationEvaluator
from ui.web.app import app


class TestCuratedIntelligenceAndUnionNull:
    def test_sync_ingests_all_curated_intelligence_sources(self):
        loader = DynamicScenarioLoader()
        report = loader.sync_all()

        # Verify intelligence indexed
        assert report["total_indexed_intelligence"] >= 6
        assert "intel_portswigger_union_null" in report["intelligence_list"]
        assert "intel_hackerone_top_sqli" in report["intelligence_list"]
        assert "intel_cypher_graph_injection" in report["intelligence_list"]
        assert "intel_tryhackme_fundamentals" in report["intelligence_list"]
        assert "intel_secbyte_interview_architecture" in report["intelligence_list"]
        assert "intel_bugbounty_attack_surface" in report["intelligence_list"]

        # Verify items stored in KnowledgeStore
        item_union = loader.kb.get_item("intel_portswigger_union_null")
        assert item_union is not None
        assert "UNION SELECT NULL" in item_union.verification_strategy
        assert item_union.topic == "sqli"

        item_cypher = loader.kb.get_item("intel_cypher_graph_injection")
        assert item_cypher is not None
        assert "Neo4j" in item_cypher.name or "Cypher" in item_cypher.name

    def test_rag_retrieves_union_null_and_cypher_guidance(self):
        rag = LearningRetrievalEngine()

        # Query RAG with PortSwigger UNION signals
        res_union = rag.retrieve_context(
            signals=["union_based_surface", "column_count_probe"],
            topic="sqli"
        )
        assert len(res_union["matched_knowledge_items"]) >= 1
        union_texts = [k["verification_strategy"] for k in res_union["matched_knowledge_items"]]
        assert any("UNION SELECT NULL" in t for t in union_texts)

        # Query RAG with Cypher graph signals
        res_cypher = rag.retrieve_context(
            signals=["neo4j_backend", "cypher_syntax_error"],
            topic="sqli"
        )
        assert len(res_cypher["matched_knowledge_items"]) >= 1
        cypher_names = [k["name"] for k in res_cypher["matched_knowledge_items"]]
        assert any("Cypher" in n or "Neo4j" in n for n in cypher_names)


    def test_evaluator_validates_union_null_scenario(self):
        evaluator = SQLiGraduationEvaluator()

        # Agent accurately deduces 2 columns via NULL probing
        agent_reasoning = {
            "declared_vulnerable": True,
            "hypothesis": "union_based_null_technique SQLi",
            "evidence_items": ["EVID-UNION-NULL-2-COLUMNS-REFLECTED"]
        }

        result = evaluator.evaluate_scenario_attempt("sqli_lvl5_union_null_probing", agent_reasoning)
        assert result["passed"] is True
        assert result["false_positive"] is False
        assert result["evidence_sufficient"] is True

    @pytest.mark.asyncio
    async def test_rest_api_sync_reflects_new_curated_intelligence(self):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            res_sync = await client.get("/api/learning/sync")
            assert res_sync.status_code == 200
            data = res_sync.json()
            report = data["sync_report"]
            assert report["total_indexed_intelligence"] >= 6
            assert "intel_portswigger_union_null" in report["intelligence_list"]
