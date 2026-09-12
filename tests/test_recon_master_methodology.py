"""
Unit & Integration Tests for Reconnaissance & Attack Surface Master Methodology
Tests:
- Ingestion of complete recon pipeline (Subdomain, Alive Host, Crawling, JS Secrets, Content, Parameters, VHosts)
- Dynamic synchronization into KnowledgeStore
- SkillGraph integration with recon sub-tree
- Hybrid RAG retrieval for recon signals
- REST API /api/learning/sync reflection
"""
import pytest
import httpx

from core.learning.scenario_loader import DynamicScenarioLoader
from core.learning.skill_graph import SkillGraph
from core.learning.retrieval import LearningRetrievalEngine
from ui.web.app import app


class TestReconMasterMethodology:
    def test_sync_indexes_recon_methodologies_and_scenarios(self):
        loader = DynamicScenarioLoader()
        report = loader.sync_all()

        # Check recon methodologies indexed
        assert report["total_indexed_intelligence"] >= 18
        assert "recon_meth_001" in report["intelligence_list"]
        assert "recon_meth_002" in report["intelligence_list"]
        assert "recon_meth_003" in report["intelligence_list"]
        assert "recon_meth_004" in report["intelligence_list"]
        assert "recon_meth_005" in report["intelligence_list"]
        assert "recon_meth_006" in report["intelligence_list"]
        assert "recon_meth_007" in report["intelligence_list"]
        assert "recon_meth_008" in report["intelligence_list"]
        assert "recon_meth_009" in report["intelligence_list"]
        assert "recon_meth_010" in report["intelligence_list"]
        assert "recon_meth_011" in report["intelligence_list"]
        assert "recon_meth_012" in report["intelligence_list"]

        # Check recon scenarios indexed
        assert "recon_lvl1_subdomain_and_alive_clustering" in report["scenarios_list"]
        assert "recon_lvl2_sensitive_artifact_exposure" in report["scenarios_list"]

        # Check specific item content
        item_sub = loader.kb.get_item("recon_meth_001")
        assert item_sub is not None
        assert "Subdomain" in item_sub.name
        assert "deduplicate" in item_sub.verification_strategy.lower()

        item_ghdb = loader.kb.get_item("recon_meth_008")
        assert item_ghdb is not None
        assert "Google Hacking Database" in item_ghdb.name

        item_gh = loader.kb.get_item("recon_meth_009")
        assert item_gh is not None
        assert "GitHub Dorking" in item_gh.name

        item_to = loader.kb.get_item("recon_meth_010")
        assert item_to is not None
        assert "Subdomain Takeover" in item_to.name

        item_403 = loader.kb.get_item("recon_meth_011")
        assert item_403 is not None
        assert "403" in item_403.name

        item_cms = loader.kb.get_item("recon_meth_012")
        assert item_cms is not None
        assert "WordPress" in item_cms.name


    def test_skill_graph_tracks_recon_competencies(self, tmp_path):
        db_path = tmp_path / "skills_recon.sqlite3"
        sg = SkillGraph(db_path=db_path)

        recon_node = sg.get_skill("recon_core")
        assert recon_node is not None
        assert recon_node.category == "recon"

        sub_node = sg.get_skill("recon_subdomain_discovery")
        assert sub_node is not None
        assert sub_node.parent_skill == "recon_core"

        # Record attempt
        init_prof = sub_node.proficiency
        sg.record_attempt("recon_subdomain_discovery", success=True)
        updated_prof = sg.get_skill("recon_subdomain_discovery").proficiency
        assert updated_prof > init_prof

    def test_rag_retrieves_recon_methodology(self):
        rag = LearningRetrievalEngine()

        # Query RAG for alive host verification signals
        res_alive = rag.retrieve_context(
            signals=["alive_hosts", "http_status_codes"],
            topic="recon"
        )
        assert len(res_alive["matched_knowledge_items"]) >= 1
        names = [k["name"] for k in res_alive["matched_knowledge_items"]]
        assert any("Alive Host" in n for n in names)

        # Query RAG for sensitive backup file signals
        res_backup = rag.retrieve_context(
            signals=["sensitive_file_extension", "backup_artifacts"],
            topic="recon"
        )
        assert len(res_backup["matched_knowledge_items"]) >= 1
        strategies = [k["verification_strategy"] for k in res_backup["matched_knowledge_items"]]
        assert any("soft-404" in s for s in strategies)

    @pytest.mark.asyncio
    async def test_rest_api_sync_returns_recon_intelligence(self):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            res_sync = await client.get("/api/learning/sync")
            assert res_sync.status_code == 200
            data = res_sync.json()
            report = data["sync_report"]
            assert report["total_indexed_intelligence"] >= 13
            assert "recon_meth_001" in report["intelligence_list"]
            assert "recon_lvl2_sensitive_artifact_exposure" in report["scenarios_list"]
