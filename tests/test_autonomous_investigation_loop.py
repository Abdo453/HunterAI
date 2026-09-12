"""
Comprehensive Unit & Integration Tests for Autonomous Investigation Loop
Tests:
- End-to-end investigation cycle:
  (Browser Recon -> Normalize -> Semantic Interpret -> Hypothesize -> Repeater -> Diff -> Belief Update -> Attack Graph -> Experience DB -> Skill Graph)
- REST API /api/orchestration/run_investigation
"""
import pytest
import httpx
from pathlib import Path

from core.orchestration.investigation_loop import AutonomousInvestigationEngine, InvestigationReport
from core.learning.skill_graph import SkillGraph
from core.learning.experience_store import ExperienceStore
from ui.web.app import app


class TestAutonomousInvestigationLoop:
    @pytest.mark.asyncio
    async def test_autonomous_investigation_cycle_end_to_end(self, tmp_path):
        db_skills = tmp_path / "skills.sqlite3"
        db_exp = tmp_path / "exp.sqlite3"

        skill_graph = SkillGraph(db_path=db_skills)
        exp_store = ExperienceStore(db_path=db_exp)

        initial_prof = skill_graph.get_skill("sqli_boolean_differential").proficiency

        engine = AutonomousInvestigationEngine(
            skill_graph=skill_graph,
            experience_store=exp_store
        )

        report = await engine.run_investigation_cycle(
            target_url="https://lab.internal/catalog/products",
            hypothesis_name="SQL_INJECTION",
            skill_to_train="sqli_boolean_differential"
        )

        assert isinstance(report, InvestigationReport)
        assert report.status == "VERIFIED_AND_LEARNED"
        assert report.final_confidence > report.initial_confidence
        assert report.differential_score >= 0.70
        assert report.evidence_id is not None
        assert report.new_skill_proficiency > initial_prof

        # Check Attack Graph was populated
        assert len(engine.attack_graph.nodes) >= 1

        # Check Experience DB recorded the episode
        episodes = exp_store.get_recent_episodes(limit=5)
        assert len(episodes) >= 1
        assert episodes[0].episode_id == report.investigation_id


        # Check terminal output
        summary = report.format_terminal_summary()
        assert "HunterAI Autonomous Investigation Report" in summary
        assert "VERIFIED_AND_LEARNED" in summary

    @pytest.mark.asyncio
    async def test_rest_api_run_investigation_endpoint(self):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            payload = {
                "target_url": "https://teststore.lab.local/items",
                "hypothesis": "SQL_INJECTION",
                "skill": "sqli_boolean_differential"
            }
            res = await client.post("/api/orchestration/run_investigation", json=payload)
            assert res.status_code == 200
            data = res.json()
            assert "report" in data
            assert data["report"]["status"] == "VERIFIED_AND_LEARNED"
            assert "terminal_summary" in data
