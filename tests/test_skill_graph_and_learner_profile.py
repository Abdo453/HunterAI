"""
Unit Tests for SkillGraph and Diagnostic Competence Model
Tests: Hierarchical skill DAG, proficiency tracking, weakness diagnosis, and prerequisite recommendation.
"""
import pytest
from pathlib import Path

from core.learning.skill_graph import SkillGraph, SkillNode


class TestSkillGraphAndLearnerProfile:
    def test_skill_graph_initialization_and_canonical_nodes(self, tmp_path):
        db_file = tmp_path / "test_skills.sqlite3"
        sg = SkillGraph(db_path=db_file)

        skills = sg.get_all_skills()
        assert len(skills) >= 10

        sqli_node = sg.get_skill("sqli_boolean_differential")
        assert sqli_node is not None
        assert sqli_node.category == "sqli"
        assert sqli_node.parent_skill == "sqli_core"

    def test_record_attempt_updates_proficiency(self, tmp_path):
        db_file = tmp_path / "test_skills.sqlite3"
        sg = SkillGraph(db_path=db_file)

        init_prof = sg.get_skill("sqli_blind_inference").proficiency

        # Successful attempt boosts proficiency
        sg.record_attempt("sqli_blind_inference", success=True)
        boosted = sg.get_skill("sqli_blind_inference")
        assert boosted.proficiency > init_prof
        assert boosted.attempts_count == 1
        assert boosted.success_count == 1

        # Failed attempt reduces proficiency and increments failure count
        sg.record_attempt("sqli_blind_inference", success=False)
        reduced = sg.get_skill("sqli_blind_inference")
        assert reduced.proficiency < boosted.proficiency
        assert reduced.consecutive_failures == 1

    def test_diagnose_weakest_skills(self, tmp_path):
        db_file = tmp_path / "test_skills.sqlite3"
        sg = SkillGraph(db_path=db_file)

        weakest = sg.diagnose_weakest_skills(category="sqli", limit=2)
        assert len(weakest) == 2
        # Initial canonical tree has time_statistical (0.45) and blind_inference (0.50) as weakest
        weakest_ids = [w.skill_id for w in weakest]
        assert "sqli_time_statistical" in weakest_ids

    def test_recommend_next_scenario_skill_considers_prerequisites(self, tmp_path):
        db_file = tmp_path / "test_skills.sqlite3"
        sg = SkillGraph(db_path=db_file)

        recommended = sg.recommend_next_scenario_skill(category="sqli")
        assert recommended is not None
        assert recommended.category == "sqli"
