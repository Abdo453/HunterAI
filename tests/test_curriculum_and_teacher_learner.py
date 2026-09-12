"""
Unit Tests for SecurityCurriculum, TeacherAgent, and LearnerAgent
Tests: 10 curriculum levels, challenge presentation, reasoning trace evaluation, and feedback assimilation.
"""
import pytest

from core.learning.curriculum import SecurityCurriculum
from core.learning.teacher_agent import TeacherAgent
from core.learning.learner_agent import LearnerAgent
from core.learning.knowledge_store import KnowledgeStore
from core.learning.experience_store import ExperienceStore


class TestCurriculumAndTeacherLearner:
    def test_curriculum_defines_ten_progressive_levels(self):
        curriculum = SecurityCurriculum()
        levels = curriculum.get_all_levels()
        assert len(levels) == 10
        assert levels[0].level == 0
        assert levels[0].title == "HTTP Fundamentals"
        assert levels[3].title == "Object-Level Authorization (BOLA)"
        assert levels[9].title == "Multi-Step Kill Chains"

    def test_teacher_agent_presents_challenge(self, tmp_path):
        kb_file = tmp_path / "t_kb.sqlite3"
        kb = KnowledgeStore(db_path=kb_file)
        teacher = TeacherAgent(knowledge_store=kb)

        challenge = teacher.present_challenge(3)  # Level 3 BOLA
        assert challenge["level"] == 3
        assert challenge["title"] == "Object-Level Authorization (BOLA)"
        assert "quiz_question" in challenge
        assert len(challenge["relevant_knowledge"]) > 0

    def test_teacher_agent_evaluates_reasoning_trace(self, tmp_path):
        kb_file = tmp_path / "t_kb.sqlite3"
        kb = KnowledgeStore(db_path=kb_file)
        teacher = TeacherAgent(knowledge_store=kb)

        # Flawed reasoning: Random scanning without baseline, no evidence
        bad_eval = teacher.evaluate_reasoning_trace(
            level_num=3,
            actions_taken=["nmap", "whois"],
            hypotheses={"BOLA": 0.2},
            evidence_collected=[]
        )
        assert bad_eval.passed is False
        assert bad_eval.score < 0.50
        assert len(bad_eval.misconceptions_identified) >= 2

        # Sound reasoning: Hypothesis formulated, baseline/differential probe executed, evidence collected
        good_eval = teacher.evaluate_reasoning_trace(
            level_num=3,
            actions_taken=["unauthenticated_baseline", "cross_tenant_probe"],
            hypotheses={"BOLA": 0.95},
            evidence_collected=["EVID-DIFF-001"]
        )
        assert good_eval.passed is True
        assert good_eval.score >= 0.80
        assert good_eval.next_level_unlocked is True

    def test_learner_agent_tackles_challenge_and_saves_episode(self, tmp_path):
        exp_file = tmp_path / "l_exp.sqlite3"
        exp = ExperienceStore(db_path=exp_file)
        learner = LearnerAgent(experience_store=exp)

        challenge = {
            "level": 3,
            "title": "Object-Level Authorization (BOLA)",
            "lab_scenario": "BOLA_MultiTenant_Enterprise"
        }

        # Mock runner callback simulating autonomous reasoning run
        def mock_scenario_runner(rag_context):
            return {
                "hypotheses": [{"name": "BOLA", "prob": 0.95}],
                "hypotheses_dict": {"BOLA": 0.95},
                "actions_taken": ["unauthenticated_baseline", "cross_tenant_probe"],
                "observations": [{"status": 200}],
                "evidence": ["EVID-BOLA-PROOF"],
                "goal_achieved": True,
                "decision_regret": 0.02,
                "investigation_log": [
                    {"action_taken": "cross_tenant_probe", "information_gain_bits": 0.5, "goal_satisfied": True}
                ]
            }

        result = learner.tackle_challenge(challenge, mock_scenario_runner)
        assert result["goal_achieved"] is True
        assert len(result["lessons_learned"]) >= 1

        # Verify episode was saved in ExperienceStore
        recent = exp.get_recent_episodes()
        assert len(recent) == 1
        assert recent[0].final_outcome == "SUCCESS_CONFIRMED"
