"""
Unit Tests for ExperienceStore and LessonExtractor
Tests: Episode recording, lesson extraction from reasoning traces, and episodic recall.
"""
import pytest
from pathlib import Path

from core.learning.experience_store import ExperienceStore, InvestigationEpisode
from core.learning.lesson_extractor import LessonExtractor, LearnedLesson


class TestExperienceStoreAndLessons:
    def test_save_and_query_investigation_episodes(self, tmp_path):
        db_file = tmp_path / "test_experiences.sqlite3"
        store = ExperienceStore(db_path=db_file)

        ep = InvestigationEpisode(
            episode_id="EP-001",
            target="https://target.corp.local/api/v2/orders/10",
            topic="authorization",
            initial_state={"endpoint": "/orders/10"},
            hypotheses_evaluated=[{"name": "BOLA", "prob": 0.92}],
            actions_taken=["unauthenticated_baseline", "cross_tenant_probe"],
            observations_recorded=[{"status": 401}, {"status": 200}],
            evidence_collected=["EVID-DIFF-01"],
            final_outcome="SUCCESS_CONFIRMED",
            decision_regret_score=0.05,
            lessons=[{"type": "EVIDENCE_SUFFICIENCY", "useful_action": "cross_tenant_probe"}]
        )
        store.save_episode(ep)

        retrieved = store.get_episode("EP-001")
        assert retrieved is not None
        assert retrieved.topic == "authorization"
        assert retrieved.final_outcome == "SUCCESS_CONFIRMED"
        assert len(retrieved.actions_taken) == 2

        similar = store.find_similar_episodes(topic="authorization")
        assert len(similar) == 1
        assert similar[0].episode_id == "EP-001"

    def test_lesson_extractor_analyzes_investigation_trace(self):
        sample_log = [
            {
                "action_taken": "cross_tenant_probe",
                "action_kind": "DISAMBIGUATION",
                "information_gain_bits": 0.45,
                "observed_outcome": "200_cross_tenant_data",
                "goal_satisfied": False
            },
            {
                "action_taken": "nmap",
                "action_kind": "DISCOVERY",
                "information_gain_bits": 0.0,
                "observed_outcome": "generic_200",
                "goal_satisfied": False
            },
            {
                "action_taken": "generate_proof_report",
                "action_kind": "VERIFICATION",
                "information_gain_bits": 0.0,
                "observed_outcome": "report_ready",
                "goal_satisfied": True
            }
        ]

        lessons = LessonExtractor.extract_from_investigation(
            investigation_log=sample_log,
            topic="authorization",
            signals=["numeric_id", "cross_tenant"]
        )

        assert len(lessons) >= 3

        # 1. High EIG action recognized
        useful = next(l for l in lessons if l.lesson_type == "DISAMBIGUATION_STRATEGY")
        assert useful.useful_action == "cross_tenant_probe"
        assert useful.confidence >= 0.90

        # 2. Redundant action flagged with warning
        wasteful = next(l for l in lessons if l.lesson_type == "REDUNDANT_ACTION_WARNING")
        assert wasteful.wasteful_action == "nmap"

        # 3. Decisive evidence step recognized
        decisive = next(l for l in lessons if l.lesson_type == "EVIDENCE_SUFFICIENCY")
        assert decisive.useful_action == "generate_proof_report"
