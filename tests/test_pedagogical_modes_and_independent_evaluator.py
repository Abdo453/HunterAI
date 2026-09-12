"""
Unit & Integration Tests for Pedagogical Modes, Independent Evaluator, and Web Endpoints
Tests: Training/Practice/Exam modes, Independent verification, 0% FP enforcement, and REST APIs.
"""
import pytest
import httpx

from core.learning.pedagogical_modes import PedagogicalMode, PedagogicalSessionManager
from core.learning.independent_evaluator import IndependentEvaluator
from ui.web.app import app


class TestPedagogicalModesAndIndependentEvaluator:
    def test_pedagogical_modes_hint_policies(self):
        # 1. Training mode: unlimited hints
        train_session = PedagogicalSessionManager.create_session("sess_train", PedagogicalMode.TRAINING)
        h1 = PedagogicalSessionManager.request_hint(train_session, "sqli_boolean_differential")
        assert h1["hint_granted"] is True

        # 2. Practice mode: max 2 hints
        prac_session = PedagogicalSessionManager.create_session("sess_prac", PedagogicalMode.PRACTICE)
        p1 = PedagogicalSessionManager.request_hint(prac_session, "sqli_boolean_differential")
        assert p1["hint_granted"] is True
        p2 = PedagogicalSessionManager.request_hint(prac_session, "sqli_boolean_differential")
        assert p2["hint_granted"] is True
        # 3rd hint rejected
        p3 = PedagogicalSessionManager.request_hint(prac_session, "sqli_boolean_differential")
        assert p3["hint_granted"] is False

        # 3. Exam mode: strictly 0 hints
        exam_session = PedagogicalSessionManager.create_session("sess_exam", PedagogicalMode.EXAM)
        e1 = PedagogicalSessionManager.request_hint(exam_session, "sqli_boolean_differential")
        assert e1["hint_granted"] is False
        assert "strictly prohibited" in e1["reason"]

    def test_independent_evaluator_rejects_false_positive(self):
        evaluator = IndependentEvaluator()

        safe_scenario = {
            "scenario_id": "test_safe_scenario",
            "hidden_truth": {
                "is_vulnerable": False,
                "vulnerability": "NONE"
            }
        }

        # Agent falsely claims vulnerability on safe scenario
        false_positive_claim = {
            "declared_vulnerable": True,
            "hypothesis": "SQL_INJECTION",
            "evidence_items": ["echoed_param"]
        }

        res = evaluator.evaluate_solution(safe_scenario, false_positive_claim)
        assert res.passed is False
        assert res.false_positive is True
        assert res.score == 0.0

    def test_independent_evaluator_approves_sound_proof(self):
        evaluator = IndependentEvaluator()

        vulnerable_scenario = {
            "scenario_id": "test_vuln_scenario",
            "optimal_steps": 2,
            "hidden_truth": {
                "is_vulnerable": True,
                "vulnerability": "SQL_INJECTION",
                "variant": "sqli_boolean_differential"
            }
        }

        sound_submission = {
            "declared_vulnerable": True,
            "hypothesis": "sqli_boolean_differential",
            "evidence_items": ["EVID-DIFF-PROVEN"],
            "steps_taken": 2,
            "confidence": 0.95
        }

        res = evaluator.evaluate_solution(vulnerable_scenario, sound_submission)
        assert res.passed is True
        assert res.false_positive is False
        assert res.score >= 80.0

    @pytest.mark.asyncio
    async def test_rest_api_skill_graph_endpoint(self):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            res = await client.get("/api/learning/skill_graph")
            assert res.status_code == 200
            data = res.json()
            assert "skills" in data
            assert len(data["skills"]) >= 10
            assert "diagnosed_weak_points" in data
            assert "recommended_next_training_skill" in data

    @pytest.mark.asyncio
    async def test_rest_api_generate_novel_and_evaluate_endpoints(self):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. Generate novel scenario
            res_gen = await client.post("/api/learning/scenarios/generate_novel", json={"skill_id": "sqli_boolean_differential"})
            assert res_gen.status_code == 200
            novel = res_gen.json()
            assert "scenario" in novel
            assert "hidden_truth" not in novel["scenario"]  # Stripped for client

            # 2. Evaluate exam run
            eval_payload = {
                "scenario": {
                    "scenario_id": "exam_run_01",
                    "optimal_steps": 2,
                    "hidden_truth": {"is_vulnerable": True, "vulnerability": "SQL_INJECTION", "variant": "sqli_boolean_differential"}
                },
                "submission": {
                    "declared_vulnerable": True,
                    "hypothesis": "sqli_boolean_differential",
                    "evidence_items": ["E1"],
                    "steps_taken": 2,
                    "confidence": 0.90
                }
            }
            res_eval = await client.post("/api/learning/exam/evaluate_run", json=eval_payload)
            assert res_eval.status_code == 200
            data_eval = res_eval.json()
            assert "evaluation" in data_eval
            assert data_eval["evaluation"]["passed"] is True
            assert "expected_calibration_error" in data_eval
