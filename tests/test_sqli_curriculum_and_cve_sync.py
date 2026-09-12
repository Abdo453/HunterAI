"""
Unit & Integration Tests for SQLi Curriculum, Scenario Loader, and CVE Sync Engine
Tests:
- Dynamic discovery of 10-level SQLi curriculum
- Auto-sync and ingestion of CVE case studies (MOVEit CVE-2023-34362, WP Automatic CVE-2024-27956)
- False-positive enforcement (Observation != Vulnerability)
- SQLi graduation scorecard generation
- REST endpoints /api/learning/sync, /api/learning/sqli/curriculum, and /api/learning/sqli/evaluate
"""
import pytest
import httpx
from pathlib import Path

from core.learning.scenario_loader import DynamicScenarioLoader
from core.learning.sqli_evaluator import SQLiGraduationEvaluator, SQLiKnowledgeScorecard
from core.learning.knowledge_store import KnowledgeStore
from ui.web.app import app


class TestSQLiCurriculumAndCVESync:
    def test_dynamic_scenario_loader_discovers_all_ten_levels(self):
        loader = DynamicScenarioLoader()
        report = loader.sync_all()

        assert report["total_active_scenarios"] >= 10
        assert "sqli_lvl0_sql_concept" in report["scenarios_list"]
        assert "sqli_lvl1_input_reflection" in report["scenarios_list"]
        assert "sqli_lvl2_boolean_differential" in report["scenarios_list"]
        assert "sqli_lvl7_time_based_noise" in report["scenarios_list"]
        assert "sqli_lvl9_multi_hypothesis_investigation" in report["scenarios_list"]

    def test_cve_case_studies_auto_synced_into_knowledge_store(self):
        loader = DynamicScenarioLoader()
        report = loader.sync_all()

        assert report["total_indexed_cves"] >= 4
        assert "CVE-2023-34362" in report["cves_list"]
        assert "CVE-2024-27956" in report["cves_list"]

        # Verify MOVEit CVE ingested into KnowledgeStore
        kb_item = loader.kb.get_item("CVE-2023-34362")
        assert kb_item is not None
        assert "MOVEit" in kb_item.name
        assert "human.aspx" in kb_item.signals or "moveit_transfer_login" in kb_item.signals
        assert kb_item.item_type == "cve_case_study"

    def test_evaluator_flags_false_positive_on_reflection(self):
        evaluator = SQLiGraduationEvaluator()

        # Flawed Agent attempt: Claims input reflection in Level 1 is SQLi
        flawed_attempt = {
            "declared_vulnerable": True,
            "hypothesis": "SQL_INJECTION",
            "evidence_items": ["echoed_input"]
        }
        eval_res = evaluator.evaluate_scenario_attempt("sqli_lvl1_input_reflection", flawed_attempt)

        assert eval_res["passed"] is False
        assert eval_res["false_positive"] is True  # Flagged!

    def test_evaluator_passes_sound_epistemic_agent_reasoning(self):
        evaluator = SQLiGraduationEvaluator()

        # Sound Agent attempt on Level 2 Boolean Differential
        sound_attempt = {
            "declared_vulnerable": True,
            "hypothesis": "boolean_differential SQLi",
            "evidence_items": ["EVID-DIFF-HASH-01"]
        }
        eval_res = evaluator.evaluate_scenario_attempt("sqli_lvl2_boolean_differential", sound_attempt)

        assert eval_res["passed"] is True
        assert eval_res["false_positive"] is False
        assert eval_res["evidence_sufficient"] is True

    def test_full_curriculum_graduation_evaluation(self):
        evaluator = SQLiGraduationEvaluator()

        # Simulated perfect reasoning run across all 10 levels
        perfect_run = [
            {"scenario_id": "sqli_lvl0_sql_concept", "declared_vulnerable": False, "hypothesis": "Normal SQL predicate", "evidence_items": []},
            {"scenario_id": "sqli_lvl1_input_reflection", "declared_vulnerable": False, "hypothesis": "Harmless echo", "evidence_items": []},
            {"scenario_id": "sqli_lvl2_boolean_differential", "declared_vulnerable": True, "hypothesis": "boolean_differential SQLi", "evidence_items": ["E1"]},
            {"scenario_id": "sqli_lvl3_auth_logic", "declared_vulnerable": True, "hypothesis": "auth_query_truncation SQLi", "evidence_items": ["E2"]},
            {"scenario_id": "sqli_lvl4_error_based", "declared_vulnerable": True, "hypothesis": "error_based SQLi", "evidence_items": ["E3"]},
            {"scenario_id": "sqli_lvl5_union_reasoning", "declared_vulnerable": True, "hypothesis": "union_based SQLi", "evidence_items": ["E4"]},
            {"scenario_id": "sqli_lvl6_blind_inference", "declared_vulnerable": True, "hypothesis": "blind_boolean SQLi", "evidence_items": ["E5"]},
            {"scenario_id": "sqli_lvl7_time_based_noise", "declared_vulnerable": True, "hypothesis": "time_based_blind SQLi", "evidence_items": ["E6"]},
            {"scenario_id": "sqli_lvl8_filtering_normalization", "declared_vulnerable": True, "hypothesis": "waf_filtered SQLi", "evidence_items": ["E7"]},
            {"scenario_id": "sqli_lvl9_multi_hypothesis_investigation", "declared_vulnerable": True, "hypothesis": "order_by SQLi", "evidence_items": ["E8"]}
        ]

        scorecard = evaluator.evaluate_full_curriculum(perfect_run)

        assert scorecard.total_scenarios_evaluated == 10
        assert scorecard.false_positives_count == 0
        assert scorecard.false_positive_rate_pct == 0.0
        assert scorecard.evidence_completeness_pct >= 80.0
        assert scorecard.overall_sqli_score >= 85.0
        assert scorecard.graduated_to_labs is True

        terminal_report = scorecard.format_terminal_scorecard()
        assert "GRADUATED" in terminal_report

    @pytest.mark.asyncio
    async def test_rest_api_sync_and_sqli_curriculum_endpoints(self):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # Test /api/learning/sync
            res_sync = await client.get("/api/learning/sync")
            assert res_sync.status_code == 200
            data_sync = res_sync.json()
            assert "sync_report" in data_sync
            assert data_sync["sync_report"]["total_active_scenarios"] >= 10

            # Test /api/learning/sqli/curriculum (hidden truths stripped)
            res_curr = await client.get("/api/learning/sqli/curriculum")
            assert res_curr.status_code == 200
            data_curr = res_curr.json()
            assert data_curr["total"] >= 10
            for sc in data_curr["sqli_scenarios"]:
                assert "hidden_truth" not in sc  # Stripped for student safety!
                assert "available_actions" in sc

            # Test /api/learning/sqli/evaluate
            sample_attempts = [
                {"scenario_id": "sqli_lvl0_sql_concept", "declared_vulnerable": False, "hypothesis": "Normal SQL", "evidence_items": []},
                {"scenario_id": "sqli_lvl1_input_reflection", "declared_vulnerable": False, "hypothesis": "Harmless echo", "evidence_items": []}
            ]
            res_eval = await client.post("/api/learning/sqli/evaluate", json={"attempts": sample_attempts})
            assert res_eval.status_code == 200
            data_eval = res_eval.json()
            assert "scorecard" in data_eval
            assert data_eval["scorecard"]["false_positives_count"] == 0
