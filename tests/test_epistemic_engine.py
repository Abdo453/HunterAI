"""
Unit tests for HunterAI Research-Grade Epistemic Engine:
- Epistemic Stratification & Evidence Lineage Graph
- Predictive Experiment Designer
- Agent Compiler (Mission Synthesis)
- Research Postmortem & Self-Evaluator
"""
import pytest

from hunter_ai.runtime import (
    EpistemicType, EpistemicNode, EvidenceGraph, PredictiveExperimentSpec,
    AgentCompiler, CompiledResearchPlan, ResearchPostmortemEvaluator, ResearchPostmortem
)


# ─── 1. Evidence Lineage Graph Tests ─────────────────────────────────────────
class TestEvidenceGraph:
    def test_node_creation_and_lineage_tracking(self):
        graph = EvidenceGraph()

        # Observation -> Hypothesis -> Evidence -> Finding
        obs = graph.add_node(
            epistemic_type=EpistemicType.OBSERVATION,
            content="HTTP 200 returned on /api/user/5 with JSON body",
            confidence=1.0,
            node_id="N_OBS_1"
        )
        hyp = graph.add_node(
            epistemic_type=EpistemicType.HYPOTHESIS,
            content="Endpoint /api/user/{id} lacks tenant authorization check",
            confidence=0.5,
            parent_ids=[obs.id],
            node_id="N_HYP_1"
        )
        ev = graph.add_node(
            epistemic_type=EpistemicType.EVIDENCE,
            content="User B cookie retrieved User A record without restriction",
            confidence=0.9,
            parent_ids=[hyp.id],
            node_id="N_EV_1"
        )
        finding = graph.add_node(
            epistemic_type=EpistemicType.CONFIRMED,
            content="BOLA / IDOR on /api/user/{id}",
            confidence=0.95,
            parent_ids=[ev.id],
            node_id="N_FND_1"
        )

        assert finding.id == "N_FND_1"
        assert "N_EV_1" in finding.parent_ids
        assert "N_FND_1" in ev.child_ids

        # Full lineage path extraction
        lineage = graph.get_lineage("N_FND_1")
        lineage_ids = [n["id"] for n in lineage]
        assert "N_FND_1" in lineage_ids
        assert "N_EV_1" in lineage_ids
        assert "N_HYP_1" in lineage_ids
        assert "N_OBS_1" in lineage_ids

    def test_cascading_evidence_invalidation(self):
        graph = EvidenceGraph()
        # Node A -> Node B -> Node C
        n_a = graph.add_node(EpistemicType.EVIDENCE, "Initial probe diff", confidence=0.8, node_id="A")
        n_b = graph.add_node(EpistemicType.HYPOTHESIS, "Vulnerability hypothesis", confidence=0.75, parent_ids=["A"], node_id="B")
        n_c = graph.add_node(EpistemicType.CONFIRMED, "Candidate finding", confidence=0.9, parent_ids=["B"], node_id="C")

        # Invalidate root evidence node A (e.g. found to be random nonce noise)
        graph.invalidate_node("A", reason="Identified as dynamic random nonce")

        assert graph.get_node("A").confidence == 0.0
        # Child node B confidence should degrade significantly
        assert graph.get_node("B").confidence < 0.3
        assert "A" in graph.get_node("B").metadata.get("degraded_by_parent", "")


# ─── 2. Predictive Experiment Spec Tests ─────────────────────────────────────
class TestPredictiveExperimentSpec:
    def test_pre_probe_prediction_evaluation(self):
        spec = PredictiveExperimentSpec(
            experiment_id="EXP_PRED_01",
            hypothesis_id="HYP_SQLI_01",
            question="Is query parameter concatenated into SQL command?",
            variable_under_test="id",
            baseline_value="1",
            mutated_value="1' AND 1=1--",
            prediction_if_true="Status 200 with identical item catalog",
            prediction_if_false="Generic 400 Bad Request or 404",
            falsification_condition="WAF block 403 or rate limit 429"
        )

        # 1. Prediction satisfied
        ok, conf, reason = spec.evaluate_result("Server returned Status 200 with identical item catalog content")
        assert ok is True
        assert conf >= 0.9
        assert "confirmed pre-probe prediction" in reason

        # 2. Falsification triggered
        ok, conf, reason = spec.evaluate_result("Request rejected: WAF block 403 triggered by Imperva")
        assert ok is False
        assert conf <= 0.1
        assert "Falsification condition triggered" in reason


# ─── 3. Agent Compiler Tests ─────────────────────────────────────────────────
class TestAgentCompiler:
    def test_mission_compilation_rest_api(self):
        plan = AgentCompiler.compile_mission(
            target_domain="api.store.local",
            target_technology="REST_API",
            max_steps=15
        )

        assert isinstance(plan, CompiledResearchPlan)
        assert plan.target_domain == "api.store.local"
        assert plan.allocated_budget_steps == 15
        assert "http_probe" in plan.authorized_toolset
        assert "tenant_isolation_idor" in plan.priority_exploration_vectors
        assert plan.stopping_criteria["max_consecutive_stagnant_steps"] == 4

    def test_mission_compilation_graphql(self):
        plan = AgentCompiler.compile_mission(
            target_domain="graphql.store.local",
            target_technology="GRAPHQL",
            max_steps=10
        )
        assert "introspection_query" in plan.priority_exploration_vectors


# ─── 4. Research Postmortem Evaluator Tests ──────────────────────────────────
class TestResearchPostmortemEvaluator:
    def test_postmortem_generation(self):
        tested = [
            {"id": "H1", "status": "CONFIRMED"},
            {"id": "H2", "status": "REFUTED"},
            {"id": "H3", "status": "REFUTED"}
        ]
        confirmed = [
            {"vulnerability": "IDOR", "parameter": "account_id", "endpoint": "/api/account"}
        ]

        pm = ResearchPostmortemEvaluator.evaluate_mission(
            mission_id="M_TEST_01",
            target="test.local",
            duration=12.4,
            tested_hypotheses=tested,
            confirmed_findings=confirmed,
            stagnation_events=1
        )

        assert pm.mission_id == "M_TEST_01"
        assert pm.hypotheses_confirmed_count == 1
        assert pm.hypotheses_falsified_count == 2
        assert len(pm.key_lessons_learned) >= 1
        assert "account_id" in pm.extracted_heuristics[0]
