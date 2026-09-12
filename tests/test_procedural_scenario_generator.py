"""
Unit Tests for Procedural Scenario Generator
Tests: Randomized endpoint synthesis, parameter permutations, noise injection, and hidden truth isolation.
"""
import pytest

from core.learning.scenario_generator import ProceduralScenarioGenerator


class TestProceduralScenarioGenerator:
    def test_generate_vulnerable_procedural_scenario(self):
        scenario = ProceduralScenarioGenerator.generate_scenario(
            skill_id="sqli_boolean_differential",
            is_vulnerable=True,
            inject_noise=True
        )

        assert "procedural_sqli_boolean_differential_" in scenario["scenario_id"]
        assert scenario["skill"] == "sqli_boolean_differential"
        assert scenario["hidden_truth"]["is_vulnerable"] is True
        assert scenario["hidden_truth"]["vulnerable_param"] is not None

        # Check observations contain baseline and noise
        obs = scenario["observations"]
        assert len(obs) >= 2
        assert "response_length" in obs[0]
        assert "latency_ms" in obs[0]

        # Check candidate actions present
        actions = scenario["available_actions"]
        assert len(actions) >= 2

    def test_generate_safe_procedural_scenario(self):
        scenario = ProceduralScenarioGenerator.generate_scenario(
            skill_id="sqli_boolean_differential",
            is_vulnerable=False,
            inject_noise=False
        )

        assert scenario["hidden_truth"]["is_vulnerable"] is False
        assert scenario["hidden_truth"]["vulnerable_param"] is None
        assert "Strict parameterized" in scenario["hidden_truth"]["root_cause"]

    def test_generator_produces_non_deterministic_variations(self):
        # Generate two scenarios and verify randomization across domain/endpoints/parameters
        sc_1 = ProceduralScenarioGenerator.generate_scenario("sqli_error_analysis")
        sc_2 = ProceduralScenarioGenerator.generate_scenario("sqli_error_analysis")

        assert sc_1["scenario_id"] != sc_2["scenario_id"]
