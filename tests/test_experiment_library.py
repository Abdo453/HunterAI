"""
Unit Tests for Scientific Experiment Library
Tests: Standardized experiment templates, applicable hypothesis lookup, and skill-based queries.
"""
import pytest

from core.learning.experiment_library import ExperimentLibrary, ExperimentTemplate


class TestExperimentLibrary:
    def test_canonical_experiments_registered(self):
        library = ExperimentLibrary()
        experiments = library.get_all_experiments()
        assert len(experiments) >= 6

        exp_boolean = library.get_experiment("exp_sqli_boolean_pair")
        assert exp_boolean is not None
        assert exp_boolean.probe_kind == "BOOLEAN_PAIR"
        assert exp_boolean.evidence_type_produced == "BEHAVIOR_DIFF"

    def test_find_experiments_for_hypothesis(self):
        library = ExperimentLibrary()

        sqli_exps = library.find_experiments_for_hypothesis("SQLi")
        assert len(sqli_exps) >= 3
        probe_kinds = [e.probe_kind for e in sqli_exps]
        assert "BOOLEAN_PAIR" in probe_kinds
        assert "ERROR_SYNTAX" in probe_kinds

        bola_exps = library.find_experiments_for_hypothesis("BOLA")
        assert len(bola_exps) >= 2
        bola_kinds = [e.probe_kind for e in bola_exps]
        assert "CROSS_TENANT_SWAP" in bola_kinds

    def test_register_and_retrieve_custom_experiment(self):
        library = ExperimentLibrary()
        custom = ExperimentTemplate(
            experiment_id="exp_csrf_token_swap",
            skill_id="csrf_validation",
            name="Cross-Origin CSRF Nonce Bypass Probe",
            probe_kind="CSRF_TOKEN_SWAP",
            applicable_hypotheses=["CSRF"],
            evidence_type_produced="AUTH_ANOMALY"
        )
        library.register_experiment(custom)

        retrieved = library.get_experiment("exp_csrf_token_swap")
        assert retrieved is not None
        assert retrieved.name == "Cross-Origin CSRF Nonce Bypass Probe"
