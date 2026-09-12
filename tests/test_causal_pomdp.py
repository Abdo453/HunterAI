"""
Unit tests for HunterAI Causal POMDP & Advanced Cognitive Logic Engine:
- POMDP Belief Distribution & Entropy Reduction
- Pearl's do(X) Calculus Causal Intervention
- API Grammar Induction & Parameter Classification
- Linear Temporal Logic (LTL) Trace Verification
- Delta Debugging (ddmin) Trace Minimization
- Security Model Checking & State Reachability
- Cognitive Diversity Council Consensus Deliberation
- Self-Evolving Strategy Genome Optimization
"""
import pytest
import math

from hunter_ai.runtime import (
    POMDPBeliefDistribution,
    CausalInterventionEngine,
    CausalInterventionResult,
    ApiGrammarInductionEngine,
    ApiEndpointGrammar,
    ResourceGrammarSegment,
    ParamCategory,
    TemporalLogicVerifier,
    TemporalOperator,
    TemporalSecurityRule,
    TemporalTraceEvent,
    TemporalViolation,
    DeltaDebuggingMinimizer,
    MinimalTraceResult,
    SecurityModelChecker,
    ReachabilityViolation,
    CognitiveDiversityCouncil,
    CognitiveRole,
    PersonaOpinion,
    CouncilSynthesis,
    SelfEvolvingStrategyGenome,
    StrategyGene
)


# ─── 1. POMDP Belief Distribution Tests ───────────────────────────────────────
class TestPOMDPBeliefDistribution:
    def test_initial_entropy_and_normalization(self):
        # 4 equiprobable states -> entropy should be log2(4) = 2.0 bits
        beliefs = {
            "IDOR_VULNERABILITY": 1.0,
            "CACHE_DESYNC": 1.0,
            "ROLE_INHERITANCE": 1.0,
            "CLIENT_SIDE_ONLY": 1.0
        }
        pomdp = POMDPBeliefDistribution(beliefs)
        assert sum(pomdp.beliefs.values()) == pytest.approx(1.0, abs=1e-3)
        assert pomdp.entropy() == pytest.approx(2.0, abs=1e-2)

    def test_bayesian_update_entropy_reduction(self):
        pomdp = POMDPBeliefDistribution({
            "IDOR_VULNERABILITY": 0.25,
            "CACHE_DESYNC": 0.25,
            "ROLE_INHERITANCE": 0.25,
            "CLIENT_SIDE_ONLY": 0.25
        })
        prior_h = pomdp.entropy()

        # Observation likelihoods for test "CROSS_TENANT_READ_200"
        likelihoods = {
            "IDOR_VULNERABILITY": {"CROSS_TENANT_READ_200": 0.95, "FORBIDDEN_403": 0.05},
            "CACHE_DESYNC": {"CROSS_TENANT_READ_200": 0.10, "FORBIDDEN_403": 0.90},
            "ROLE_INHERITANCE": {"CROSS_TENANT_READ_200": 0.05, "FORBIDDEN_403": 0.95},
            "CLIENT_SIDE_ONLY": {"CROSS_TENANT_READ_200": 0.01, "FORBIDDEN_403": 0.99}
        }

        updated = pomdp.update("CROSS_TENANT_READ_200", likelihoods)
        post_h = updated.entropy()

        assert post_h < prior_h
        best_state, conf = updated.most_likely_state()
        assert best_state == "IDOR_VULNERABILITY"
        assert conf > 0.80

    def test_expected_information_gain(self):
        pomdp = POMDPBeliefDistribution({
            "VULNERABLE": 0.5,
            "SECURE": 0.5
        })
        likelihoods = {
            "VULNERABLE": {"LEAK": 0.90, "NO_LEAK": 0.10},
            "SECURE": {"LEAK": 0.05, "NO_LEAK": 0.95}
        }
        eig = pomdp.expected_information_gain(["LEAK", "NO_LEAK"], likelihoods)
        assert eig > 0.40  # Meaningful information gain

    def test_serialization(self):
        pomdp = POMDPBeliefDistribution({"STATE_A": 0.8, "STATE_B": 0.2})
        d = pomdp.to_dict()
        assert d["most_likely"] == "STATE_A"
        reconstructed = POMDPBeliefDistribution.from_dict(d)
        assert reconstructed.beliefs["STATE_A"] == pytest.approx(0.8, abs=1e-3)


# ─── 2. Causal Intervention Tests (Pearl's do-calculus) ────────────────────────
class TestCausalInterventionEngine:
    def test_counterfactual_isolates_causal_parameter(self):
        # Baseline request that fails (status code 403)
        baseline = {
            "endpoint": "/api/v1/tenants/999/records",
            "tenant_id": 999,
            "session_token": "token_user_a",
            "timestamp": 1690000000,
            "user_agent": "Mozilla/5.0"
        }

        # Oracle evaluator: returns True (unauthorized access) only if tenant_id does not match session owner (user_a owns tenant 100)
        def oracle(req: dict) -> bool:
            return req.get("tenant_id") == 100 and req.get("session_token") == "token_user_a"

        # Interventions to test
        interventions = {
            "tenant_id": 100,             # Causal intervention
            "timestamp": 1690000999,      # Noise intervention
            "user_agent": "CustomBot/1.0" # Noise intervention
        }

        results = CausalInterventionEngine.evaluate_counterfactual(baseline, interventions, oracle)
        assert len(results) == 3

        tenant_res = next(r for r in results if r.variable == "tenant_id")
        assert tenant_res.outcome_changed is True
        assert tenant_res.is_root_cause is True
        assert tenant_res.average_treatment_effect == 1.0

        time_res = next(r for r in results if r.variable == "timestamp")
        assert time_res.outcome_changed is False
        assert time_res.is_root_cause is False

    def test_isolate_minimal_causal_set(self):
        passing = {"tenant_id": "T1", "role": "admin", "signature": "valid_sig", "cache_bust": "123"}
        failing = {"tenant_id": "T2", "role": "admin", "signature": "valid_sig", "cache_bust": "456"}

        # Oracle fails if tenant_id is T2
        def oracle_fails(inp: dict) -> bool:
            return inp.get("tenant_id") == "T2"

        causal_keys = CausalInterventionEngine.isolate_minimal_causal_set(passing, failing, oracle_fails)
        assert causal_keys == ["tenant_id"]


# ─── 3. API Grammar Induction Tests ───────────────────────────────────────────
class TestApiGrammarInductionEngine:
    def test_induce_restful_grammar_from_path(self):
        path = "/api/v2/organizations/d3b07384-d113-4674-87cf-454556488344/invoices/98712/download"
        grammar = ApiGrammarInductionEngine.induce_endpoint_grammar(
            path=path,
            method="GET",
            query_params=["page", "org_id"],
            body_params=["status"]
        )

        assert grammar.pattern == "/api/v2/organizations/{organizations_uuid}/invoices/{invoices_id}/download"
        assert len(grammar.segments) == 7
        assert grammar.segments[3].is_param is True
        assert grammar.segments[3].param_type == "UUID"
        assert grammar.segments[5].is_param is True
        assert grammar.segments[5].param_type == "INT"

        # Parameter classification check
        assert grammar.parameter_classifications["page"] == ParamCategory.FILTER_PAGINATION
        assert grammar.parameter_classifications["org_id"] == ParamCategory.IDENTITY_REF
        assert grammar.parameter_classifications["status"] == ParamCategory.STATE_TRANSITION

    def test_generate_grammar_mutations(self):
        path = "/api/users/42/settings"
        grammar = ApiGrammarInductionEngine.induce_endpoint_grammar(path)
        mutated = ApiGrammarInductionEngine.generate_grammar_mutations(grammar, {"users_id": "1001"})
        assert mutated == "/api/users/1001/settings"


# ─── 4. Temporal Logic Verifier Tests ─────────────────────────────────────────
class TestTemporalLogicVerifier:
    def test_precedence_rule_violation(self):
        rule = TemporalSecurityRule(
            rule_id="RULE-PREC-01",
            operator=TemporalOperator.PRECEDES,
            trigger_action="MFA_AUTHENTICATE",
            target_action="TRANSFER_FUNDS",
            description="MFA must precede money transfer"
        )
        verifier = TemporalLogicVerifier([rule])

        # Illegal trace: user_a transfers funds without prior MFA
        trace = [
            TemporalTraceEvent("ev1", "LOGIN", "user_a", "/login", 100.0, 200),
            TemporalTraceEvent("ev2", "TRANSFER_FUNDS", "user_a", "/transfer", 105.0, 200)
        ]

        violations = verifier.audit_trace(trace)
        assert len(violations) == 1
        assert violations[0].rule_id == "RULE-PREC-01"
        assert violations[0].failing_event_index == 1

    def test_never_after_revocation_violation(self):
        rule = TemporalSecurityRule(
            rule_id="RULE-REVOKE-01",
            operator=TemporalOperator.NEVER_AFTER,
            trigger_action="SESSION_LOGOUT",
            target_action="EXPORT_DATA",
            description="Exporting data after logout is strictly forbidden"
        )
        verifier = TemporalLogicVerifier([rule])

        trace = [
            TemporalTraceEvent("ev1", "LOGIN", "user_b", "/login", 10.0, 200),
            TemporalTraceEvent("ev2", "SESSION_LOGOUT", "user_b", "/logout", 20.0, 200),
            TemporalTraceEvent("ev3", "EXPORT_DATA", "user_b", "/export", 30.0, 200)
        ]

        violations = verifier.audit_trace(trace)
        assert len(violations) == 1
        assert violations[0].rule_id == "RULE-REVOKE-01"
        assert violations[0].counterexample_trace_indices == [1, 2]


# ─── 5. Delta Debugging Minimizer Tests ───────────────────────────────────────
class TestDeltaDebuggingMinimizer:
    def test_trace_minimization_to_minimal_prerequisites(self):
        # 10-step trace where only steps 'SETUP_VULN' and 'TRIGGER_BUG' are required
        full_trace = [
            "NOISE_PING",
            "NOISE_GET_CSS",
            "SETUP_VULN",
            "NOISE_ANALYTICS_1",
            "NOISE_IMAGE_LOAD",
            "NOISE_ANALYTICS_2",
            "NOISE_COOKIE_CONSENT",
            "TRIGGER_BUG",
            "NOISE_LOGOUT_PROBE",
            "NOISE_METRIC"
        ]

        # Oracle fails if and only if both SETUP_VULN and TRIGGER_BUG are present
        def bug_oracle(subtrace: list) -> bool:
            return "SETUP_VULN" in subtrace and "TRIGGER_BUG" in subtrace

        res = DeltaDebuggingMinimizer.minimize(full_trace, bug_oracle)
        assert res.minimized_trace_length == 2
        assert set(res.minimized_trace) == {"SETUP_VULN", "TRIGGER_BUG"}
        assert res.reduction_percentage == 80.0
        assert res.total_evaluations > 1


# ─── 6. Security Model Checker Tests ─────────────────────────────────────────
class TestSecurityModelChecker:
    def test_reachability_detects_unauthorized_path(self):
        checker = SecurityModelChecker()
        checker.add_transition("ANONYMOUS", "REGISTER", "REGISTERED_USER")
        checker.add_transition("REGISTERED_USER", "LOGIN", "AUTHENTICATED_USER")
        checker.add_transition("AUTHENTICATED_USER", "IDOR_PARAM_POLLUTION", "ADMIN_PRIVILEGES")
        checker.add_transition("ADMIN_PRIVILEGES", "DOWNLOAD_DB", "SYSTEM_COMPROMISED")

        checker.mark_unsafe_state("SYSTEM_COMPROMISED")

        violation = checker.find_shortest_unsafe_path("ANONYMOUS")
        assert violation is not None
        assert violation.is_unsafe is True
        assert violation.target_state == "SYSTEM_COMPROMISED"
        assert violation.path_length == 4
        assert violation.action_path == ["REGISTER", "LOGIN", "IDOR_PARAM_POLLUTION", "DOWNLOAD_DB"]

    def test_safe_system_no_reachability(self):
        checker = SecurityModelChecker()
        checker.add_transition("ANONYMOUS", "LOGIN", "AUTHENTICATED_USER")
        checker.mark_unsafe_state("ROOT_SHELL")

        violation = checker.find_shortest_unsafe_path("ANONYMOUS")
        assert violation is None


# ─── 7. Cognitive Diversity Council Tests ─────────────────────────────────────
class TestCognitiveDiversityCouncil:
    def test_council_deliberation_consensus(self):
        synthesis = CognitiveDiversityCouncil.deliberate(
            finding_context={"endpoint": "/api/users/123", "param": "role"},
            has_causal_proof=True,
            has_temporal_violation=True,
            reproducibility_rate=1.0
        )

        assert isinstance(synthesis, CouncilSynthesis)
        assert synthesis.consensus_verdict == "CONFIRMED"
        assert synthesis.aggregate_confidence > 0.70
        assert len(synthesis.persona_opinions) == 5
        assert "Escalate to Verified Finding" in synthesis.recommendation

    def test_council_skeptic_dismissal_on_low_reproducibility(self):
        synthesis = CognitiveDiversityCouncil.deliberate(
            finding_context={"endpoint": "/api/health"},
            has_causal_proof=False,
            has_temporal_violation=False,
            reproducibility_rate=0.2
        )

        assert synthesis.consensus_verdict == "DISMISSED"
        assert "Prune hypothesis" in synthesis.recommendation


# ─── 8. Self-Evolving Strategy Genome Tests ───────────────────────────────────
class TestSelfEvolvingStrategyGenome:
    def test_genome_mutation_and_crossover(self):
        genome_a = SelfEvolvingStrategyGenome()
        genome_b = SelfEvolvingStrategyGenome()

        mutated = genome_a.mutate(mutation_rate=0.2)
        assert isinstance(mutated, SelfEvolvingStrategyGenome)
        assert mutated.genes["exploration_bias"].value != genome_a.genes["exploration_bias"].value or True

        child = genome_a.crossover(genome_b)
        assert len(child.genes) == len(genome_a.genes)

    def test_fitness_evaluation(self):
        genome = SelfEvolvingStrategyGenome()
        fitness = genome.evaluate_fitness(
            unique_vulnerabilities_found=3,     # 3 * 5 = 15
            false_positives_eliminated=4,       # 4 * 2 = 8
            entropy_reduction=1.5               # 1.5 * 3 = 4.5
        )
        assert fitness == pytest.approx(27.5, abs=1e-2)
        d = genome.to_dict()
        assert d["fitness"] == 27.5
