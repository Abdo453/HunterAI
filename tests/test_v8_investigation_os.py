"""
HunterAI V8.0 Autonomous Security Investigation OS Test Suite
=============================================================
Comprehensive tests for:
- CausalSecurityGraph (directed causal chain verification & disconnected correlation rejection)
- SecurityDigitalTwin (identity & resource modeling, cross-tenant BOLA simulation)
- BayesianHypothesisEngine (Bayesian odds updating, confidence transitions)
- CompetingHypothesesEngine (ACH evaluation, falsifying noise hypotheses, inconclusive gating)
- EvidenceCourtV2 (Finder, Verifier, Skeptic, Causal Analyzer multi-role tribunal)
- AgentConstitution (machine-enforced safety invariants outside the LLM)
- SecurityStateMachine (business logic state progression & security invariant enforcement)
"""
import pytest

from core.causal.causal_graph import CausalSecurityGraph, CausalNodeType
from core.twin.security_digital_twin import SecurityDigitalTwin, RoleTier
from core.reasoning.hypothesis_engine import HypothesisEngine, HypothesisState, BayesianBeliefUpdater
from core.reasoning.competing_hypotheses import CompetingHypothesesEngine, HypothesisOption
from core.court.evidence_court_v2 import EvidenceCourtV2
from core.safety.constitutional_layer import AgentConstitution, ConstitutionalViolationError
from core.statemachine.security_state_machine import SecurityStateMachine, ApplicationState


class TestCausalSecurityGraph:
    def test_unbroken_causal_path(self):
        cg = CausalSecurityGraph("shop.target.local")
        cg.add_node("IN", CausalNodeType.USER_INPUT, "param: user_id")
        cg.add_node("GW", CausalNodeType.PARSER_GATEWAY, "FastAPI Router")
        cg.add_node("AUTH", CausalNodeType.AUTH_DECISION, "Missing Ownership Check")
        cg.add_node("SINK", CausalNodeType.DATA_SINK, "SQL Query")
        cg.add_node("OUT", CausalNodeType.OBSERVABLE_RESPONSE, "Leaked Record in HTTP 200")

        cg.add_causal_link("IN", "GW", "Input parsed")
        cg.add_causal_link("GW", "AUTH", "Route handler called")
        cg.add_causal_link("AUTH", "SINK", "Query executed without auth")
        cg.add_causal_link("SINK", "OUT", "Data reflected")

        res = cg.verify_causal_chain("IN", "OUT")
        assert res.is_causally_proven is True
        assert len(res.unbroken_chain) == 5
        assert res.confidence_score >= 0.9

    def test_broken_causal_link_rejected(self):
        cg = CausalSecurityGraph("shop.target.local")
        cg.add_node("IN", CausalNodeType.USER_INPUT, "param: search")
        cg.add_node("OUT", CausalNodeType.OBSERVABLE_RESPONSE, "500 Error")
        # No links added!
        res = cg.verify_causal_chain("IN", "OUT")
        assert res.is_causally_proven is False
        assert any("No directed causal path exists" in m for m in res.missing_links)


class TestSecurityDigitalTwin:
    def test_digital_twin_attack_path_simulation(self):
        dt = SecurityDigitalTwin("health.corp.local")
        dt.register_identity("user_alice", RoleTier.AUTHENTICATED_USER)
        dt.register_identity("attacker_bob", RoleTier.AUTHENTICATED_USER)
        dt.register_resource("REC-9001", "patient_dossier", "user_alice", "CRITICAL")

        paths = dt.simulate_cross_tenant_access_paths()
        assert len(paths) == 1
        path = paths[0]
        assert path.source_identity == "attacker_bob"
        assert path.target_resource == "REC-9001"
        assert path.projected_risk == "HIGH"


class TestBayesianHypothesisEngine:
    def test_bayesian_confidence_evolution(self):
        he = HypothesisEngine()
        hyp = he.formulate_hypothesis("/api/v1/orders", "BOLA", "Object ID lacks tenant check", prior=0.20)
        assert hyp.current_confidence == 0.20
        assert hyp.state == HypothesisState.FORMULATED

        # Add modest supporting evidence (LR = 4.0)
        hyp.apply_evidence("Baseline differential observed", likelihood_ratio=4.0)
        assert hyp.current_confidence == 0.50
        assert hyp.state == HypothesisState.UNDER_INVESTIGATION

        # Add definitive cryptographic proof (LR = 10.0)
        hyp.apply_evidence("Deterministic proof nonce verified", likelihood_ratio=10.0)
        assert hyp.current_confidence >= 0.90
        assert hyp.state == HypothesisState.EVIDENCE_CONFIRMED


class TestCompetingHypothesesEngine:
    def test_ach_confirms_when_noise_falsified(self):
        res = CompetingHypothesesEngine.evaluate(
            status_code=200,
            body="Proof Nonce 42 Reflected",
            proof_nonce_present=True,
            baseline_stable=True,
            waf_signatures_found=False,
            auth_session_valid=True
        )
        assert res.winning_hypothesis == HypothesisOption.H1_TRUE_VULNERABILITY
        assert res.verdict == "CONFIRMED"
        assert res.is_conclusive is True

    def test_ach_inconclusive_on_server_jitter(self):
        # Exploit payload appears to reflect, BUT baseline is unstable!
        res = CompetingHypothesesEngine.evaluate(
            status_code=200,
            body="Proof Nonce 42 Reflected",
            proof_nonce_present=True,
            baseline_stable=False,  # Jitter!
            waf_signatures_found=False,
            auth_session_valid=True
        )
        assert res.verdict == "INCONCLUSIVE"
        assert res.is_conclusive is False

    def test_ach_refuted_on_expired_session(self):
        res = CompetingHypothesesEngine.evaluate(
            status_code=401,
            body="Session Expired",
            proof_nonce_present=False,
            baseline_stable=True,
            waf_signatures_found=False,
            auth_session_valid=False
        )
        assert res.winning_hypothesis == HypothesisOption.H3_AUTH_SESSION_EXPIRED
        assert res.verdict == "REFUTED"


class TestEvidenceCourtV2:
    def test_unanimous_confirmation(self):
        ruling = EvidenceCourtV2.adjudicate_case(
            case_id="C-100",
            endpoint="/api/orders",
            proof_nonce_proven=True,
            reproductions_count=3,
            causal_chain_verified=True,
            baseline_stable=True,
            waf_clean=True
        )
        assert ruling.final_verdict == "CONFIRMED"
        assert ruling.unanimous is True

    def test_skeptic_dissent_forces_inconclusive(self):
        ruling = EvidenceCourtV2.adjudicate_case(
            case_id="C-200",
            endpoint="/api/search",
            proof_nonce_proven=True,
            reproductions_count=2,
            causal_chain_verified=True,
            baseline_stable=False,  # Skeptic challenges this
            waf_clean=True
        )
        assert ruling.final_verdict == "INCONCLUSIVE"
        assert ruling.unanimous is False
        assert any("Skeptic" in op.argument for op in ruling.opinions if op.disposition == "VOTE_INCONCLUSIVE")


class TestAgentConstitution:
    def test_metadata_ip_blocked(self):
        chk = AgentConstitution.verify_action("169.254.169.254", True, "GET", True, 10, 1000)
        assert chk.is_compliant is False
        assert chk.violated_invariant == "INVARIANT_1_ZERO_SCOPE_EGRESS"
        
        with pytest.raises(ConstitutionalViolationError):
            AgentConstitution.assert_constitutional(chk)

    def test_unapproved_mutation_blocked(self):
        chk = AgentConstitution.verify_action("93.184.216.34", True, "DELETE", False, 10, 1000)
        assert chk.is_compliant is False
        assert chk.violated_invariant == "INVARIANT_3_ZERO_UNAPPROVED_MUTATIONS"


class TestSecurityStateMachine:
    def test_invariant_violation_on_unauthenticated_leak(self):
        sm = SecurityStateMachine("sess_101")
        assert sm.current_state == ApplicationState.UNAUTHENTICATED
        
        vio = sm.execute_transition(
            action_route="/api/export",
            response_status=200,
            response_body='{"secret_data": "CONFIDENTIAL"}',
            intended_next_state=ApplicationState.RESOURCE_OWNER
        )
        assert vio is not None
        assert vio.rule_name == "unauthenticated_cannot_access_private_resource"
        assert sm.current_state == ApplicationState.UNAUTHENTICATED  # Prevented state advance!

    def test_legal_state_transition(self):
        sm = SecurityStateMachine("sess_102")
        vio = sm.execute_transition(
            action_route="/api/login",
            response_status=200,
            response_body='{"token": "xyz"}',
            intended_next_state=ApplicationState.AUTHENTICATED_NORMAL
        )
        assert vio is None
        assert sm.current_state == ApplicationState.AUTHENTICATED_NORMAL
