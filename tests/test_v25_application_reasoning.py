# -*- coding: utf-8 -*-
"""
HunterAI V25.0 Application Reasoning Engine Test Suite
======================================================
Comprehensive test suite verifying:
1. ApplicationDigitalTwin (Identities, Resources, Endpoints, Workflows)
2. TargetContradictionEngine (Authz inconsistency, Status-body desync)
3. AttackChainComposer & Shortest Path Search
4. MutationGrammarEngine (Financial, Identity, Role, Redirect mutations)
5. ProtocolStateLearner (Illegal jumps, Stale session reuse)
6. DynamicInvariantDiscoverer (Workflow observation, Invariant violation)
7. WhyNotEngine (Negative proof accounting & Coverage)
8. MetamorphicEngine (Parameter order, Encoding equivalence)
9. ExperimentNotebook (Investigation traces, Failure intelligence)
10. SelfGeneratedTestSynthesizer
11. AutonomousBrain V25 attachment
"""
import pytest
from unittest.mock import MagicMock

from core.twin.application_twin import (
    ApplicationDigitalTwin,
    ResourceSensitivity,
    TwinResource,
    TwinEndpoint,
)
from core.reasoning.target_contradiction_engine import (
    TargetContradictionEngine,
    ContradictionType,
)
from core.chains.attack_chain_composer import (
    AttackChainComposer,
    ChainLink,
)
from core.mutation.grammar_engine import (
    MutationGrammarEngine,
    MutationCategory,
)
from core.statemachine.protocol_state_learner import (
    ProtocolStateLearner,
    StateViolationClass,
)
from core.business_logic.invariant_discovery import (
    DynamicInvariantDiscoverer,
    InferredInvariant,
)
from core.visibility.why_not_engine import (
    WhyNotEngine,
    NegativeProofRecord,
)
from core.testing.metamorphic_engine import (
    MetamorphicEngine,
    MetamorphicRelationType,
)
from core.experiment.experiment_notebook import (
    ExperimentNotebook,
)
from core.testing.self_generated_tests import (
    SelfGeneratedTestSynthesizer,
)
from core.brain.autonomous_brain import AutonomousBrain


# =========================================================================
# 1. Application Digital Twin Tests
# =========================================================================

def test_application_twin_unified_state_sync():
    twin = ApplicationDigitalTwin(target_host="app.target.local")
    twin.ingest_wire_observation("GET", "/api/v1/users/42?include=profile", 200)
    twin.ingest_wire_observation("POST", "/api/v1/orders", 201)

    summary = twin.get_summary()
    assert summary["target_host"] == "app.target.local"
    assert summary["total_identities"] >= 4
    assert summary["total_endpoints"] >= 2
    assert "GET:/api/v1/users/42" in twin.endpoints
    assert twin.endpoints["POST:/api/v1/orders"].state_mutating is True


def test_application_twin_identity_and_resource_registration():
    twin = ApplicationDigitalTwin(target_host="shop.local")
    twin.register_resource("inv_9981", "invoice", owner="user_a", sensitivity=ResourceSensitivity.RESTRICTED)
    twin.register_workflow_state("checkout", "CREATED", {"pay": "PAID"})

    assert "inv_9981" in twin.resources
    assert twin.resources["inv_9981"].sensitivity == ResourceSensitivity.RESTRICTED
    assert "checkout" in twin.workflows
    assert twin.workflows["checkout"]["CREATED"].allowed_transitions["pay"] == "PAID"


# =========================================================================
# 2. Target Contradiction Engine Tests
# =========================================================================

def test_contradiction_engine_authorization_inconsistency():
    engine = TargetContradictionEngine()

    standard_resp = {"status": 403, "body": "Forbidden by Gateway"}
    tampered_resp = {
        "status": 200,
        "body": '{"admin_metrics": {"active_users": 1024, "db_cluster": "primary-east"}}'
    }

    contradiction = engine.evaluate_authorization_behavior(
        endpoint="/admin/metrics",
        standard_response=standard_resp,
        tampered_response=tampered_resp,
        tampering_description="Header X-Original-URL: /admin/metrics"
    )

    assert contradiction is not None
    assert contradiction.contradiction_type == ContradictionType.GATEWAY_BACKEND_DISCREPANCY
    assert "PERIMETER_GATEWAY_AUTH_BYPASS" in contradiction.suggested_hypothesis


def test_contradiction_engine_status_body_desync():
    engine = TargetContradictionEngine()

    contradiction = engine.evaluate_status_body_desync(
        endpoint="/api/v1/user/private_record",
        response_status=401,
        response_body='{"error": "Unauthorized", "user_ssn": "999-12-4455", "role": "admin"}',
        expected_sensitive_marker="999-12-4455"
    )

    assert contradiction is not None
    assert contradiction.contradiction_type == ContradictionType.STATUS_BODY_DESYNC
    assert "STATUS_MASKED_INFORMATION_LEAK" in contradiction.suggested_hypothesis


# =========================================================================
# 3. Attack Chain Composer & Path Search Tests
# =========================================================================

def test_attack_chain_composer_evidence_backed_linkage():
    composer = AttackChainComposer()

    links = [
        ChainLink(1, "FIND-01", "InfoDisclosure", "Find UUID in JS bundle", "user_uuid_441", "Found in bundle.js"),
        ChainLink(2, "FIND-02", "BOLA", "Replay UUID against order endpoint", "signed_s3_url", "Server returned private S3 bucket URL"),
        ChainLink(3, "FIND-03", "DataExfiltration", "Download private database snapshot", "customer_pii", "Exfiltrated 50,000 PII records"),
    ]

    chain = composer.compose_chain(
        chain_title="JS UUID to Full Customer PII Leak",
        initial_identity="anonymous",
        target_impact="Mass Customer PII Exfiltration",
        links=links
    )

    assert chain.composite_severity == "CRITICAL"
    assert len(chain.links) == 3
    assert chain.links[1].unlocked_primitive == "signed_s3_url"


def test_attack_path_search_shortest_distance():
    # Graph representing attack hops with weights (costs)
    # Anonymous -> [Login (2.0), Docs (0.5)]
    # Docs -> [Leaked_Token (1.0)]
    # Login -> [User_Session (1.0)]
    # Leaked_Token -> [Admin_DB (1.0)]
    # User_Session -> [Admin_DB (5.0)]
    graph = {
        "Anonymous": [("Docs", 0.5), ("Login", 2.0)],
        "Docs": [("Leaked_Token", 1.0)],
        "Login": [("User_Session", 1.0)],
        "Leaked_Token": [("Admin_DB", 1.0)],
        "User_Session": [("Admin_DB", 5.0)],
    }

    cost, path = AttackChainComposer.search_shortest_attack_path(graph, "Anonymous", "Admin_DB")
    assert cost == 2.5  # Anonymous (0.5) -> Docs (1.0) -> Leaked_Token (1.0) -> Admin_DB
    assert path == ["Anonymous", "Docs", "Leaked_Token", "Admin_DB"]


# =========================================================================
# 4. Mutation Grammar Engine Tests
# =========================================================================

def test_mutation_grammar_financial_value_classes():
    mutations = MutationGrammarEngine.generate_mutations("FINANCIAL_VALUE", original_value=50.0)
    values = [m.mutated_value for m in mutations]

    assert -1 in values
    assert 0 in values
    assert 2147483648 in values
    assert any(m.category == MutationCategory.NEGATIVE_ARITHMETIC for m in mutations)


def test_mutation_grammar_identity_reference_classes():
    mutations = MutationGrammarEngine.generate_mutations("IDENTITY_REFERENCE", original_value=1)
    values = [m.mutated_value for m in mutations]

    assert 2 in values  # Sequential step +1
    assert "null" in values
    assert "1' OR '1'='1" in values


def test_mutation_grammar_role_and_redirect_classes():
    role_muts = MutationGrammarEngine.generate_mutations("ROLE_FLAG")
    assert any(m.mutated_value == "admin" for m in role_muts)
    assert any(m.mutated_value is True for m in role_muts)

    redir_muts = MutationGrammarEngine.generate_mutations("REDIRECT_TARGET")
    assert any(m.mutated_value == "//evil-attacker.com" for m in redir_muts)
    assert any("%0d%0a" in str(m.mutated_value) for m in redir_muts)


# =========================================================================
# 5. Protocol State Machine Learner Tests
# =========================================================================

def test_protocol_state_learner_illegal_jump_detection():
    learner = ProtocolStateLearner()

    # Simulator allows jumping from CREATED to FULFILLED directly
    def sim_jump(from_st, to_st, act):
        return {"status": 200, "transition_success": True}

    violation = learner.test_illegal_step_jump(
        current_state="CREATED",
        attempted_target_state="FULFILLED",
        action="FORCE_FULFILL",
        dispatch_fn=sim_jump
    )

    assert violation is not None
    assert violation.violation_class == StateViolationClass.ILLEGAL_STEP_JUMP
    assert "CREATED to FULFILLED" in violation.evidence_proof


def test_protocol_state_learner_session_rotation_check():
    learner = ProtocolStateLearner()

    # Old token still valid post logout
    def sim_stale_probe(token):
        return {"status": 200, "is_revoked": False}

    violation = learner.test_session_rotation_consistency("stale_jwt_token", sim_stale_probe)
    assert violation is not None
    assert violation.violation_class == StateViolationClass.STALE_SESSION_REUSE


# =========================================================================
# 6. Dynamic Security Invariant Discovery Tests
# =========================================================================

def test_dynamic_invariant_discovery_from_traffic():
    discoverer = DynamicInvariantDiscoverer()
    discoverer.observe_workflow_sequence("OrderProcessing", ["CREATED", "PAID", "SHIPPED", "DELIVERED"])

    assert len(discoverer.inferred_invariants) == 1
    inv = discoverer.inferred_invariants[0]
    assert inv.resource_type == "OrderProcessing"
    assert inv.observed_precondition == "DELIVERED"
    assert inv.prohibited_postcondition == "CREATED"


def test_dynamic_invariant_violation_verification():
    discoverer = DynamicInvariantDiscoverer()
    discoverer.observe_workflow_sequence("OrderProcessing", ["CREATED", "PAID", "SHIPPED", "DELIVERED"])
    inv = discoverer.inferred_invariants[0]

    # Application allows reverting delivered order back to created state
    def sim_reversal(from_st, to_st):
        return {"success": True}

    tested_inv = discoverer.test_inferred_invariant(inv.invariant_id, sim_reversal)
    assert tested_inv.tested is True
    assert tested_inv.is_breached is True
    assert "State reversal proven" in tested_inv.evidence_proof


# =========================================================================
# 7. 'Why Not?' Negative Proof Engine Tests
# =========================================================================

def test_why_not_engine_negative_proof_accounting():
    engine = WhyNotEngine()
    rec = engine.record_negative_proof(
        endpoint="/api/v1/transfers",
        vuln_class="BOLA",
        tested_identities=["user_a", "user_b", "anonymous"],
        total_probes=12,
        rejections=12,
        negative_control_verified=True,
        private_data_leaked=False,
        coverage=100.0
    )

    assert rec.coverage_percentage == 100.0
    assert rec.probes_rejected_strictly == 12
    assert "zero sensitive data leakage" in rec.reason_no_finding


def test_why_not_engine_coverage_audit():
    engine = WhyNotEngine()
    engine.record_negative_proof(
        endpoint="/api/orders",
        vuln_class="SQLI",
        tested_identities=["anonymous"],
        total_probes=10,
        rejections=10,
        negative_control_verified=True,
        coverage=85.0
    )

    rec = engine.get_negative_proof("/api/orders", "SQLI")
    assert rec is not None
    assert rec.coverage_percentage == 85.0


# =========================================================================
# 8. Metamorphic Security Inconsistency Tests
# =========================================================================

def test_metamorphic_engine_parameter_order_invariance():
    engine = MetamorphicEngine()

    # Invariant: Both orders are denied (403)
    def consistent_request(p):
        return {"status": 403}

    report = engine.test_parameter_order_invariance("/api/search", {"q": "test", "role": "user"}, consistent_request)
    assert report is None  # Consistent behavior, no anomaly


def test_metamorphic_engine_security_inconsistency_detection():
    engine = MetamorphicEngine()

    # Inconsistent: First key blocked, reversed key allowed
    def inconsistent_request(p):
        first_key = list(p.keys())[0]
        return {"status": 403 if first_key == "role" else 200}

    report = engine.test_parameter_order_invariance("/api/admin", {"role": "admin", "action": "view"}, inconsistent_request)
    assert report is not None
    assert report.relation_type == MetamorphicRelationType.PARAMETER_ORDER_SHUFFLE
    assert "Security Inconsistency" in report.inconsistency_rationale


def test_metamorphic_engine_encoding_equivalence_invariance():
    engine = MetamorphicEngine()

    # Raw payload blocked by WAF (403), URL-encoded payload accepted (200)
    def encoding_request(p):
        return {"status": 200 if "%2e%2e" in p else 403}

    report = engine.test_encoding_equivalence_invariance("/download", "../etc/passwd", "%2e%2e/etc/passwd", encoding_request)
    assert report is not None
    assert report.relation_type == MetamorphicRelationType.URL_ENCODING_EQUIVALENCE
    assert report.severity == "CRITICAL"


# =========================================================================
# 9. Experiment Notebook & Failure Intelligence Tests
# =========================================================================

def test_experiment_notebook_logging_and_failure_intelligence():
    nb = ExperimentNotebook()

    nb.record_experiment(
        hypothesis="SQL_INJECTION",
        endpoint="/api/search",
        technique="UNION_SELECT_ALL",
        probes_sent=5,
        outcome="BLOCKED_BY_WAF",
        lessons="Cloudflare WAF strictly blocks UNION SELECT patterns on /api/search"
    )

    assert nb.is_technique_suppressed("/api/search", "UNION_SELECT_ALL") is True
    assert nb.is_technique_suppressed("/api/search", "TIME_BASED_SLEEP") is False

    summary = nb.get_summary()
    assert summary["total_experiments"] == 1
    assert summary["suppressed_techniques_count"] == 1


# =========================================================================
# 10. Self-Generated Tests & Brain Integration Tests
# =========================================================================

def test_self_generated_test_synthesizer_code_emission():
    code = SelfGeneratedTestSynthesizer.synthesize_pytest_code(
        test_name="coupon_post_refund_reuse",
        endpoint="https://target.local/api/coupon/redeem",
        method="POST",
        exploit_payload={"coupon": "VIP50", "order_id": "ORD-123"},
        expected_secure_status=403,
        vulnerability_title="Single-Use Coupon Replay Post Refund"
    )

    assert "def test_regression_coupon_post_refund_reuse():" in code
    assert "assert response.status_code == 403" in code
    assert "ORD-123" in code


def test_autonomous_brain_v25_engines_attachment():
    brain = AutonomousBrain(resource_manager=MagicMock(), tool_manager=MagicMock(), dry_run=True)
    assert brain.application_twin is not None
    assert brain.target_contradiction_engine is not None
    assert brain.attack_chain_composer is not None
    assert brain.mutation_grammar is not None
    assert brain.protocol_state_learner is not None
    assert brain.dynamic_invariant_discoverer is not None
    assert brain.why_not_engine is not None
    assert brain.metamorphic_engine is not None
    assert brain.experiment_notebook is not None
    assert brain.test_synthesizer is not None
