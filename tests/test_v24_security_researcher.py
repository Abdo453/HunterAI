# -*- coding: utf-8 -*-
"""
HunterAI V24.0 Security Researcher Test Suite
============================================
Comprehensive test suite verifying:
1. IdentityGraph & MultiIdentityReplayer (BOLA, BFLA, Cross-Tenant, Unauth Leak)
2. BusinessLogicReasoningEngine (Invariants, Step-Skipping, Post-Refund Reuse, Price/Qty Tampering)
3. RaceConditionEngine (Burst requests, Double-Spend, Coupon concurrency)
4. SemanticParameterAnalyzer & AttackOpportunityGraph (Parameter semantics, Multi-vector opportunities)
5. AdversarialEvidenceProsecutor (Counter-theories, Rebuttals, Concession vs Objection Sustained)
6. AutonomousBrain integration
"""
import pytest
from unittest.mock import MagicMock

from core.identity import (
    IdentityGraph,
    IdentityContext,
    MultiIdentityReplayer,
    AuthZAnomalyType,
)
from core.business_logic import (
    BusinessLogicReasoningEngine,
    BusinessInvariant,
    BusinessResourceState,
    BusinessActionType,
)
from core.concurrency import (
    RaceConditionEngine,
    RaceTargetType,
)
from core.opportunity import (
    AttackOpportunityGraph,
    SemanticParameterAnalyzer,
    SemanticParameterRole,
)
from core.court.adversarial_prosecutor import (
    AdversarialEvidenceProsecutor,
    CounterTheoryType,
)
from core.brain.autonomous_brain import AutonomousBrain


# =========================================================================
# 1. Identity Graph & Multi-Identity Replayer Tests
# =========================================================================

def test_identity_graph_registration_and_contexts():
    graph = IdentityGraph()
    identities = graph.list_identities()
    assert len(identities) >= 4  # anonymous, user_a, user_b, admin
    
    anon = graph.get_identity("anonymous")
    assert anon is not None
    assert anon.is_anonymous()

    admin = graph.get_identity("admin")
    assert admin is not None
    assert admin.is_admin()

    user_a = graph.get_identity("user_a")
    assert user_a.tenant_id == "tenant_alpha"


def test_multi_identity_replayer_horizontal_privesc_detection():
    graph = IdentityGraph()
    replayer = MultiIdentityReplayer(graph)

    # Simulator where user_b accessing user_a's order returns the data without 403
    def leaky_simulator(obj_id, ident: IdentityContext):
        return {
            "status": 200,
            "body": f'{{"order_id": "{obj_id}", "owner": "user_a", "secret_data": "CONFIDENTIAL"}}',
            "private_data": ["CONFIDENTIAL", obj_id]
        }

    results = replayer.replay_authorization_matrix(
        endpoint="https://api.target.local/api/v1/orders/1337",
        method="GET",
        target_object_id="order_1337",
        owner_identity_id="user_a",
        simulator_fn=leaky_simulator
    )

    user_b_res = next((r for r in results if r.tested_identity == "user_b"), None)
    assert user_b_res is not None
    assert user_b_res.is_anomaly is True
    assert user_b_res.anomaly_type in (AuthZAnomalyType.CROSS_TENANT_BREACH, AuthZAnomalyType.BOLA_HORIZONTAL_ACCESS)
    assert user_b_res.sensitive_data_leaked is True


def test_multi_identity_replayer_vertical_privesc_detection():
    graph = IdentityGraph()
    replayer = MultiIdentityReplayer(graph)

    def admin_endpoint_simulator(obj_id, ident: IdentityContext):
        # Non-admin user accessing admin endpoint returns 200
        return {"status": 200, "body": '{"admin_setting": "modified"}', "private_data": []}

    results = replayer.replay_authorization_matrix(
        endpoint="https://api.target.local/api/v1/admin/users/42",
        method="POST",
        target_object_id="user_42",
        owner_identity_id="admin",
        simulator_fn=admin_endpoint_simulator
    )

    user_a_res = next((r for r in results if r.tested_identity == "user_a"), None)
    assert user_a_res is not None
    assert user_a_res.is_anomaly is True
    assert user_a_res.anomaly_type == AuthZAnomalyType.BFLA_VERTICAL_PRIVILEGE_ESCALATION


def test_multi_identity_unauth_leak_detection():
    graph = IdentityGraph()
    replayer = MultiIdentityReplayer(graph)

    def unauth_leak_simulator(obj_id, ident: IdentityContext):
        if ident.is_anonymous() or ident.identity_id == "user_a":
            return {"status": 200, "body": '{"invoice_id": "INV-99", "secret_data": "LEAKED_SECRET"}', "private_data": ["LEAKED_SECRET"]}
        return {"status": 200, "body": '{"invoice_id": "INV-99"}', "private_data": []}

    results = replayer.replay_authorization_matrix(
        endpoint="https://api.target.local/api/invoices/INV-99",
        method="GET",
        target_object_id="INV-99",
        owner_identity_id="user_a",
        simulator_fn=unauth_leak_simulator
    )

    anon_res = next((r for r in results if r.tested_identity == "anonymous"), None)
    assert anon_res is not None
    assert anon_res.is_anomaly is True
    assert anon_res.anomaly_type == AuthZAnomalyType.UNAUTHENTICATED_INFORMATION_LEAK


def test_multi_identity_shield_on_public_page():
    graph = IdentityGraph()
    replayer = MultiIdentityReplayer(graph)

    # Public page returns 200 for everyone without private data
    def public_page_simulator(obj_id, ident: IdentityContext):
        return {"status": 200, "body": '{"title": "Welcome to Public Store"}', "private_data": ["MY_SECRET_ORDER"]}

    results = replayer.replay_authorization_matrix(
        endpoint="https://api.target.local/about",
        method="GET",
        target_object_id="store_page",
        owner_identity_id="user_a",
        simulator_fn=public_page_simulator
    )

    # None should be flagged as an anomaly because private data did NOT leak
    assert all(not r.is_anomaly for r in results)


# =========================================================================
# 2. Business Logic Reasoning Engine Tests
# =========================================================================

def test_business_logic_invariants_registration():
    engine = BusinessLogicReasoningEngine()
    assert len(engine.invariants) >= 5
    assert "INV-04-MANDATORY-PAYMENT-STEP" in engine.invariants
    assert "INV-03-COUPON-ONCE-PER-USER" in engine.invariants


def test_business_logic_step_skipping_detection():
    engine = BusinessLogicReasoningEngine()
    
    # Target endpoint allows downloading asset from CREATED state without payment
    violation = engine.test_step_skipping(
        target_endpoint="https://store.local/api/orders/download_skip",
        initial_state=BusinessResourceState.CREATED,
        attempted_action=BusinessActionType.DOWNLOAD_ASSET
    )

    assert violation is not None
    assert violation.invariant_id == "INV-04-MANDATORY-PAYMENT-STEP"
    assert violation.resulting_state == BusinessResourceState.FULFILLED.value
    assert "Step-Skipping" in violation.security_impact


def test_business_logic_coupon_reuse_after_refund():
    engine = BusinessLogicReasoningEngine()
    
    # Server accepts coupon after order was refunded
    violation = engine.test_coupon_reuse_after_refund(
        coupon_code="REUSABLE_VIP50",
        user_id="user_123"
    )

    assert violation is not None
    assert violation.invariant_id == "INV-03-COUPON-ONCE-PER-USER"
    assert violation.initial_state == BusinessResourceState.REFUNDED.value


def test_business_logic_negative_parameter_tampering():
    engine = BusinessLogicReasoningEngine()

    # Negative quantity inverts price or makes cart negative
    violation = engine.test_negative_parameter_tampering(
        target_endpoint="https://store.local/api/cart/tamper",
        parameter_name="quantity",
        negative_value=-5
    )

    assert violation is not None
    assert violation.invariant_id == "INV-05-POSITIVE-QUANTITY-PRICE"
    assert "Financial loss" in violation.security_impact


# =========================================================================
# 3. Race Condition & Concurrency Engine Tests
# =========================================================================

def test_race_condition_engine_double_spend_detection():
    engine = RaceConditionEngine()

    # Endpoint vulnerable to parallel overdraw
    finding = engine.execute_financial_race(
        endpoint="https://api.target.local/api/wallet/debit_race",
        initial_balance=100.0,
        debit_amount=60.0,
        concurrency=5
    )

    assert finding.is_race_confirmed is True
    assert finding.successful_requests_count == 5
    assert finding.post_race_state["balance"] < 0
    assert "Double-spend proven" in finding.evidence_proof


def test_race_condition_coupon_concurrency_detection():
    engine = RaceConditionEngine()

    finding = engine.execute_coupon_race(
        endpoint="https://api.target.local/api/coupon/redeem_race",
        coupon_code="SINGLE_USE_50",
        concurrency=5
    )

    assert finding.is_race_confirmed is True
    assert finding.successful_requests_count > 1
    assert finding.state_mutation_delta["duplicate_redemptions"] > 0


# =========================================================================
# 4. Semantic Parameter Analyzer & Opportunity Graph Tests
# =========================================================================

def test_semantic_parameter_analyzer_classification():
    p_price = SemanticParameterAnalyzer.analyze_parameter("subtotal_price")
    assert p_price.semantic_role == SemanticParameterRole.FINANCIAL_VALUE
    assert "PRICE_TAMPERING" in p_price.risk_hypotheses

    p_qty = SemanticParameterAnalyzer.analyze_parameter("item_quantity")
    assert p_qty.semantic_role == SemanticParameterRole.FINANCIAL_VALUE
    assert "NEGATIVE_QUANTITY" in p_qty.risk_hypotheses

    p_id = SemanticParameterAnalyzer.analyze_parameter("account_id")
    assert p_id.semantic_role == SemanticParameterRole.IDENTITY_REFERENCE
    assert "BOLA_IDOR" in p_id.risk_hypotheses

    p_role = SemanticParameterAnalyzer.analyze_parameter("is_admin")
    assert p_role.semantic_role == SemanticParameterRole.ROLE_FLAG
    assert "MASS_ASSIGNMENT" in p_role.risk_hypotheses


def test_attack_opportunity_graph_derivation():
    graph = AttackOpportunityGraph()
    opps = graph.derive_opportunities_for_endpoint(
        endpoint="/api/v1/orders/1337",
        method="PUT",
        parameters=["id", "price", "role", "redirect_url"]
    )

    assert len(opps) >= 4
    vectors = [o.vuln_vector for o in opps]
    assert "BOLA_IDOR" in vectors
    assert "PRICE_TAMPERING" in vectors
    assert "MASS_ASSIGNMENT" in vectors
    assert "OPEN_REDIRECT" in vectors
    # Path object ID check
    assert any("BOLA_PATH" in v for v in vectors)


# =========================================================================
# 5. Adversarial Evidence Prosecutor Tests
# =========================================================================

def test_adversarial_prosecutor_challenges_and_rebuttals():
    prosecutor = AdversarialEvidenceProsecutor()

    # Evidence with all rebuttals satisfied (sensitive data leaked, WAF clean, dynamic nonce verified)
    evidence = {
        "sensitive_data_leaked": True,
        "waf_clean": True,
        "cache_busting_verified": True
    }

    ruling = prosecutor.cross_examine_finding(
        vuln_family="Broken Object Level Authorization (BOLA)",
        endpoint="/api/orders/42",
        evidence_payload=evidence
    )

    assert ruling.all_rebutted is True
    assert ruling.prosecutor_disposition == "CONCEDED"
    assert "Prosecution Concession" in ruling.justification


def test_adversarial_prosecutor_objection_sustained_on_unrebutted_noise():
    prosecutor = AdversarialEvidenceProsecutor()

    # Generic 200 OK without sensitive data leaked
    evidence = {
        "sensitive_data_leaked": False,
        "waf_clean": True
    }

    ruling = prosecutor.cross_examine_finding(
        vuln_family="Authentication Bypass",
        endpoint="/admin/login",
        evidence_payload=evidence
    )

    assert ruling.all_rebutted is False
    assert ruling.prosecutor_disposition == "OBJECTION_SUSTAINED"
    assert "GENERIC_ERROR_200_MASK" in [c.theory_type.value for c in ruling.challenges_raised]


# =========================================================================
# 6. AutonomousBrain Integration Test
# =========================================================================

def test_autonomous_brain_researcher_engines_integration():
    brain = AutonomousBrain(resource_manager=MagicMock(), tool_manager=MagicMock(), dry_run=True)
    assert brain.identity_graph is not None
    assert brain.multi_identity_replayer is not None
    assert brain.business_logic_engine is not None
    assert brain.race_engine is not None
    assert brain.opportunity_graph is not None
    assert brain.adversarial_prosecutor is not None
