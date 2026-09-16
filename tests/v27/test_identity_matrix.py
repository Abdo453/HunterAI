"""
Tests for Multi-Tenant Identity Matrix (V27.0)
"""
import pytest
from core.reasoning.identity_matrix import (
    AccessOutcome,
    IdentityMatrixCell,
    IdentityMatrixEngine,
    IdentityPrincipal,
)


def test_identity_matrix_registration_and_cell_creation():
    engine = IdentityMatrixEngine()

    p_alice = IdentityPrincipal(
        principal_id="alice",
        tenant_id="tenant_alpha",
        role="MEMBER",
        session_token="token_alice_123",
        resource_ownership={"doc_alice_1", "invoice_alice_99"},
    )
    p_bob = IdentityPrincipal(
        principal_id="bob",
        tenant_id="tenant_beta",
        role="MEMBER",
        session_token="token_bob_456",
        resource_ownership={"doc_bob_1"},
    )

    engine.register_principal(p_alice)
    engine.register_principal(p_bob)

    # Legitimate owner cells must be ALLOWED
    assert engine.grid[("alice", "doc_alice_1")].outcome == AccessOutcome.ALLOWED
    assert engine.grid[("bob", "doc_bob_1")].outcome == AccessOutcome.ALLOWED

    # Cross-tenant / cross-principal cells must be CANDIDATE ('?')
    assert engine.grid[("alice", "doc_bob_1")].outcome == AccessOutcome.CANDIDATE
    assert engine.grid[("bob", "doc_alice_1")].outcome == AccessOutcome.CANDIDATE


def test_identity_matrix_generate_candidate_experiments():
    engine = IdentityMatrixEngine()

    p_user = IdentityPrincipal(
        principal_id="user_1",
        tenant_id="tenant_1",
        role="MEMBER",
        session_token="user_tok",
        resource_ownership={"res_user_1"},
    )
    p_admin = IdentityPrincipal(
        principal_id="admin_1",
        tenant_id="tenant_1",
        role="ADMIN",
        session_token="admin_tok",
        resource_ownership={"res_admin_config"},
    )
    p_cross_tenant = IdentityPrincipal(
        principal_id="tenant2_user",
        tenant_id="tenant_2",
        role="MEMBER",
        session_token="t2_tok",
        resource_ownership={"res_tenant2_vault"},
    )

    engine.register_principal(p_user)
    engine.register_principal(p_admin)
    engine.register_principal(p_cross_tenant)

    candidates = engine.generate_candidate_experiments()
    categories = [c["category"] for c in candidates]

    assert "VERTICAL_PRIVILEGE_ESCALATION" in categories
    assert "CROSS_TENANT_ISOLATION_BREACH" in categories

    for c in candidates:
        assert "expected_negative_observable" in c
        assert "HTTP 403 Forbidden" in c["expected_negative_observable"]


def test_identity_matrix_verdict_update():
    engine = IdentityMatrixEngine()
    p_alice = IdentityPrincipal(principal_id="alice", tenant_id="t1", resource_ownership={"doc_1"})
    p_bob = IdentityPrincipal(principal_id="bob", tenant_id="t2", resource_ownership={"doc_2"})

    engine.register_principal(p_alice)
    engine.register_principal(p_bob)

    # Bob attempts to access Alice's document -> 403 verified
    engine.update_verdict(
        actor_id="bob",
        resource_id="doc_1",
        outcome=AccessOutcome.DENIED,
        evidence_id="ev_403_confirmed",
        reason="Server returned 403 Forbidden",
    )
    assert engine.grid[("bob", "doc_1")].outcome == AccessOutcome.DENIED

    summary = engine.export_matrix_summary()
    assert summary["metrics"]["verified_denied"] == 1
