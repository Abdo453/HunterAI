"""
Tests for WorldModel, IdentityGraph, ApplicationStateMachine, and InvariantEngine
"""
import pytest

from hunter_ai.runtime import (
    ApplicationWorldModel, IdentityGraph, UserIdentity, ResourceObject,
    RoleLevel, ApplicationStateMachine, StateTransition,
    InvariantEngine, InvariantType, SecurityInvariant
)


# ─── 1. IdentityGraph Tests ───────────────────────────────────────────────────
class TestIdentityGraph:
    def test_identity_registration_and_authorization(self):
        graph = IdentityGraph()
        alice = graph.register_user("u1", "alice", RoleLevel.AUTHENTICATED_USER)
        bob = graph.register_user("u2", "bob", RoleLevel.AUTHENTICATED_USER)
        admin = graph.register_user("u3", "admin", RoleLevel.ADMINISTRATOR)

        obj_alice = graph.register_object("order", "ord_100", owner_user_id="u1", is_public=False)
        obj_public = graph.register_object("catalog", "cat_5", owner_user_id="u1", is_public=True)

        # Alice owns her order
        assert graph.is_authorized("u1", "ord_100") is True

        # Bob does NOT own Alice's order
        assert graph.is_authorized("u2", "ord_100") is False

        # Admin can access Alice's order
        assert graph.is_authorized("u3", "ord_100") is True

        # Public objects can be accessed by Bob
        assert graph.is_authorized("u2", "cat_5") is True

    def test_cross_tenant_pairs_generation(self):
        graph = IdentityGraph()
        graph.register_user("u1", "alice")
        graph.register_user("u2", "bob")

        graph.register_object("order", "ord_alice", owner_user_id="u1", is_public=False)
        graph.register_object("order", "ord_bob", owner_user_id="u2", is_public=False)
        graph.register_object("doc", "doc_public", owner_user_id="u1", is_public=True)

        pairs = graph.get_cross_tenant_test_pairs()
        # Bob attacking Alice's order, and Alice attacking Bob's order
        assert len(pairs) == 2
        attackers = [p[0].username for p in pairs]
        targets = [p[1].object_id for p in pairs]
        assert "alice" in attackers and "bob" in attackers
        assert "ord_alice" in targets and "ord_bob" in targets


# ─── 2. ApplicationStateMachine Tests ─────────────────────────────────────────
class TestApplicationStateMachine:
    def test_workflow_negative_sequence_generation(self):
        sm = ApplicationStateMachine()
        transitions = [
            StateTransition("CART", "CHECKOUT", "initiate_checkout", "/api/checkout"),
            StateTransition("CHECKOUT", "PAYMENT", "process_payment", "/api/pay"),
            StateTransition("PAYMENT", "ORDER_CONFIRMED", "confirm_order", "/api/confirm")
        ]
        sm.register_workflow("ecommerce_checkout", transitions)

        skipped = sm.get_skipped_step_scenarios("ecommerce_checkout")
        assert len(skipped) == 1
        assert skipped[0]["skipped_step"] == "process_payment"
        assert skipped[0]["attempted_step"] == "confirm_order"
        assert skipped[0]["target_endpoint"] == "/api/confirm"

        replayed = sm.get_replayed_step_scenarios("ecommerce_checkout")
        assert len(replayed) == 3


# ─── 3. InvariantEngine Tests ─────────────────────────────────────────────────
class TestInvariantEngine:
    def test_tenant_isolation_violation_detection(self):
        engine = InvariantEngine()
        bob = UserIdentity("u2", "bob", RoleLevel.AUTHENTICATED_USER)
        alice_order = ResourceObject(
            object_type="invoice",
            object_id="inv_999",
            owner_user_id="u1",
            is_public=False,
            attributes={"client_secret": "sec_alice_secret_token"}
        )

        # Cross-tenant request succeeded with HTTP 200 and leaked private secret
        violation = engine.evaluate_access(
            actor=bob,
            target_object=alice_order,
            endpoint="/api/invoices/inv_999",
            response_status=200,
            response_body='{"invoice_id": "inv_999", "secret": "sec_alice_secret_token"}'
        )

        assert violation is not None
        assert violation.invariant_type == InvariantType.TENANT_ISOLATION
        assert violation.confidence >= 0.9
        assert "bob" in violation.observed_behavior

    def test_tenant_isolation_legitimate_access(self):
        engine = InvariantEngine()
        alice = UserIdentity("u1", "alice", RoleLevel.AUTHENTICATED_USER)
        alice_order = ResourceObject("invoice", "inv_999", "u1", False)

        # Owner accessing own object is not a violation
        violation = engine.evaluate_access(
            actor=alice,
            target_object=alice_order,
            endpoint="/api/invoices/inv_999",
            response_status=200,
            response_body='{"invoice_id": "inv_999"}'
        )
        assert violation is None

    def test_workflow_sequence_violation_detection(self):
        engine = InvariantEngine()

        # Step succeeded (200) despite skipping payment step
        violation = engine.evaluate_workflow_sequence(
            workflow_name="checkout",
            skipped_step="process_payment",
            attempted_step="confirm_order",
            endpoint="/api/confirm",
            response_status=200,
            response_body='{"status": "ORDER_CONFIRMED"}'
        )

        assert violation is not None
        assert violation.invariant_type == InvariantType.STATE_PREREQUISITE
        assert "confirm_order" in violation.observed_behavior
        assert "process_payment" in violation.observed_behavior

    def test_workflow_sequence_enforced(self):
        engine = InvariantEngine()

        # Server correctly returned 403 Forbidden when skipping payment
        violation = engine.evaluate_workflow_sequence(
            workflow_name="checkout",
            skipped_step="process_payment",
            attempted_step="confirm_order",
            endpoint="/api/confirm",
            response_status=403,
            response_body='{"error": "Payment required"}'
        )
        assert violation is None
