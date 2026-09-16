"""
Tests for ApplicationStateMachineEngine (V27.0)
"""
import pytest
from core.reasoning.state_machine_engine import (
    ApplicationStateMachineEngine,
    ApplicationStateNode,
    EpistemicStatus,
    StateCondition,
    StateTransitionEdge,
)


def test_state_machine_initial_guest_state():
    engine = ApplicationStateMachineEngine(target_domain="shop.example.com")
    assert engine.current_state_id == "state_guest"
    assert "state_guest" in engine.states
    guest = engine.states["state_guest"]
    assert guest.name == "GUEST"
    assert guest.epistemic_status == EpistemicStatus.OBSERVED
    assert guest.confidence == 1.0


def test_state_machine_login_transition():
    engine = ApplicationStateMachineEngine(target_domain="shop.example.com")
    login_tx = {
        "tx_id": "tx_login_001",
        "url": "https://shop.example.com/api/v1/auth/login",
        "method": "POST",
        "status_code": 200,
        "req_headers": {"content-type": "application/json"},
        "resp_headers": {"set-cookie": "session_token=xyz789; Path=/; Secure; HttpOnly"},
        "resp_body": '{"token": "jwt_token_here", "user": "alice"}',
    }

    to_state, transition = engine.ingest_transaction(login_tx)
    assert to_state.name == "AUTHENTICATED"
    assert to_state.state_id == "state_authenticated"
    assert engine.current_state_id == "state_authenticated"
    assert transition is not None
    assert transition.from_state_id == "state_guest"
    assert transition.to_state_id == "state_authenticated"
    assert transition.http_method == "POST"


def test_state_machine_cart_and_checkout_progression():
    engine = ApplicationStateMachineEngine(target_domain="shop.example.com")
    # 1. Cart
    cart_tx = {
        "tx_id": "tx_cart_001",
        "url": "https://shop.example.com/cart/item/add",
        "method": "POST",
        "status_code": 200,
        "req_headers": {"cookie": "session_token=xyz"},
        "resp_headers": {},
        "resp_body": '{"item": "book", "qty": 1}',
    }
    state_cart, _ = engine.ingest_transaction(cart_tx)
    assert state_cart.name == "CART_ACTIVE"

    # 2. Checkout
    chk_tx = {
        "tx_id": "tx_chk_001",
        "url": "https://shop.example.com/checkout",
        "method": "GET",
        "status_code": 200,
        "req_headers": {"cookie": "session_token=xyz"},
        "resp_headers": {},
        "resp_body": "<html>Checkout Page</html>",
    }
    state_chk, _ = engine.ingest_transaction(chk_tx)
    assert state_chk.name == "CHECKOUT_IN_PROGRESS"

    # 3. Pay
    pay_tx = {
        "tx_id": "tx_pay_001",
        "url": "https://shop.example.com/checkout/pay",
        "method": "POST",
        "status_code": 200,
        "req_headers": {"cookie": "session_token=xyz"},
        "resp_headers": {},
        "resp_body": '{"order_id": "ORD-999", "status": "paid"}',
    }
    state_paid, _ = engine.ingest_transaction(pay_tx)
    assert state_paid.name == "ORDER_COMPLETED"


def test_detect_illegal_state_jump():
    engine = ApplicationStateMachineEngine(target_domain="shop.example.com")
    # Guest trying to jump directly to order completed
    violation = engine.detect_illegal_state_jump("state_guest", "state_order_completed", "/api/order/complete")
    assert violation is not None
    assert violation["violation"] is True
    assert "INV-BYPASS-PAYMENT" in violation["rule"]

    # Guest trying to access admin
    violation_admin = engine.detect_illegal_state_jump("state_guest", "state_privileged_admin", "/admin/dashboard")
    assert violation_admin is not None
    assert "INV-AUTH-BYPASS" in violation_admin["rule"]
