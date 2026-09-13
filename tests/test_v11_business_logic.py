"""
HunterAI V11.0 Business Logic & Workflow Invariant Engine Test Suite
===================================================================
Verifies:
1. Multi-Step Workflow Graph & Step Skipping Detection
2. Valid Multi-Step Sequential Execution (Zero False Positives)
3. Non-Idempotent Step Re-entrancy / Replay Vulnerability Detection
4. Identity & Password Recovery OTP Step Bypasses
5. Concurrency & TOCTOU Auditing (Missing Idempotency-Key & Check-Then-Act)
6. Safe Deterministic Concurrency Burst Simulation (Exploit vs Protected)
7. AST Workflow Step Guard and Idempotency Remediation Synthesis
"""
import pytest
from core.statemachine.workflow_engine import (
    WorkflowGraph,
    WorkflowStep,
    WorkflowFlawType,
    WorkflowAuditor,
    create_standard_checkout_workflow,
    create_standard_password_reset_workflow,
)
from core.statemachine.concurrency_auditor import (
    ConcurrencyAuditor,
    ConcurrencyRiskLevel,
    TOCTOUHazardType,
)
from core.remediation.workflow_remediation import (
    WorkflowRemediationEngine,
    WorkflowRemediationRequest,
)


def test_standard_checkout_workflow_step_skipping():
    graph = create_standard_checkout_workflow()
    auditor = WorkflowAuditor(graph)

    # Attack: Client jumps from Add to Cart directly to Order Confirmation
    adversarial_trace = [
        {"step_id": "STEP_ADD_CART", "route": "/api/cart/add", "status_code": 200},
        {"step_id": "STEP_ORDER_COMPLETE", "route": "/api/order/complete", "status_code": 200},
    ]

    flaws = auditor.audit_trace(adversarial_trace)
    assert len(flaws) >= 1

    # Check for Step Skipping Flaw
    skip_flaw = next((f for f in flaws if f.flaw_type == WorkflowFlawType.STEP_SKIPPING), None)
    assert skip_flaw is not None
    assert skip_flaw.step_id == "STEP_ORDER_COMPLETE"
    assert skip_flaw.severity == "CRITICAL"
    assert "STEP_PAYMENT" in skip_flaw.description
    assert skip_flaw.cwe_id == "CWE-841"

    # Check that payment invariant was also triggered
    inv_flaw = next((f for f in flaws if f.flaw_type == WorkflowFlawType.PARAMETER_TAMPERING), None)
    assert inv_flaw is not None
    assert "payment_must_precede_confirmation" in inv_flaw.description


def test_valid_checkout_workflow_zero_false_positives():
    graph = create_standard_checkout_workflow()
    auditor = WorkflowAuditor(graph)

    # Legitimate customer journey following all prescribed steps
    legitimate_trace = [
        {"step_id": "STEP_ADD_CART", "route": "/api/cart/add", "status_code": 200},
        {"step_id": "STEP_APPLY_DISCOUNT", "route": "/api/cart/coupon", "status_code": 200},
        {"step_id": "STEP_SHIPPING", "route": "/api/checkout/shipping", "status_code": 200},
        {"step_id": "STEP_PAYMENT", "route": "/api/checkout/pay", "status_code": 200},
        {"step_id": "STEP_ORDER_COMPLETE", "route": "/api/order/complete", "status_code": 200},
    ]

    flaws = auditor.audit_trace(legitimate_trace)
    # Must have zero flaws on compliant legitimate trace
    assert len(flaws) == 0


def test_re_entrancy_double_discount():
    graph = create_standard_checkout_workflow()
    auditor = WorkflowAuditor(graph)

    # Attack: Applying coupon twice in the same session
    replay_trace = [
        {"step_id": "STEP_ADD_CART", "route": "/api/cart/add", "status_code": 200},
        {"step_id": "STEP_APPLY_DISCOUNT", "route": "/api/cart/coupon", "status_code": 200},
        {"step_id": "STEP_APPLY_DISCOUNT", "route": "/api/cart/coupon", "status_code": 200},
    ]

    flaws = auditor.audit_trace(replay_trace)
    replay_flaw = next((f for f in flaws if f.flaw_type == WorkflowFlawType.RE_ENTRANCY), None)
    assert replay_flaw is not None
    assert replay_flaw.step_id == "STEP_APPLY_DISCOUNT"
    assert "2 times" in replay_flaw.description
    assert replay_flaw.cwe_id == "CWE-674"


def test_password_reset_workflow_otp_bypass():
    graph = create_standard_password_reset_workflow()
    auditor = WorkflowAuditor(graph)

    # Attack: User requests reset, then attempts to set new password without verifying OTP
    bypass_trace = [
        {"step_id": "STEP_REQUEST_RESET", "route": "/auth/password/reset/request", "status_code": 200},
        {"step_id": "STEP_SET_PASSWORD", "route": "/auth/password/reset/confirm", "status_code": 200},
    ]

    flaws = auditor.audit_trace(bypass_trace)
    assert len(flaws) >= 1

    skip = next(f for f in flaws if f.flaw_type == WorkflowFlawType.STEP_SKIPPING)
    assert "STEP_VERIFY_OTP" in skip.description
    assert skip.severity == "CRITICAL"


def test_concurrency_auditor_missing_idempotency():
    auditor = ConcurrencyAuditor()

    report = auditor.evaluate_endpoint(
        route="/api/v1/transfers/send",
        method="POST",
        headers={"Content-Type": "application/json"}
    )

    assert report.is_vulnerable is True
    assert report.risk_level in (ConcurrencyRiskLevel.HIGH, ConcurrencyRiskLevel.CRITICAL)
    assert TOCTOUHazardType.MISSING_IDEMPOTENCY_KEY in report.hazards_detected
    assert TOCTOUHazardType.PARALLEL_REPLAY_HAZARD in report.hazards_detected
    assert len(report.remediation_advice) >= 1
    assert "Idempotency-Key" in report.remediation_advice[0]


def test_concurrency_auditor_check_then_act_pattern():
    auditor = ConcurrencyAuditor()

    vulnerable_snippet = """
    def debit_user_account(user_id, amount):
        user = get_user(user_id)
        if user.balance >= amount:
            user.balance -= amount
            user.save()
            return True
        return False
    """

    report = auditor.evaluate_endpoint(
        route="/api/v1/wallet/debit",
        method="POST",
        source_code_snippet=vulnerable_snippet
    )

    assert report.is_vulnerable is True
    assert TOCTOUHazardType.CHECK_THEN_ACT_WINDOW in report.hazards_detected
    assert TOCTOUHazardType.UNLOCKED_RESOURCE_MUTATION in report.hazards_detected
    assert "select_for_update" in report.remediation_advice[0] or "transaction" in report.remediation_advice[0]


def test_concurrency_burst_simulation():
    auditor = ConcurrencyAuditor()

    # 1. Vulnerable execution: burst of 5 parallel debits against 100 balance
    vuln_sim = auditor.simulate_burst_race(
        endpoint="/api/v1/wallet/debit",
        initial_balance=100,
        debit_amount=100,
        concurrent_requests=5,
        has_locking=False,
        has_idempotency=False
    )
    assert vuln_sim["is_race_exploited"] is True
    assert vuln_sim["successful_debits"] > 1
    assert vuln_sim["final_balance"] < 0

    # 2. Defended with Pessimistic Locking: only 1 debit succeeds
    locked_sim = auditor.simulate_burst_race(
        endpoint="/api/v1/wallet/debit",
        initial_balance=100,
        debit_amount=100,
        concurrent_requests=5,
        has_locking=True,
        has_idempotency=False
    )
    assert locked_sim["is_race_exploited"] is False
    assert locked_sim["successful_debits"] == 1
    assert locked_sim["final_balance"] == 0

    # 3. Defended with Idempotency Key: only 1 debit succeeds
    idem_sim = auditor.simulate_burst_race(
        endpoint="/api/v1/wallet/debit",
        initial_balance=100,
        debit_amount=100,
        concurrent_requests=5,
        has_locking=False,
        has_idempotency=True
    )
    assert idem_sim["is_race_exploited"] is False
    assert idem_sim["successful_debits"] == 1
    assert idem_sim["final_balance"] == 0


def test_workflow_remediation_engine_synthesis():
    # 1. Step Skipping Remediation
    req_skip = WorkflowRemediationRequest(
        flaw_type="STEP_SKIPPING",
        route="/api/order/complete",
        file_path="checkout_views.py",
        function_name="confirm_order"
    )
    res_skip = WorkflowRemediationEngine.generate_remediation(req_skip)
    assert res_skip.flaw_type == "STEP_SKIPPING"
    assert "require_workflow_step" in res_skip.defense_middleware_code
    assert "@require_workflow_step" in res_skip.patched_endpoint_snippet
    assert "test_step_skipping_blocked" in res_skip.regression_test_code
    assert "--- a/checkout_views.py" in res_skip.git_diff

    # 2. Idempotency Remediation
    req_idem = WorkflowRemediationRequest(
        flaw_type="MISSING_IDEMPOTENCY_KEY",
        route="/api/payments/charge",
        file_path="payment_views.py",
        function_name="process_charge"
    )
    res_idem = WorkflowRemediationEngine.generate_remediation(req_idem)
    assert res_idem.flaw_type == "MISSING_IDEMPOTENCY_KEY"
    assert "Idempotency-Key" in res_idem.defense_middleware_code
    assert "test_duplicate_idempotency_key_rejected" in res_idem.regression_test_code

    # 3. Concurrency Locking Remediation
    req_lock = WorkflowRemediationRequest(
        flaw_type="CHECK_THEN_ACT_WINDOW",
        route="/api/wallet/debit",
        file_path="wallet_views.py",
        function_name="debit_wallet"
    )
    res_lock = WorkflowRemediationEngine.generate_remediation(req_lock)
    assert res_lock.flaw_type == "CHECK_THEN_ACT_WINDOW"
    assert "select_for_update" in res_lock.patched_endpoint_snippet
    assert "transaction.atomic" in res_lock.patched_endpoint_snippet
    assert "test_concurrent_debit_prevents_negative_balance" in res_lock.regression_test_code
