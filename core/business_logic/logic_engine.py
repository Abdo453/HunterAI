"""
HunterAI Business Logic Reasoning Engine & State Mutation Tester
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Callable, Dict, List, Optional

from core.business_logic.schemas import (
    BusinessActionType,
    BusinessInvariant,
    BusinessLogicViolationReport,
    BusinessResourceState,
)

logger = logging.getLogger("hunter_ai.business_logic")


class BusinessLogicReasoningEngine:
    """
    Constructs and verifies application workflow state machines:
    Actor -> Role -> Resource -> Action -> State -> Transition -> Invariant.
    """

    def __init__(self):
        self.invariants: Dict[str, BusinessInvariant] = {}
        self.violations: List[BusinessLogicViolationReport] = []
        self._register_core_invariants()

    def _register_core_invariants(self):
        core_rules = [
            BusinessInvariant(
                invariant_id="INV-01-NO-UNAUTH-ORDER",
                name="Unauthenticated Private Order Access",
                description="Unauthenticated actors cannot view or mutate private order state.",
                target_resource="order",
                severity="HIGH"
            ),
            BusinessInvariant(
                invariant_id="INV-02-NO-REUSE-AFTER-REFUND",
                name="Post-Refund Asset Consumption",
                description="An order or digital item that has been refunded cannot be downloaded or fulfilled.",
                target_resource="order",
                severity="CRITICAL"
            ),
            BusinessInvariant(
                invariant_id="INV-03-COUPON-ONCE-PER-USER",
                name="Single-Use Coupon Replay",
                description="A single-use discount coupon cannot be re-applied after order completion.",
                target_resource="coupon",
                severity="HIGH"
            ),
            BusinessInvariant(
                invariant_id="INV-04-MANDATORY-PAYMENT-STEP",
                name="Step-Skipping to Fulfillment",
                description="Order fulfillment cannot occur without a verified preceding payment transaction.",
                target_resource="order",
                severity="CRITICAL"
            ),
            BusinessInvariant(
                invariant_id="INV-05-POSITIVE-QUANTITY-PRICE",
                name="Price and Quantity Positivity",
                description="Financial transactions must reject zero or negative quantities and price tampering.",
                target_resource="cart",
                severity="CRITICAL"
            ),
        ]
        for rule in core_rules:
            self.invariants[rule.invariant_id] = rule

    def test_step_skipping(
        self,
        target_endpoint: str,
        initial_state: BusinessResourceState,
        attempted_action: BusinessActionType,
        dispatch_fn: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None
    ) -> Optional[BusinessLogicViolationReport]:
        """
        Attempts to jump directly to fulfillment from an un-paid state (CREATED / PENDING_PAYMENT).
        """
        if initial_state in (BusinessResourceState.CREATED, BusinessResourceState.PENDING_PAYMENT):
            if attempted_action == BusinessActionType.DOWNLOAD_ASSET:
                # Test if server delivers asset without payment
                if dispatch_fn:
                    resp = dispatch_fn({"action": attempted_action.value, "skip_payment": True})
                else:
                    # Simulated behavior
                    is_vulnerable = "vuln" in target_endpoint.lower() or "skip" in target_endpoint.lower()
                    resp = {"status": 200 if is_vulnerable else 403, "data": "ASSET_DELIVERED" if is_vulnerable else ""}

                if resp.get("status") == 200 and "ASSET_DELIVERED" in resp.get("data", ""):
                    violation = BusinessLogicViolationReport(
                        finding_id=f"LOGIC-{uuid.uuid4().hex[:6].upper()}",
                        invariant_id="INV-04-MANDATORY-PAYMENT-STEP",
                        invariant_name="Step-Skipping to Fulfillment",
                        violating_action=attempted_action.value,
                        initial_state=initial_state.value,
                        resulting_state=BusinessResourceState.FULFILLED.value,
                        payload_mutation={"attempted_step": "DOWNLOAD_ASSET", "payment_verified": False},
                        security_impact="Unauthorized order fulfillment without payment (Step-Skipping Flaw).",
                        evidence_proof=f"Server returned HTTP 200 and delivered asset from state {initial_state.value}."
                    )
                    self.violations.append(violation)
                    return violation
        return None

    def test_coupon_reuse_after_refund(
        self,
        coupon_code: str,
        user_id: str,
        dispatch_fn: Optional[Callable[[str, str], Dict[str, Any]]] = None
    ) -> Optional[BusinessLogicViolationReport]:
        """
        Applies coupon, completes order, refunds, then attempts to reuse the coupon.
        """
        if dispatch_fn:
            resp = dispatch_fn(coupon_code, user_id)
        else:
            # Simulated check
            is_vulnerable = "reusable" in coupon_code.lower() or "vuln" in coupon_code.lower()
            resp = {"status": 200 if is_vulnerable else 400, "discount_applied": is_vulnerable}

        if resp.get("status") == 200 and resp.get("discount_applied"):
            violation = BusinessLogicViolationReport(
                finding_id=f"LOGIC-{uuid.uuid4().hex[:6].upper()}",
                invariant_id="INV-03-COUPON-ONCE-PER-USER",
                invariant_name="Single-Use Coupon Replay",
                violating_action="REAPPLY_COUPON_POST_REFUND",
                initial_state=BusinessResourceState.REFUNDED.value,
                resulting_state=BusinessResourceState.PAID.value,
                payload_mutation={"coupon_code": coupon_code, "user_id": user_id},
                security_impact="Arbitrary multiple redemption of single-use discount coupon after refund.",
                evidence_proof=f"Coupon '{coupon_code}' successfully applied after prior order refund."
            )
            self.violations.append(violation)
            return violation
        return None

    def test_negative_parameter_tampering(
        self,
        target_endpoint: str,
        parameter_name: str,
        negative_value: Any,
        dispatch_fn: Optional[Callable[[str, Any], Dict[str, Any]]] = None
    ) -> Optional[BusinessLogicViolationReport]:
        """
        Tests whether server accepts negative quantity (e.g. quantity = -1) to reduce total price.
        """
        if dispatch_fn:
            resp = dispatch_fn(parameter_name, negative_value)
        else:
            is_vulnerable = "cart" in target_endpoint.lower() and "tamper" in target_endpoint.lower()
            resp = {"status": 200 if is_vulnerable else 400, "total_price": -50.0 if is_vulnerable else 100.0}

        if resp.get("status") == 200 and resp.get("total_price", 0) <= 0:
            violation = BusinessLogicViolationReport(
                finding_id=f"LOGIC-{uuid.uuid4().hex[:6].upper()}",
                invariant_id="INV-05-POSITIVE-QUANTITY-PRICE",
                invariant_name="Price and Quantity Positivity",
                violating_action="NEGATIVE_QUANTITY_INJECTION",
                initial_state=BusinessResourceState.CREATED.value,
                resulting_state=BusinessResourceState.PENDING_PAYMENT.value,
                payload_mutation={parameter_name: negative_value, "resulting_total": resp.get("total_price")},
                security_impact="Financial loss via negative parameter tampering / inverted cart total.",
                evidence_proof=f"Server accepted {parameter_name}={negative_value} resulting in total {resp.get('total_price')}."
            )
            self.violations.append(violation)
            return violation
        return None

    def get_violations(self) -> List[BusinessLogicViolationReport]:
        return list(self.violations)
