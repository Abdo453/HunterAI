"""
HunterAI V27.0 - Application State Machine Engine
=================================================
Deterministic, observation-driven application state inference.
Separates Observation from Inference:
  OBSERVED -> INFERRED -> HYPOTHESIZED -> VERIFIED -> REJECTED

The LLM is NEVER the source of truth for application state; state nodes and
transitions are strictly derived from concrete HTTP telemetry, cookies,
authentication tokens, redirects, and state mutations.
"""
from __future__ import annotations

import logging
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("hunter_ai.state_machine_engine")


class EpistemicStatus(str, Enum):
    OBSERVED = "OBSERVED"          # Directly witnessed on the wire or DOM
    INFERRED = "INFERRED"          # Logically derived from concrete evidence
    HYPOTHESIZED = "HYPOTHESIZED"  # Candidate state/transition for testing
    VERIFIED = "VERIFIED"          # Formally proven via causal experiment
    REJECTED = "REJECTED"          # Disproved via negative evidence


@dataclass
class StateCondition:
    condition_type: str            # 'cookie', 'header', 'status', 'token', 'role'
    key: str                       # e.g., 'session_id', 'Authorization'
    expected_value: str = "present"  # 'present', 'absent', or specific regex
    satisfied: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ApplicationStateNode:
    state_id: str
    name: str                      # e.g., 'GUEST', 'AUTHENTICATED', 'CHECKOUT_ACTIVE'
    epistemic_status: EpistemicStatus = EpistemicStatus.INFERRED
    evidence_refs: List[str] = field(default_factory=list)
    preconditions: List[StateCondition] = field(default_factory=list)
    postconditions: List[StateCondition] = field(default_factory=list)
    identity_context: str = "ANONYMOUS"  # 'GUEST', 'USER_A', 'USER_B', 'ADMIN'
    confidence: float = 0.80
    created_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["epistemic_status"] = self.epistemic_status.value
        return d


@dataclass
class StateTransitionEdge:
    edge_id: str
    from_state_id: str
    to_state_id: str
    action_route: str              # e.g., '/login', '/api/checkout'
    http_method: str = "GET"
    epistemic_status: EpistemicStatus = EpistemicStatus.OBSERVED
    evidence_refs: List[str] = field(default_factory=list)
    confidence: float = 0.90
    mutations_detected: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["epistemic_status"] = self.epistemic_status.value
        return d


class ApplicationStateMachineEngine:
    """
    Infers application business logic state machine from real HTTP traffic.
    Guarantees that inference != fact, maintaining strict evidence lineage.
    """

    def __init__(self, target_domain: str = "target.local"):
        self.target_domain = target_domain
        self.states: Dict[str, ApplicationStateNode] = {}
        self.transitions: List[StateTransitionEdge] = []
        self.current_state_id: str = "state_guest"
        self.state_history: List[str] = ["state_guest"]

        # Bootstrap initial baseline Guest state
        self._init_baseline_states()

    def _init_baseline_states(self):
        guest = ApplicationStateNode(
            state_id="state_guest",
            name="GUEST",
            epistemic_status=EpistemicStatus.OBSERVED,
            identity_context="GUEST",
            confidence=1.0,
            preconditions=[StateCondition(condition_type="cookie", key="session_id", expected_value="absent")],
            metadata={"description": "Unauthenticated initial visitor session"}
        )
        self.states[guest.state_id] = guest

    def ingest_transaction(self, tx: Dict[str, Any]) -> Tuple[ApplicationStateNode, Optional[StateTransitionEdge]]:
        """
        Processes an HTTP transaction and deterministically infers state progression.
        """
        tx_id = tx.get("tx_id") or tx.get("request_id") or f"tx_{uuid.uuid4().hex[:8]}"
        url = tx.get("url") or tx.get("path") or "/"
        method = (tx.get("method") or "GET").upper()
        status = int(tx.get("status_code") or tx.get("status") or 200)

        req_hdrs = {k.lower(): str(v) for k, v in tx.get("req_headers", {}).items()}
        resp_hdrs = {k.lower(): str(v) for k, v in tx.get("resp_headers", {}).items()}
        resp_body = str(tx.get("resp_body") or "")

        # 1. Detect Session Tokens
        set_cookie = resp_hdrs.get("set-cookie", "")
        req_cookie = req_hdrs.get("cookie", "")
        auth_hdr = req_hdrs.get("authorization", "")

        from_state = self.states.get(self.current_state_id, self.states["state_guest"])
        to_state: Optional[ApplicationStateNode] = None
        transition: Optional[StateTransitionEdge] = None

        # Route matching patterns
        url_lower = url.lower()

        # CASE A: Authentication Event (POST to /login, /auth, /signin)
        if any(k in url_lower for k in ("/login", "/auth", "/signin", "/token")) and method == "POST":
            if status in (200, 302) and (set_cookie or "token" in resp_body.lower() or "jwt" in resp_body.lower()):
                state_id = "state_authenticated"
                if state_id not in self.states:
                    self.states[state_id] = ApplicationStateNode(
                        state_id=state_id,
                        name="AUTHENTICATED",
                        epistemic_status=EpistemicStatus.INFERRED,
                        evidence_refs=[tx_id],
                        identity_context="AUTHENTICATED_USER",
                        confidence=0.95,
                        preconditions=[StateCondition(condition_type="cookie", key="session_token", expected_value="present")],
                        metadata={"authenticated_via": url}
                    )
                to_state = self.states[state_id]

        # CASE B: Logout / Session Revocation Event
        elif any(k in url_lower for k in ("/logout", "/signout", "/revoke", "/invalidate")):
            state_id = "state_session_revoked"
            if state_id not in self.states:
                self.states[state_id] = ApplicationStateNode(
                    state_id=state_id,
                    name="SESSION_REVOKED",
                    epistemic_status=EpistemicStatus.INFERRED,
                    evidence_refs=[tx_id],
                    identity_context="REVOKED",
                    confidence=0.90,
                    metadata={"revoked_via": url}
                )
            to_state = self.states[state_id]

        # CASE C: Cart / Work-in-Progress Action
        elif any(k in url_lower for k in ("/cart", "/basket", "/draft", "/item/add")) and method in ("POST", "PUT"):
            state_id = "state_cart_active"
            if state_id not in self.states:
                self.states[state_id] = ApplicationStateNode(
                    state_id=state_id,
                    name="CART_ACTIVE",
                    epistemic_status=EpistemicStatus.INFERRED,
                    evidence_refs=[tx_id],
                    identity_context=from_state.identity_context,
                    confidence=0.85,
                    metadata={"active_workflow": "shopping"}
                )
            to_state = self.states[state_id]

        # CASE D: Final Paid / Completed Action
        elif any(k in url_lower for k in ("/pay", "/charge", "/complete_purchase", "/finalize")) and method == "POST":
            state_id = "state_order_completed"
            if state_id not in self.states:
                self.states[state_id] = ApplicationStateNode(
                    state_id=state_id,
                    name="ORDER_COMPLETED",
                    epistemic_status=EpistemicStatus.INFERRED,
                    evidence_refs=[tx_id],
                    identity_context=from_state.identity_context,
                    confidence=0.90,
                )
            to_state = self.states[state_id]

        # CASE E: Checkout / Order In-Flight Action
        elif any(k in url_lower for k in ("/checkout", "/confirm_order", "/billing")):
            state_id = "state_checkout_in_progress"
            if state_id not in self.states:
                self.states[state_id] = ApplicationStateNode(
                    state_id=state_id,
                    name="CHECKOUT_IN_PROGRESS",
                    epistemic_status=EpistemicStatus.INFERRED,
                    evidence_refs=[tx_id],
                    identity_context=from_state.identity_context,
                    confidence=0.85,
                )
            to_state = self.states[state_id]

        # CASE F: Administrative / Privileged Endpoint
        elif "/admin" in url_lower or "/internal" in url_lower or "/manage" in url_lower:
            if status == 200:
                state_id = "state_privileged_admin"
                if state_id not in self.states:
                    self.states[state_id] = ApplicationStateNode(
                        state_id=state_id,
                        name="PRIVILEGED_ADMIN",
                        epistemic_status=EpistemicStatus.INFERRED,
                        evidence_refs=[tx_id],
                        identity_context="ADMIN",
                        confidence=0.95,
                    )
                to_state = self.states[state_id]

        # Default fallback: maintain current state with updated evidence
        if not to_state:
            to_state = from_state
            if tx_id not in to_state.evidence_refs:
                to_state.evidence_refs.append(tx_id)
        else:
            if to_state.state_id != from_state.state_id:
                edge_id = f"trans_{from_state.state_id}_to_{to_state.state_id}_{len(self.transitions)+1}"
                transition = StateTransitionEdge(
                    edge_id=edge_id,
                    from_state_id=from_state.state_id,
                    to_state_id=to_state.state_id,
                    action_route=url,
                    http_method=method,
                    epistemic_status=EpistemicStatus.OBSERVED,
                    evidence_refs=[tx_id],
                    confidence=0.90,
                    mutations_detected={"status": status, "set_cookie": bool(set_cookie)}
                )
                self.transitions.append(transition)
                self.current_state_id = to_state.state_id
                self.state_history.append(to_state.state_id)

        return to_state, transition

    def detect_illegal_state_jump(
        self,
        candidate_from_state: str,
        candidate_to_state: str,
        action_route: str
    ) -> Optional[Dict[str, Any]]:
        """
        Identifies potential business logic sequence violations (e.g. GUEST -> ORDER_COMPLETED).
        """
        # Define known invariant illegal jumps
        illegal_patterns = [
            ("state_guest", "state_order_completed", "INV-BYPASS-PAYMENT: Guest jumping directly to completed order"),
            ("state_guest", "state_privileged_admin", "INV-AUTH-BYPASS: Unauthenticated guest accessing administrative control"),
            ("state_session_revoked", "state_authenticated", "INV-REVOKED-REUSE: Revoked session resuming privileged operations"),
            ("state_cart_active", "state_order_completed", "INV-SKIP-CHECKOUT: Order completed without checkout billing step"),
        ]

        for from_s, to_s, reason in illegal_patterns:
            if candidate_from_state == from_s and candidate_to_state == to_s:
                return {
                    "violation": True,
                    "rule": reason,
                    "from_state": candidate_from_state,
                    "to_state": candidate_to_state,
                    "action_route": action_route,
                    "suggested_hypothesis": f"Business logic sequence violation via {action_route}"
                }
        return None

    def export_graph(self) -> Dict[str, Any]:
        """Exports state graph in JSON serializable format."""
        return {
            "target_domain": self.target_domain,
            "current_state": self.current_state_id,
            "states_count": len(self.states),
            "transitions_count": len(self.transitions),
            "states": {k: v.to_dict() for k, v in self.states.items()},
            "transitions": [t.to_dict() for t in self.transitions],
            "history": self.state_history,
        }
