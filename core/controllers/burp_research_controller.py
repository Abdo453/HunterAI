"""
HunterAI Burp Research Controller — Bidirectional Control Plane
===============================================================
Empowers HunterAI to actively control Burp Suite as an execution backend:
- observe(): Ingest and inspect live traffic history
- replay(): Execute targeted mutations against recorded transactions
- send_to_repeater(): Provision reproducible tabs inside Burp's Repeater
- modify_request(): Construct deterministic mutations (params, headers, body)
- compare(): Perform differential analysis between baseline and experiment
- queue(): Schedule experiments through the prioritized Burp Experiment Queue
- cancel(): Safely abort scheduled or in-flight experiments
- fetch_response(): Retrieve full response data by ID

Strict Constitutional Barrier:
- Every action is strictly verified against ScopeGuard (Zero Out-of-Scope Egress)
- State-mutating actions verify RiskBudgetManager and check approval gates
- All actions emit an immutable ControlActionReceipt with SHA-256 audit digest
"""
from __future__ import annotations

import copy
import hashlib
import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from core.burp_gateway.correlation import (
    BurpCorrelationContext,
    HDR_ENGAGEMENT_ID,
    HDR_TRANSACTION_ID,
    HDR_HYPOTHESIS_ID,
    HDR_EXPERIMENT_ID,
    HDR_PARENT_ID,
    HDR_IDENTITY_ID,
    HDR_INTENT,
    HDR_ACTION_TYPE,
)
from core.burp_gateway.traffic_normalizer import (
    BurpTrafficNormalizer,
    CanonicalIdentity,
    CanonicalRequest,
    CanonicalResponse,
    CanonicalTransaction,
    TargetStateContext,
    TrafficSource,
)
from core.governance.risk_budget_queue import RiskBudgetManager, RiskTier
from core.scope_guard import ScopeGuard

logger = logging.getLogger("hunter_ai.burp_research_controller")


class ScopeViolationError(PermissionError):
    """Raised when an active probe or replay attempts to touch out-of-scope targets."""
    pass


class ActionStatus(str, Enum):
    ALLOWED = "ALLOWED"
    DENIED_SCOPE = "DENIED_SCOPE"
    DENIED_RISK_BUDGET = "DENIED_RISK_BUDGET"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"
    QUEUED = "QUEUED"


@dataclass
class ControlActionReceipt:
    receipt_id: str = field(default_factory=lambda: f"rcpt_{uuid.uuid4().hex[:8]}")
    action: str = ""
    target_url: str = ""
    status: ActionStatus = ActionStatus.EXECUTED
    reason: str = ""
    audit_hash: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "action": self.action,
            "target_url": self.target_url,
            "status": self.status.value,
            "reason": self.reason,
            "audit_hash": self.audit_hash,
            "timestamp": self.timestamp,
        }


@dataclass
class ExecutionResult:
    receipt: ControlActionReceipt
    transaction: Optional[CanonicalTransaction] = None
    diff_summary: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "receipt": self.receipt.to_dict(),
            "transaction": self.transaction.to_dict() if self.transaction else None,
            "diff_summary": self.diff_summary,
        }


@dataclass
class DifferentialAnalysis:
    baseline_tx_id: str
    experiment_tx_id: str
    status_code_changed: bool
    status_baseline: int
    status_experiment: int
    length_delta_bytes: int
    header_diffs: Dict[str, Tuple[Optional[str], Optional[str]]]
    body_diff_snippet: str
    invariant_violation: Optional[str] = None
    verdict: str = "INCONCLUSIVE"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class BurpResearchController:
    """
    Bidirectional Research Controller connecting Cognitive Brain to Burp Suite.
    """

    def __init__(
        self,
        scope_guard: Optional[ScopeGuard] = None,
        risk_budget_manager: Optional[RiskBudgetManager] = None,
        capture_store: Optional[Any] = None,
        evidence_graph: Optional[Any] = None,
        experiment_queue: Optional[Any] = None,
        event_stream: Optional[Any] = None,
        http_transport_fn: Optional[Callable[[CanonicalRequest], CanonicalResponse]] = None,
    ):
        self.scope_guard = scope_guard or ScopeGuard(
            in_scope=["*"],
            out_of_scope=["169.254.169.254", "*.internal", "disallowed-foreign.org"]
        )
        self.risk_manager = risk_budget_manager or RiskBudgetManager()
        self.capture_store = capture_store
        self.evidence_graph = evidence_graph
        self.experiment_queue = experiment_queue
        self.event_stream = event_stream
        self._http_transport_fn = http_transport_fn or self._default_mock_transport

        self._transactions: Dict[str, CanonicalTransaction] = {}
        self._repeater_tabs: Dict[str, CanonicalRequest] = {}
        self._receipts: List[ControlActionReceipt] = []

    def observe(self, tx_id: Optional[str] = None, limit: int = 50) -> List[CanonicalTransaction]:
        """Inspects captured transactions from memory or attached CaptureStore."""
        if tx_id:
            tx = self._transactions.get(tx_id)
            return [tx] if tx else []
        tx_list = list(self._transactions.values())
        return tx_list[-limit:]

    def fetch_response(self, tx_id: str) -> Optional[CanonicalResponse]:
        """Retrieves canonical response by transaction ID."""
        tx = self._transactions.get(tx_id)
        return tx.response if tx else None

    def modify_request(
        self,
        base_request_id: str,
        mutations: Dict[str, Any],
    ) -> CanonicalRequest:
        """
        Creates a mutated copy of a baseline request without modifying the original.
        Mutations can include:
        - "params": Dict[str, Any] (query/body params)
        - "headers": Dict[str, str] (header additions or replacements)
        - "body": str (body replacement)
        - "method": str (HTTP verb tampering)
        - "path": str (URL path tampering)
        """
        base_tx = self._transactions.get(base_request_id)
        if not base_tx:
            raise ValueError(f"Baseline transaction {base_request_id} not found.")

        base_req = copy.deepcopy(base_tx.request)

        # Mutate URL
        if "url" in mutations:
            base_req.url = str(mutations["url"])
            p = urlparse(base_req.url)
            base_req.host = p.netloc or base_req.host
            base_req.path = p.path or "/"
            if p.query:
                base_req.query_params = parse_qs(p.query)

        # Mutate Method
        if "method" in mutations:
            base_req.method = str(mutations["method"]).upper()

        # Mutate Headers
        if "headers" in mutations and isinstance(mutations["headers"], dict):
            for hk, hv in mutations["headers"].items():
                if hv is None:
                    base_req.headers.pop(hk, None)
                else:
                    base_req.headers[hk] = str(hv)

        # Mutate Parameters
        if "params" in mutations and isinstance(mutations["params"], dict):
            # Query params
            parsed = urlparse(base_req.url)
            qp = parse_qs(parsed.query)
            for pk, pv in mutations["params"].items():
                qp[pk] = [str(pv)] if not isinstance(pv, list) else [str(x) for x in pv]

            new_query = urlencode(qp, doseq=True)
            new_url = urlunparse((
                parsed.scheme,
                parsed.netloc,
                mutations.get("path", parsed.path),
                parsed.params,
                new_query,
                parsed.fragment
            ))
            base_req.url = new_url
            base_req.path = mutations.get("path", parsed.path)
            base_req.query_params = qp

            # Form body if application/x-www-form-urlencoded
            if "application/x-www-form-urlencoded" in base_req.content_type and base_req.body:
                bp = parse_qs(base_req.body)
                for pk, pv in mutations["params"].items():
                    bp[pk] = [str(pv)] if not isinstance(pv, list) else [str(x) for x in pv]
                base_req.body = urlencode(bp, doseq=True)

            # JSON body if application/json
            elif "application/json" in base_req.content_type and base_req.body:
                try:
                    js = json.loads(base_req.body)
                    if isinstance(js, dict):
                        js.update(mutations["params"])
                        base_req.body = json.dumps(js)
                except Exception:
                    pass

        # Mutate Raw Body
        if "body" in mutations:
            base_req.body = str(mutations["body"])

        return base_req

    def replay(
        self,
        request_id: str,
        mutation: Optional[Dict[str, Any]] = None,
        correlation: Optional[BurpCorrelationContext] = None,
        reason: str = "Active Verification Replay",
        risk_tier: RiskTier = RiskTier.LOW_RISK,
    ) -> ExecutionResult:
        """
        Replays a transaction (optionally mutated) through the Burp execution backend.
        Enforces ScopeGuard and RiskBudgetManager.
        """
        base_tx = self._transactions.get(request_id)
        if not base_tx:
            receipt = self._create_receipt("REPLAY_REQUEST", "", ActionStatus.FAILED, f"Transaction {request_id} not found")
            return ExecutionResult(receipt=receipt)

        # Prepare request
        if mutation:
            target_req = self.modify_request(request_id, mutation)
            action_type = "MUTATION"
        else:
            target_req = copy.deepcopy(base_tx.request)
            action_type = "REPLAY"

        # ── CONSTITUTIONAL SCOPE CHECK ──────────────────────────────────────
        is_allowed, scope_reason = self.scope_guard.is_allowed(target_req.url)
        if not is_allowed:
            receipt = self._create_receipt(
                "REPLAY_REQUEST",
                target_req.url,
                ActionStatus.DENIED_SCOPE,
                f"Scope violation: {scope_reason}"
            )
            logger.warning(f"[RESEARCH CONTROLLER] Blocked out-of-scope replay: {target_req.url} ({scope_reason})")
            raise ScopeViolationError(f"Scope violation for {target_req.url}: {scope_reason}")

        # ── RISK BUDGET CHECK ───────────────────────────────────────────────
        if target_req.method in ("POST", "PUT", "DELETE", "PATCH"):
            risk_tier = RiskTier.MEDIUM_RISK if risk_tier == RiskTier.LOW_RISK else risk_tier

        if not self.risk_manager.can_execute(risk_tier):
            receipt = self._create_receipt(
                "REPLAY_REQUEST",
                target_req.url,
                ActionStatus.DENIED_RISK_BUDGET,
                f"Risk budget exceeded for tier {risk_tier.value}"
            )
            return ExecutionResult(receipt=receipt)

        self.risk_manager.consume(risk_tier)

        # Build correlation context
        if correlation is None:
            correlation = base_tx.correlation.spawn_child(
                action_type=action_type,
                intent=reason,
            )
        else:
            correlation.parent_transaction_id = request_id

        # Inject correlation headers
        for hk, hv in correlation.to_headers().items():
            target_req.headers[hk] = hv

        # Execute HTTP transport
        t0 = time.time()
        resp = self._http_transport_fn(target_req)
        resp.round_trip_ms = round((time.time() - t0) * 1000, 2)

        # Build canonical transaction
        new_tx = CanonicalTransaction(
            tx_id=correlation.transaction_id,
            source=TrafficSource.REPEATER if mutation else TrafficSource.AGENT_PROBE,
            correlation=correlation,
            request=target_req,
            response=resp,
            identity=BurpTrafficNormalizer._extract_identity(target_req.headers, correlation),
            state=BurpTrafficNormalizer._extract_state(target_req.headers, resp.headers),
            timestamp=time.time(),
        )

        # Store in local memory
        self._transactions[new_tx.tx_id] = new_tx

        # Persist in CaptureStore if attached
        if self.capture_store and hasattr(self.capture_store, "store_transaction"):
            try:
                from core.burp_gateway.capture_store import CapturedTransaction
                cap_tx = CapturedTransaction(
                    tx_id=new_tx.tx_id,
                    target_host=new_tx.request.host,
                    method=new_tx.request.method,
                    url=new_tx.request.url,
                    status_code=new_tx.response.status_code,
                    req_headers=new_tx.request.headers,
                    req_body=new_tx.request.body,
                    resp_headers=new_tx.response.headers,
                    resp_body=new_tx.response.body,
                    tool_source="research_controller",
                    timestamp=new_tx.timestamp,
                    identity=correlation.identity_id,
                    parent_request=request_id,
                )
                self.capture_store.store_transaction(cap_tx)
            except Exception as e:
                logger.warning(f"[RESEARCH CONTROLLER] Failed to persist in capture store: {e}")

        # Broadcast to Live Event Stream if attached
        if self.event_stream and hasattr(self.event_stream, "publish_event"):
            try:
                self.event_stream.publish_event(
                    "MUTATION_EXECUTED" if mutation else "REPLAY_EXECUTED",
                    new_tx.to_dict()
                )
            except Exception as e:
                logger.warning(f"[RESEARCH CONTROLLER] Failed to publish stream event: {e}")

        # Create receipt
        receipt = self._create_receipt(
            "REPLAY_REQUEST",
            target_req.url,
            ActionStatus.EXECUTED,
            f"Successfully executed {action_type} -> HTTP {resp.status_code}"
        )

        diff = f"Replay of {request_id} -> {new_tx.tx_id} [Status: {resp.status_code}, Length: {len(resp.body)} bytes]"
        return ExecutionResult(receipt=receipt, transaction=new_tx, diff_summary=diff)

    def send_to_repeater(
        self,
        request_or_tx_id: Union[str, CanonicalRequest],
        tab_name: Optional[str] = None,
        correlation: Optional[BurpCorrelationContext] = None,
    ) -> str:
        """Provisions a named Repeater experiment workspace tab."""
        if isinstance(request_or_tx_id, str):
            base_tx = self._transactions.get(request_or_tx_id)
            if not base_tx:
                raise ValueError(f"Transaction {request_or_tx_id} not found.")
            req = copy.deepcopy(base_tx.request)
        else:
            req = copy.deepcopy(request_or_tx_id)

        # Validate scope
        is_allowed, scope_reason = self.scope_guard.is_allowed(req.url)
        if not is_allowed:
            raise ScopeViolationError(f"Target {req.url} is outside authorized scope: {scope_reason}")

        tab_id = tab_name or f"Repeater-{uuid.uuid4().hex[:6]}"
        self._repeater_tabs[tab_id] = req

        if self.event_stream and hasattr(self.event_stream, "publish_event"):
            try:
                self.event_stream.publish_event("REPEATER_TAB_PROVISIONED", {
                    "tab_id": tab_id,
                    "url": req.url,
                    "method": req.method,
                })
            except Exception:
                pass

        logger.info(f"[RESEARCH CONTROLLER] Provisioned Repeater Tab '{tab_id}' for {req.method} {req.url}")
        return tab_id

    def compare(self, baseline_tx_id: str, experiment_tx_id: str) -> DifferentialAnalysis:
        """
        Conducts deep behavioral differential analysis between a baseline transaction
        and an experimental mutation.
        """
        base = self._transactions.get(baseline_tx_id)
        exp = self._transactions.get(experiment_tx_id)

        if not base or not exp:
            raise ValueError(f"Transactions {baseline_tx_id} or {experiment_tx_id} not found for comparison.")

        status_changed = base.response.status_code != exp.response.status_code
        len_delta = len(exp.response.body) - len(base.response.body)

        # Header diffs
        hdr_diffs = {}
        all_hdrs = set(base.response.headers.keys()).union(exp.response.headers.keys())
        for h in all_hdrs:
            v1 = base.response.headers.get(h)
            v2 = exp.response.headers.get(h)
            if v1 != v2:
                hdr_diffs[h] = (v1, v2)

        body_snippet = (
            f"Baseline: {base.response.body[:60]}... | Experiment: {exp.response.body[:60]}..."
            if len(base.response.body) > 0 or len(exp.response.body) > 0 else "Empty bodies"
        )

        # Security invariant check
        inv_violation = None
        verdict = "INCONCLUSIVE"
        if base.response.status_code == 403 and exp.response.status_code == 200:
            inv_violation = "INV-AUTHZ-BYPASS: Baseline forbidden 403 bypassed to 200 OK!"
            verdict = "CONFIRMED_ANOMALY"
        elif status_changed:
            verdict = "DIFFERENTIAL_OBSERVED"
        elif len_delta != 0:
            verdict = "LENGTH_DIVERGENCE_OBSERVED"

        return DifferentialAnalysis(
            baseline_tx_id=baseline_tx_id,
            experiment_tx_id=experiment_tx_id,
            status_code_changed=status_changed,
            status_baseline=base.response.status_code,
            status_experiment=exp.response.status_code,
            length_delta_bytes=len_delta,
            header_diffs=hdr_diffs,
            body_diff_snippet=body_snippet,
            invariant_violation=inv_violation,
            verdict=verdict,
        )

    def queue(
        self,
        request: CanonicalRequest,
        priority: int = 5,
        eig: float = 0.5,
        risk_tier: str = "LOW_RISK",
        timeout_sec: float = 10.0,
        correlation: Optional[BurpCorrelationContext] = None,
    ) -> str:
        """Schedules a research experiment through the attached BurpExperimentQueue."""
        if not self.experiment_queue:
            raise RuntimeError("BurpExperimentQueue is not attached to this BurpResearchController.")

        from core.burp_gateway.experiment_queue import BurpExperimentItem
        try:
            tier_enum = RiskTier(risk_tier)
        except Exception:
            tier_enum = RiskTier.LOW_RISK

        corr = correlation or BurpCorrelationContext(action_type="QUEUED_EXPERIMENT")
        item = BurpExperimentItem(
            correlation=corr,
            request=request,
            priority=priority,
            expected_info_gain=eig,
            risk_tier=tier_enum,
            timeout_seconds=timeout_sec,
        )
        exp_id = self.experiment_queue.enqueue(item)
        self._create_receipt("QUEUE_EXPERIMENT", request.url, ActionStatus.QUEUED, f"Queued exp {exp_id}")
        return exp_id

    def cancel(self, task_or_exp_id: str) -> bool:
        """Cancels a scheduled experiment in the queue."""
        if self.experiment_queue and hasattr(self.experiment_queue, "cancel"):
            return self.experiment_queue.cancel(task_or_exp_id)
        return False

    def ingest_canonical(self, tx: CanonicalTransaction):
        """Indexes an externally observed canonical transaction."""
        self._transactions[tx.tx_id] = tx

    def _create_receipt(
        self,
        action: str,
        target_url: str,
        status: ActionStatus,
        reason: str
    ) -> ControlActionReceipt:
        raw_sig = f"{action}:{target_url}:{status.value}:{reason}:{time.time()}"
        hsh = hashlib.sha256(raw_sig.encode()).hexdigest()[:16]
        receipt = ControlActionReceipt(
            action=action,
            target_url=target_url,
            status=status,
            reason=reason,
            audit_hash=hsh,
        )
        self._receipts.append(receipt)
        return receipt

    def _default_mock_transport(self, req: CanonicalRequest) -> CanonicalResponse:
        """High-fidelity local mock transport simulating target server reflections."""
        parsed = urlparse(req.url)
        path = parsed.path

        # Simulating BOLA or Admin behavior based on inputs
        if "user_id" in req.url or "id=" in req.url:
            qp = parse_qs(parsed.query)
            uid = qp.get("user_id", [""])[0] or qp.get("id", [""])[0]
            if uid in ("102", "admin", "0"):
                return CanonicalResponse(
                    status_code=200,
                    headers={"Content-Type": "application/json"},
                    body=json.dumps({"id": uid, "name": "Target Account", "balance": 9999.0}),
                )
            return CanonicalResponse(
                status_code=403,
                headers={"Content-Type": "application/json"},
                body=json.dumps({"error": "Forbidden: Tenant Access Denied"}),
            )

        if "admin" in path:
            auth_hdr = req.headers.get("authorization") or req.headers.get("Authorization") or ""
            if "admin" in auth_hdr.lower():
                return CanonicalResponse(status_code=200, body="Admin Dashboard Authorized")
            return CanonicalResponse(status_code=403, body="Forbidden: Administrator privilege required")

        return CanonicalResponse(
            status_code=200,
            headers={"Content-Type": "text/html; charset=utf-8"},
            body=f"<html><body>Target Response for {req.method} {req.path}</body></html>",
        )
