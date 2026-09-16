"""
HunterAI Burp Control & Sensor Layer (BCSL)
===========================================
The official integration boundary between HunterAI Intelligence and Burp Suite:
- Validates ExperimentContract against ScopeGuard & RiskBudget
- Orchestrates request mutation and execution via BurpResearchController
- Captures pre/post state changes and computes differential analysis
- Emits unbroken 7-stage causal provenance for the Evidence Court
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from typing import Any, Dict, List, Optional

from core.burp_gateway.correlation import BurpCorrelationContext
from core.burp_gateway.experiment_contract import (
    ExperimentContract,
    ExperimentExecutionRecord,
    StateSnapshot,
)
from core.burp_gateway.traffic_normalizer import (
    CanonicalRequest,
    CanonicalResponse,
    CanonicalTransaction,
    TrafficSource,
)
from core.controllers.burp_research_controller import (
    ActionStatus,
    BurpResearchController,
    ScopeViolationError,
)
from core.governance.risk_budget_queue import RiskBudgetManager, RiskTier
from core.scope_guard import ScopeGuard

logger = logging.getLogger("hunter_ai.bcsl")


class BurpControlSensorLayer:
    """
    Burp Control & Sensor Layer (BCSL) Facade.
    Guarantees strict separation between Hypothesis, Experiment, and Physical Burp Execution.
    """

    def __init__(
        self,
        research_controller: Optional[BurpResearchController] = None,
        scope_guard: Optional[ScopeGuard] = None,
        risk_budget: Optional[RiskBudgetManager] = None,
        event_stream: Optional[Any] = None,
        capture_store: Optional[Any] = None,
    ):
        self.scope_guard = scope_guard or ScopeGuard(in_scope=[], out_of_scope=["169.254.169.254"])
        self.risk_budget = risk_budget or RiskBudgetManager()
        self.event_stream = event_stream
        self.capture_store = capture_store
        self.controller = research_controller or BurpResearchController(
            scope_guard=self.scope_guard,
            risk_budget_manager=self.risk_budget,
            capture_store=self.capture_store,
            event_stream=self.event_stream,
        )

    def submit_experiment(self, contract: ExperimentContract) -> ExperimentExecutionRecord:
        """
        Submits an ExperimentContract for controlled execution through Burp Suite.
        """
        exp_id = contract.experiment_id or f"exp_{uuid.uuid4().hex[:8]}"
        base_tx = self.controller._transactions.get(contract.source_request_id)

        # Baseline capture
        state_before = StateSnapshot(
            observed_cookies=dict(base_tx.state.cookies) if base_tx and base_tx.state else {},
            bearer_token_fingerprint=base_tx.identity.bearer_token_hash if base_tx else None,
            timestamp=time.time(),
        )

        provenance = [
            f"[STAGE-1] Hypothesis Formulation: {contract.hypothesis_id}",
            f"[STAGE-2] Source Baseline Binding: {contract.source_request_id}",
            f"[STAGE-3] Experiment Contract Submitted to BCSL: {exp_id}",
        ]

        if not base_tx:
            # Baseline transaction missing
            return self._create_error_record(
                exp_id=exp_id,
                contract=contract,
                status="FAILED_MISSING_BASELINE",
                provenance=provenance + ["[STAGE-4] Aborted: Source request not found in BCSL memory"],
                state_before=state_before,
            )

        # ── SCOPE & RISK POLICY GATES ────────────────────────────────────────
        target_url = contract.target_endpoint or base_tx.request.url
        is_allowed, scope_reason = self.scope_guard.is_allowed(target_url)
        if not is_allowed:
            provenance.append(f"[STAGE-4] SCOPE VIOLATION BLOCKED: {scope_reason}")
            logger.warning(f"[BCSL] Scope violation blocked experiment {exp_id}: {scope_reason}")
            return self._create_error_record(
                exp_id=exp_id,
                contract=contract,
                status="BLOCKED_SCOPE",
                provenance=provenance,
                state_before=state_before,
            )

        provenance.append(f"[STAGE-4] Policy & Scope Verification: PASSED ({target_url})")

        # Prepare correlation
        correlation = BurpCorrelationContext(
            hypothesis_id=contract.hypothesis_id,
            experiment_id=exp_id,
            parent_transaction_id=contract.source_request_id,
            identity_id=contract.identity_context,
            intent=f"BCSL Experiment: {contract.expected_observation}",
            action_type="EXPERIMENT_EXECUTION",
        )

        # Execute through Burp Research Controller
        try:
            exec_res = self.controller.replay(
                request_id=contract.source_request_id,
                mutation=contract.mutation_plan,
                correlation=correlation,
                reason=contract.expected_observation,
            )
            provenance.append(f"[STAGE-5] Burp Wire Execution: Replay ID {exec_res.transaction.tx_id} -> HTTP {exec_res.transaction.response.status_code}")
        except ScopeViolationError as sve:
            provenance.append(f"[STAGE-5] Burp Wire Execution BLOCKED: {sve}")
            return self._create_error_record(
                exp_id=exp_id,
                contract=contract,
                status="BLOCKED_SCOPE",
                provenance=provenance,
                state_before=state_before,
            )
        except Exception as e:
            provenance.append(f"[STAGE-5] Execution Failure: {e}")
            return self._create_error_record(
                exp_id=exp_id,
                contract=contract,
                status="FAILED_EXECUTION",
                provenance=provenance,
                state_before=state_before,
            )

        new_tx = exec_res.transaction

        # ── DIFFERENTIAL & STATE SNAPSHOT ────────────────────────────────────
        diff_analysis = self.controller.compare(contract.source_request_id, new_tx.tx_id)
        provenance.append(f"[STAGE-6] Differential Analysis: Delta {diff_analysis.length_delta_bytes:+d} bytes | Status Changed: {diff_analysis.status_code_changed}")

        state_after = StateSnapshot(
            observed_cookies=dict(new_tx.state.cookies) if new_tx.state else {},
            bearer_token_fingerprint=new_tx.identity.bearer_token_hash if new_tx.identity else None,
            timestamp=time.time(),
        )

        provenance.append(f"[STAGE-7] Evidence Committed to Evidence Court (Verdict: {diff_analysis.verdict})")

        # SHA-256 Audit digest
        audit_raw = f"{exp_id}:{new_tx.tx_id}:{contract.hypothesis_id}:{diff_analysis.verdict}:{time.time()}"
        audit_hash = hashlib.sha256(audit_raw.encode()).hexdigest()[:16]

        record = ExperimentExecutionRecord(
            experiment_id=exp_id,
            request_id=new_tx.tx_id,
            parent_request_id=contract.source_request_id,
            correlation_id=contract.correlation_id,
            identity_id=contract.identity_context,
            timestamp=time.time(),
            request=new_tx.request,
            response=new_tx.response,
            response_diff=diff_analysis.to_dict(),
            state_before=state_before,
            state_after=state_after,
            execution_status="EXECUTED",
            provenance=provenance,
            audit_hash=audit_hash,
        )

        if self.event_stream and hasattr(self.event_stream, "publish_event"):
            self.event_stream.publish_event("BCSL_EXPERIMENT_COMPLETED", record.to_dict())

        return record

    def ingest_transaction(self, tx: CanonicalTransaction):
        """Registers a canonical transaction into BCSL memory."""
        self.controller.ingest_canonical(tx)

    def ingest_captured(self, cap_tx: Any) -> CanonicalTransaction:
        """Converts a CapturedTransaction into canonical format and registers it into BCSL."""
        from core.burp_gateway.correlation import BurpCorrelationContext
        from core.burp_gateway.traffic_normalizer import (
            CanonicalIdentity,
            CanonicalRequest,
            CanonicalResponse,
            CanonicalTransaction,
            TargetStateContext,
            TrafficSource,
        )
        from urllib.parse import parse_qs, urlparse

        if isinstance(cap_tx, CanonicalTransaction):
            self.controller.ingest_canonical(cap_tx)
            return cap_tx

        source_map = {
            "proxy": TrafficSource.PROXY,
            "repeater": TrafficSource.REPEATER,
            "scanner": TrafficSource.SCANNER,
            "extension": TrafficSource.EXTENSION,
            "browser": TrafficSource.BROWSER,
        }
        tool = getattr(cap_tx, "tool_source", "proxy").lower()
        src = source_map.get(tool, TrafficSource.PROXY)

        tx_id = getattr(cap_tx, "tx_id", str(uuid.uuid4()))
        url = getattr(cap_tx, "url", "")
        method = getattr(cap_tx, "method", "GET")
        host = getattr(cap_tx, "target_host", "")
        req_headers = dict(getattr(cap_tx, "req_headers", {}))
        req_body = getattr(cap_tx, "req_body", "")
        status_code = int(getattr(cap_tx, "status_code", 200))
        resp_headers = dict(getattr(cap_tx, "resp_headers", {}))
        resp_body = getattr(cap_tx, "resp_body", "")
        parent_id = getattr(cap_tx, "parent_request", None)

        p = urlparse(url)
        q_params = parse_qs(p.query) if p.query else {}

        req_obj = CanonicalRequest(
            method=method,
            url=url,
            host=host or p.netloc,
            path=p.path or "/",
            query_params=q_params,
            headers=req_headers,
            body=req_body,
        )
        resp_obj = CanonicalResponse(
            status_code=status_code,
            headers=resp_headers,
            body=resp_body,
        )
        corr = BurpCorrelationContext(
            transaction_id=tx_id,
            parent_transaction_id=parent_id,
            action_type="INGESTED_CAPTURE",
        )
        norm_tx = CanonicalTransaction(
            tx_id=tx_id,
            source=src,
            correlation=corr,
            request=req_obj,
            response=resp_obj,
            identity=CanonicalIdentity(
                identity_id=getattr(cap_tx, "identity", "GUEST"),
                role=getattr(cap_tx, "identity", "GUEST")
            ),
            state=TargetStateContext(cookies=getattr(cap_tx, "cookies", {})),
            timestamp=getattr(cap_tx, "timestamp", time.time()),
        )
        self.controller.ingest_canonical(norm_tx)
        return norm_tx

    def provision_repeater_tab(
        self,
        request_or_tx_id: Any,
        tab_caption: Optional[str] = None,
    ) -> str:
        """Provisions an interactive research tab in Burp Repeater."""
        return self.controller.send_to_repeater(request_or_tx_id, tab_name=tab_caption)

    def _create_error_record(
        self,
        exp_id: str,
        contract: ExperimentContract,
        status: str,
        provenance: List[str],
        state_before: StateSnapshot,
    ) -> ExperimentExecutionRecord:
        return ExperimentExecutionRecord(
            experiment_id=exp_id,
            request_id="",
            parent_request_id=contract.source_request_id,
            correlation_id=contract.correlation_id,
            identity_id=contract.identity_context,
            timestamp=time.time(),
            request=CanonicalRequest(url=contract.target_endpoint),
            response=CanonicalResponse(status_code=0, body=""),
            response_diff={},
            state_before=state_before,
            state_after=state_before,
            execution_status=status,
            provenance=provenance,
            audit_hash="",
        )

