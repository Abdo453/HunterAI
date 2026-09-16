"""
HunterAI Burp Sensor — The HTTP Reality Sensor
==============================================
Transforms Burp Suite from an external proxy into a first-class perceptual organ:
- Ingests wire-level HTTP interactions from Proxy, Repeater, and Scanner
- Enriches every transaction with BurpSessionContext (lineage, auth, parameters)
- Normalizes traffic into canonical Observations for AgentBlackboard & AttackSurfaceGraph
- Maintains causal provenance chains linking raw packets to Evidence Court findings
- Exports confirmed, deterministic findings back into the Burp Target Tab
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse
from core.burp_gateway.correlation import BurpCorrelationContext
from core.burp_gateway.traffic_normalizer import BurpTrafficNormalizer, CanonicalRequest, CanonicalTransaction
from core.burp_gateway.experiment_queue import BurpExperimentQueue
from core.burp_gateway.event_stream import BurpLiveEventStream
from core.controllers.burp_research_controller import BurpResearchController, ExecutionResult, DifferentialAnalysis


logger = logging.getLogger("hunter_ai.burp_sensor")


class SensorType(str, Enum):
    BROWSER = "BROWSER"
    BURP = "BURP"
    CODE = "CODE"


@dataclass
class BurpSessionContext:
    """
    Rich Session & Transaction Context:
    Connects isolated HTTP exchanges into a continuous causal investigation graph.
    """
    request_id: str = field(default_factory=lambda: f"req_{uuid.uuid4().hex[:10]}")
    timestamp: float = field(default_factory=time.time)
    method: str = "GET"
    url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    status_code: int = 200
    content_type: str = "text/html"
    cookies: Dict[str, str] = field(default_factory=dict)
    auth_context: str = "ANONYMOUS"  # e.g., 'User A', 'User B', 'Admin', 'ANONYMOUS'
    source: str = "proxy"            # 'proxy', 'repeater', 'scanner', 'active_probe'
    parent_request: Optional[str] = None
    endpoint_id: str = ""
    parameter_ids: List[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.endpoint_id and self.url:
            parsed = urlparse(self.url)
            self.endpoint_id = f"{self.method.upper()}:{parsed.path}"
        if not self.parameter_ids and self.url:
            parsed = urlparse(self.url)
            params = list(parse_qs(parsed.query).keys())
            ct = next((v for k, v in self.headers.items() if k.lower() == "content-type"), "")
            if self.body and "application/x-www-form-urlencoded" in ct.lower():
                params.extend(list(parse_qs(self.body).keys()))
            self.parameter_ids = sorted(list(set(params)))

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> BurpSessionContext:
        valid_keys = {
            "request_id", "timestamp", "method", "url", "headers", "body",
            "response_headers", "response_body", "status_code", "content_type",
            "cookies", "auth_context", "source", "parent_request",
            "endpoint_id", "parameter_ids"
        }
        filtered = {k: v for k, v in d.items() if k in valid_keys}
        return cls(**filtered)


@dataclass
class NormalizedObservation:
    """
    Standardized Epistemic Observation:
    Dispatched to AgentBlackboard.OBSERVATIONS and AttackSurfaceGraph.
    """
    observation_id: str = field(default_factory=lambda: f"obs_{uuid.uuid4().hex[:8]}")
    sensor_type: SensorType = SensorType.BURP
    target_url: str = ""
    method: str = "GET"
    status_code: int = 200
    parameters: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    extracted_tokens: Dict[str, str] = field(default_factory=dict)
    raw_context: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["sensor_type"] = self.sensor_type.value
        return d


class BurpSensor:
    """
    First-Class Sensory Organ for HTTP Telemetry.
    Directly binds Burp Suite traffic to HunterAI's Cognitive Brain.
    """

    def __init__(
        self,
        capture_store: Optional[Any] = None,
        blackboard: Optional[Any] = None,
        attack_surface: Optional[Any] = None,
        evidence_graph: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        research_controller: Optional[Any] = None,
        experiment_queue: Optional[Any] = None,
        event_stream: Optional[Any] = None,
    ):
        self.capture_store = capture_store
        self.blackboard = blackboard
        self.attack_surface = attack_surface
        self.evidence_graph = evidence_graph
        self.event_bus = event_bus

        self._transactions: Dict[str, BurpSessionContext] = {}
        self._pending_observations: List[NormalizedObservation] = []
        self._repeater_mutations: List[Dict[str, Any]] = []
        self._scanner_issues: List[Dict[str, Any]] = []
        self._lineage_index: Dict[str, List[str]] = {}  # parent_id -> list of child_ids

        self.event_stream = event_stream or BurpLiveEventStream()
        self.experiment_queue = experiment_queue or BurpExperimentQueue()
        self.research_controller = research_controller or BurpResearchController(
            capture_store=self.capture_store,
            evidence_graph=self.evidence_graph,
            experiment_queue=self.experiment_queue,
            event_stream=self.event_stream,
        )

        logger.info("[BURP_SENSOR] Initialized HTTP Reality Sensor & Research Controller")

    def ingest_transaction(
        self,
        transaction: Any,
        parent_id: Optional[str] = None,
        auth_context: Optional[str] = None
    ) -> NormalizedObservation:
        """
        Ingests a live HTTP exchange, builds full session context, and normalizes it.
        Accepts CapturedTransaction instance, dict, or BurpSessionContext.
        """
        if isinstance(transaction, BurpSessionContext):
            ctx = transaction
        elif hasattr(transaction, "__dict__"):
            d = transaction.__dict__
            ctx = BurpSessionContext(
                request_id=d.get("request_id") or d.get("tx_id") or f"req_{uuid.uuid4().hex[:10]}",
                timestamp=d.get("timestamp", time.time()),
                method=d.get("method", "GET"),
                url=d.get("url", ""),
                headers=d.get("req_headers") or d.get("headers") or {},
                body=d.get("req_body") or d.get("body") or "",
                response_headers=d.get("resp_headers") or d.get("response_headers") or {},
                response_body=d.get("resp_body") or d.get("response_body") or "",
                status_code=d.get("status_code", 200),
                content_type=d.get("content_type", "text/html"),
                cookies=d.get("cookies") or {},
                auth_context=auth_context or d.get("auth_context") or d.get("identity") or "ANONYMOUS",
                source=d.get("tool_source") or d.get("source") or "proxy",
                parent_request=parent_id or d.get("parent_request"),
            )
        elif isinstance(transaction, dict):
            ctx = BurpSessionContext(
                request_id=transaction.get("request_id") or transaction.get("tx_id") or f"req_{uuid.uuid4().hex[:10]}",
                timestamp=transaction.get("timestamp", time.time()),
                method=transaction.get("method", "GET"),
                url=transaction.get("url", ""),
                headers=transaction.get("req_headers") or transaction.get("headers") or {},
                body=transaction.get("req_body") or transaction.get("body") or "",
                response_headers=transaction.get("resp_headers") or transaction.get("response_headers") or {},
                response_body=transaction.get("resp_body") or transaction.get("response_body") or "",
                status_code=transaction.get("status_code", 200),
                content_type=transaction.get("content_type", "text/html"),
                cookies=transaction.get("cookies") or {},
                auth_context=auth_context or transaction.get("auth_context") or transaction.get("identity") or "ANONYMOUS",
                source=transaction.get("tool_source") or transaction.get("source") or "proxy",
                parent_request=parent_id or transaction.get("parent_request"),
            )
        else:
            raise ValueError(f"Unsupported transaction type: {type(transaction)}")

        # Index transaction
        self._transactions[ctx.request_id] = ctx
        if ctx.parent_request:
            if ctx.parent_request not in self._lineage_index:
                self._lineage_index[ctx.parent_request] = []
            self._lineage_index[ctx.parent_request].append(ctx.request_id)

        # Extract tokens
        tokens = self._extract_tokens(ctx)

        # Build normalized observation
        obs = NormalizedObservation(
            sensor_type=SensorType.BURP,
            target_url=ctx.url,
            method=ctx.method.upper(),
            status_code=ctx.status_code,
            parameters=ctx.parameter_ids,
            headers=ctx.headers,
            extracted_tokens=tokens,
            raw_context=ctx.to_dict(),
            timestamp=ctx.timestamp,
        )
        self._pending_observations.append(obs)

        # Dispatch to Blackboard if attached
        if self.blackboard and hasattr(self.blackboard, "post_observation"):
            try:
                self.blackboard.post_observation(
                    author="BurpSensor",
                    title=f"{ctx.method} {ctx.url} [{ctx.status_code}]",
                    telemetry_data=obs.to_dict()
                )
            except Exception as e:
                logger.warning(f"[BURP_SENSOR] Failed to post to blackboard: {e}")

        # Update AttackSurfaceGraph if attached
        if self.attack_surface and hasattr(self.attack_surface, "add_endpoint"):
            try:
                parsed = urlparse(ctx.url)
                self.attack_surface.add_endpoint(
                    path=parsed.path,
                    method=ctx.method.upper(),
                    parameters=ctx.parameter_ids
                )
            except Exception as e:
                logger.warning(f"[BURP_SENSOR] Failed to update attack surface: {e}")

        # Persist in CaptureStore if attached
        if self.capture_store and hasattr(self.capture_store, "store_transaction"):
            try:
                from core.burp_gateway.capture_store import CapturedTransaction
                cap_tx = CapturedTransaction(
                    tx_id=ctx.request_id,
                    target_host=urlparse(ctx.url).netloc,
                    method=ctx.method,
                    url=ctx.url,
                    status_code=ctx.status_code,
                    req_headers=ctx.headers,
                    req_body=ctx.body,
                    resp_headers=ctx.response_headers,
                    resp_body=ctx.response_body,
                    tool_source=ctx.source,
                    timestamp=ctx.timestamp,
                    identity=ctx.auth_context,
                    parent_request=ctx.parent_request,
                )
                self.capture_store.store_transaction(cap_tx)
            except Exception as e:
                logger.warning(f"[BURP_SENSOR] Failed to store in capture store: {e}")

        # Forward canonical transaction to Research Controller & Event Stream
        try:
            can_tx = BurpTrafficNormalizer.normalize_dict(ctx.to_dict())
            self.research_controller.ingest_canonical(can_tx)
            self.event_stream.publish_event("REQUEST_INGESTED", can_tx.to_dict())
        except Exception as e:
            logger.warning(f"[BURP_SENSOR] Error syncing to research controller: {e}")

        return obs

    def ingest_repeater_mutation(
        self,
        base_request_id: str,
        mutated_url: str,
        payload_used: str,
        method: str = "GET",
        req_body: str = "",
        status_code: int = 200,
        resp_body: str = "",
        resp_headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Records a deliberate Repeater mutation linked to a baseline transaction.
        Tracks response delta and status code divergence.
        """
        mutation_id = f"mut_{uuid.uuid4().hex[:8]}"
        base_ctx = self._transactions.get(base_request_id)
        status_diff = status_code != (base_ctx.status_code if base_ctx else 200)
        len_diff = len(resp_body) - (len(base_ctx.response_body) if base_ctx else 0)

        record = {
            "mutation_id": mutation_id,
            "base_request_id": base_request_id,
            "mutated_url": mutated_url,
            "payload_used": payload_used,
            "method": method,
            "req_body": req_body,
            "status_code": status_code,
            "resp_body_len": len(resp_body),
            "status_diverged": status_diff,
            "length_delta": len_diff,
            "timestamp": time.time(),
        }
        self._repeater_mutations.append(record)

        # Also ingest as a child transaction in the lineage tree
        child_ctx = BurpSessionContext(
            request_id=mutation_id,
            method=method,
            url=mutated_url,
            body=req_body,
            response_headers=resp_headers or {},
            response_body=resp_body,
            status_code=status_code,
            source="repeater",
            parent_request=base_request_id,
            auth_context=base_ctx.auth_context if base_ctx else "ANONYMOUS"
        )
        self.ingest_transaction(child_ctx, parent_id=base_request_id)

        return record

    def ingest_scanner_issue(self, issue: Dict[str, Any]) -> Optional[str]:
        """
        Ingests findings from Burp Scanner.
        Deduplicates against the EvidenceGraph before creating hypothesis items.
        """
        issue_name = issue.get("name") or issue.get("issue_name") or "Unknown Burp Scanner Finding"
        url = issue.get("url") or ""
        severity = issue.get("severity", "Information")
        confidence = issue.get("confidence", "Certain")

        issue_id = f"scan_{hashlib.sha256(f'{issue_name}:{url}'.encode()).hexdigest()[:8]}"
        record = {
            "issue_id": issue_id,
            "name": issue_name,
            "url": url,
            "severity": severity,
            "confidence": confidence,
            "detail": issue.get("detail", ""),
            "remediation": issue.get("remediation", ""),
            "timestamp": time.time()
        }
        self._scanner_issues.append(record)

        # Add hypothesis into EvidenceGraph if attached
        if self.evidence_graph and hasattr(self.evidence_graph, "add_hypothesis"):
            try:
                self.evidence_graph.add_hypothesis(
                    vuln_type=issue_name,
                    rationale=f"Reported by Burp Scanner: {issue.get('detail', '')[:120]}",
                    target_url=url,
                    source_sensor="BURP_SCANNER"
                )
            except Exception as e:
                logger.warning(f"[BURP_SENSOR] Could not add scanner hypothesis to evidence graph: {e}")

        return issue_id

    def get_pending_observations(self) -> List[NormalizedObservation]:
        """Drains and returns all unconsumed observations for the Brain's OODA loop."""
        obs = list(self._pending_observations)
        self._pending_observations.clear()
        # Forward canonical transaction to Research Controller & Event Stream
        try:
            can_tx = BurpTrafficNormalizer.normalize_dict(ctx.to_dict())
            self.research_controller.ingest_canonical(can_tx)
            self.event_stream.publish_event("REQUEST_INGESTED", can_tx.to_dict())
        except Exception as e:
            logger.warning(f"[BURP_SENSOR] Error syncing to research controller: {e}")

        return obs

    def get_transaction(self, request_id: str) -> Optional[BurpSessionContext]:
        """Retrieves a transaction by its persistent ID."""
        return self._transactions.get(request_id)

    def get_lineage(self, request_id: str) -> List[BurpSessionContext]:
        """
        Traverses parent_request backward to reconstruct the entire lineage chain:
        root -> child_1 -> child_2 -> ... -> request_id.
        """
        chain = []
        curr_id = request_id
        visited = set()

        while curr_id and curr_id not in visited:
            visited.add(curr_id)
            tx = self._transactions.get(curr_id)
            if not tx:
                break
            chain.append(tx)
            curr_id = tx.parent_request

        return list(reversed(chain))

    def export_finding_to_burp(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Exports an EvidenceCourt-adjudicated finding into Burp Suite's Target Tab schema.
        Adheres to the IScanIssue specification.
        """
        finding_id = finding.get("finding_id") or f"fnd_{uuid.uuid4().hex[:8]}"
        name = finding.get("name") or finding.get("title") or "HunterAI Confirmed Vulnerability"
        url = finding.get("target_url") or finding.get("url") or "http://localhost"
        severity = finding.get("severity", "High")
        confidence = finding.get("confidence", "Certain")
        evidence_chain = finding.get("evidence", [])
        provenance = finding.get("provenance_trace") or finding.get("provenance") or []

        detail_lines = [
            f"<p><b>HunterAI Evidence Court Verdict: CONFIRMED</b></p>",
            f"<p>{finding.get('description', '')}</p>",
            "<h3>Deterministic Proof of Execution (PoE):</h3>",
            f"<pre>{finding.get('proof', 'Verified via arithmetic differential nonces')}</pre>",
            "<h3>7-Stage Causal Provenance:</h3>",
            "<ul>"
        ]
        if isinstance(provenance, list):
            for step in provenance:
                detail_lines.append(f"<li><b>{step}</b></li>")
        detail_lines.append("</ul>")

        burp_issue = {
            "finding_id": finding_id,
            "issue_name": f"[HunterAI] {name}",
            "url": url,
            "severity": severity,
            "confidence": confidence,
            "issue_background": "Discovered and certified by HunterAI Autonomous Cognitive Engine.",
            "issue_detail": "".join(detail_lines),
            "remediation_detail": finding.get("remediation", "Apply parameter validation and strict authorization checks."),
            "evidence_count": len(evidence_chain),
            "exported_at": time.time(),
        }

        # If CaptureStore is attached, add finding to it
        if self.capture_store and hasattr(self.capture_store, "add_finding"):
            try:
                self.capture_store.add_finding(
                    title=name,
                    vuln_type=finding.get("vuln_type", "VULNERABILITY"),
                    endpoint=urlparse(url).path,
                    severity=severity,
                    proof=finding.get("proof", "")
                )
            except Exception as e:
                logger.warning(f"[BURP_SENSOR] Failed to save finding to capture store: {e}")

        return burp_issue

    def get_sensor_status(self) -> Dict[str, Any]:
        """Returns comprehensive real-time sensory health diagnostics."""
        return {
            "sensor_type": SensorType.BURP.value,
            "total_transactions_ingested": len(self._transactions),
            "pending_observations": len(self._pending_observations),
            "repeater_mutations_recorded": len(self._repeater_mutations),
            "scanner_issues_ingested": len(self._scanner_issues),
            "tracked_lineage_roots": len(self._lineage_index),
            "active_auth_contexts": sorted(list(set(tx.auth_context for tx in self._transactions.values()))),
            "unique_endpoints_observed": sorted(list(set(tx.endpoint_id for tx in self._transactions.values()))),
        }


    # ── ACTIVE RESEARCH CONTROLLER PRIMITIVES ─────────────────────────────────
    def replay(
        self,
        request_id: str,
        mutation: Optional[Dict[str, Any]] = None,
        reason: str = "Active BurpSensor Replay",
        risk_tier: str = "LOW_RISK"
    ) -> ExecutionResult:
        """Executes active verification replay through BurpResearchController."""
        return self.research_controller.replay(request_id=request_id, mutation=mutation, reason=reason)

    def send_to_repeater(self, request_or_tx_id: Any, tab_name: Optional[str] = None) -> str:
        """Provisions a named Repeater experiment workspace tab."""
        return self.research_controller.send_to_repeater(request_or_tx_id, tab_name=tab_name)

    def compare(self, baseline_tx_id: str, experiment_tx_id: str) -> DifferentialAnalysis:
        """Performs differential analysis between baseline and mutation."""
        return self.research_controller.compare(baseline_tx_id, experiment_tx_id)

    def queue_experiment(self, request: CanonicalRequest, priority: int = 5, eig: float = 0.5) -> str:
        """Enqueues an experiment into the prioritized BurpExperimentQueue."""
        return self.research_controller.queue(request, priority=priority, eig=eig)

    def _extract_tokens(self, ctx: BurpSessionContext) -> Dict[str, str]:
        """Extracts security-relevant tokens (Bearer, JWT, CSRF) from request/response."""
        tokens = {}
        auth_hdr = ctx.headers.get("authorization") or ctx.headers.get("Authorization") or ""
        if auth_hdr.startswith("Bearer "):
            tokens["bearer_token"] = auth_hdr[7:]
        for k, v in ctx.headers.items():
            if "csrf" in k.lower() or "xsrf" in k.lower():
                tokens[k] = v
        for k, v in ctx.cookies.items():
            if "session" in k.lower() or "token" in k.lower() or "jwt" in k.lower():
                tokens[f"cookie:{k}"] = v
        return tokens
