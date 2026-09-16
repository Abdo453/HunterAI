"""
HunterAI V26.0 - Bidirectional Burp Control Plane & Research Controller Test Suite
==================================================================================
Comprehensive tests covering the 5 Core Epistemic Upgrades:
- P0: BurpResearchController (observe, replay, repeater, compare, scope & risk guards)
- P0: BurpTrafficNormalizer (CanonicalRequest, CanonicalResponse, CanonicalTransaction)
- P0: BurpCorrelationContext (X-HunterAI-* header injection & causal lineage)
- P1: BurpExperimentQueue (EIG ranking, rate limiting, cancellation, metrics)
- P1: BurpLiveEventStream (async streaming, bounded ring buffer, sync listeners)
- E2E Integration: BurpGateway REST API, BurpSensor, AutonomousBrain binding
"""
import asyncio
import json
import pytest
from unittest.mock import MagicMock

from core.burp_gateway.correlation import (
    BurpCorrelationContext,
    HDR_ENGAGEMENT_ID,
    HDR_TRANSACTION_ID,
    HDR_HYPOTHESIS_ID,
    HDR_EXPERIMENT_ID,
    HDR_PARENT_ID,
    HDR_IDENTITY_ID,
    HDR_INTENT,
)
from core.burp_gateway.traffic_normalizer import (
    BurpTrafficNormalizer,
    CanonicalRequest,
    CanonicalResponse,
    CanonicalTransaction,
    CanonicalIdentity,
    TargetStateContext,
    TrafficSource,
)
from core.controllers.burp_research_controller import (
    BurpResearchController,
    ScopeViolationError,
    ActionStatus,
    ControlActionReceipt,
)
from core.burp_gateway.experiment_queue import (
    BurpExperimentQueue,
    BurpExperimentItem,
    ExperimentStatus,
    TokenBucketRateLimiter,
)
from core.burp_gateway.event_stream import (
    BurpLiveEventStream,
    StreamEvent,
)
from core.governance.risk_budget_queue import RiskBudgetManager, RiskTier
from core.scope_guard import ScopeGuard
from core.sensors.burp_sensor import BurpSensor


# ── 1. BurpCorrelationContext Tests ──────────────────────────────────────────

def test_correlation_context_headers_roundtrip():
    corr = BurpCorrelationContext(
        engagement_id="eng_test_01",
        transaction_id="tx_req_100",
        hypothesis_id="hyp_bola_01",
        experiment_id="exp_replay_02",
        parent_transaction_id="tx_base_99",
        identity_id="User_B",
        intent="Testing BOLA on Order 42",
        action_type="REPLAY",
    )
    headers = corr.to_headers()
    assert headers[HDR_ENGAGEMENT_ID] == "eng_test_01"
    assert headers[HDR_TRANSACTION_ID] == "tx_req_100"
    assert headers[HDR_HYPOTHESIS_ID] == "hyp_bola_01"
    assert headers[HDR_EXPERIMENT_ID] == "exp_replay_02"
    assert headers[HDR_PARENT_ID] == "tx_base_99"
    assert headers[HDR_IDENTITY_ID] == "User_B"

    # Ingest from incoming headers
    reconstructed = BurpCorrelationContext.from_headers(headers)
    assert reconstructed.engagement_id == "eng_test_01"
    assert reconstructed.transaction_id == "tx_req_100"
    assert reconstructed.hypothesis_id == "hyp_bola_01"
    assert reconstructed.identity_id == "User_B"


def test_correlation_context_spawn_child():
    parent = BurpCorrelationContext(engagement_id="eng_01", transaction_id="tx_root")
    child = parent.spawn_child(action_type="MUTATION", intent="Child Mutation Probe")
    assert child.engagement_id == "eng_01"
    assert child.parent_transaction_id == "tx_root"
    assert child.transaction_id != "tx_root"
    assert child.action_type == "MUTATION"
    assert child.intent == "Child Mutation Probe"


# ── 2. BurpTrafficNormalizer Tests ───────────────────────────────────────────

def test_traffic_normalizer_raw_http():
    raw_req = (
        "POST /api/v1/orders HTTP/1.1\r\n"
        "Host: api.target.local\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Authorization: Bearer test_secret_token_123\r\n"
        "\r\n"
        "item_id=42&quantity=3"
    )
    raw_resp = (
        "HTTP/1.1 201 Created\r\n"
        "Content-Type: application/json\r\n"
        "Set-Cookie: sessionid=sess_abc123\r\n"
        "\r\n"
        "{\"order_id\": 999}"
    )
    tx = BurpTrafficNormalizer.normalize_raw_http(
        raw_request=raw_req,
        raw_response=raw_resp,
        host="api.target.local",
        source=TrafficSource.PROXY,
    )
    assert tx.request.method == "POST"
    assert tx.request.path == "/api/v1/orders"
    assert tx.request.get_all_parameter_names() == ["item_id", "quantity"]
    assert tx.response.status_code == 201
    assert tx.identity.bearer_token_hash is not None
    assert tx.state.cookies.get("sessionid") == "sess_abc123"


def test_traffic_normalizer_dict_json():
    payload = {
        "host": "portal.target.local",
        "tool": "repeater",
        "request": {
            "method": "GET",
            "url": "https://portal.target.local/api/profile?user=admin",
            "headers": {"Content-Type": "application/json"},
            "body": "",
        },
        "response": {
            "status_code": 200,
            "headers": {"Content-Type": "application/json"},
            "body": "{\"role\": \"admin\"}",
        }
    }
    tx = BurpTrafficNormalizer.normalize_dict(payload)
    assert tx.source == TrafficSource.REPEATER
    assert tx.request.path == "/api/profile"
    assert tx.request.query_params.get("user") == ["admin"]
    assert tx.response.status_code == 200


# ── 3. BurpResearchController Core Tests ────────────────────────────────────

def test_research_controller_observe_and_fetch():
    guard = ScopeGuard(in_scope=["target.local"])
    ctrl = BurpResearchController(scope_guard=guard)

    can_tx = CanonicalTransaction(
        tx_id="tx_test_1",
        source=TrafficSource.PROXY,
        correlation=BurpCorrelationContext(transaction_id="tx_test_1"),
        request=CanonicalRequest(method="GET", url="https://target.local/index"),
        response=CanonicalResponse(status_code=200, body="Index Page"),
        identity=CanonicalIdentity(),
        state=TargetStateContext(),
    )
    ctrl.ingest_canonical(can_tx)

    observed = ctrl.observe(limit=10)
    assert len(observed) == 1
    assert observed[0].tx_id == "tx_test_1"

    resp = ctrl.fetch_response("tx_test_1")
    assert resp is not None
    assert resp.body == "Index Page"


def test_research_controller_modify_request():
    ctrl = BurpResearchController()
    base_tx = CanonicalTransaction(
        tx_id="tx_base",
        source=TrafficSource.PROXY,
        correlation=BurpCorrelationContext(transaction_id="tx_base"),
        request=CanonicalRequest(
            method="GET",
            url="https://api.target.local/api/items?id=1",
            host="api.target.local",
            headers={"Authorization": "Bearer old_token"}
        ),
        response=CanonicalResponse(status_code=200),
        identity=CanonicalIdentity(),
        state=TargetStateContext(),
    )
    ctrl.ingest_canonical(base_tx)

    mutated = ctrl.modify_request("tx_base", {
        "method": "POST",
        "params": {"id": "999", "action": "delete"},
        "headers": {"Authorization": "Bearer new_admin_token"}
    })
    assert mutated.method == "POST"
    assert mutated.headers["Authorization"] == "Bearer new_admin_token"
    assert "id=999" in mutated.url
    assert "action=delete" in mutated.url


def test_research_controller_replay_success():
    guard = ScopeGuard(in_scope=["api.target.local"])
    ctrl = BurpResearchController(scope_guard=guard)

    base_tx = CanonicalTransaction(
        tx_id="tx_orig",
        source=TrafficSource.PROXY,
        correlation=BurpCorrelationContext(transaction_id="tx_orig"),
        request=CanonicalRequest(
            method="GET",
            url="https://api.target.local/api/v1/user?user_id=101",
            host="api.target.local"
        ),
        response=CanonicalResponse(status_code=403, body="Forbidden"),
        identity=CanonicalIdentity(),
        state=TargetStateContext(),
    )
    ctrl.ingest_canonical(base_tx)

    res = ctrl.replay(
        request_id="tx_orig",
        mutation={"params": {"user_id": "102"}},
        reason="Testing BOLA Authorization Boundary"
    )
    assert res.receipt.status == ActionStatus.EXECUTED
    assert res.receipt.audit_hash != ""
    assert res.transaction is not None
    assert res.transaction.response.status_code == 200
    assert "X-HunterAI-Parent-ID" in res.transaction.request.headers


def test_research_controller_send_to_repeater():
    guard = ScopeGuard(in_scope=["api.target.local"])
    ctrl = BurpResearchController(scope_guard=guard)
    base_tx = CanonicalTransaction(
        tx_id="tx_rep_src",
        source=TrafficSource.PROXY,
        correlation=BurpCorrelationContext(transaction_id="tx_rep_src"),
        request=CanonicalRequest(method="GET", url="https://api.target.local/test"),
        response=CanonicalResponse(status_code=200),
        identity=CanonicalIdentity(),
        state=TargetStateContext(),
    )
    ctrl.ingest_canonical(base_tx)

    tab_id = ctrl.send_to_repeater("tx_rep_src", tab_name="BOLA-Tab-01")
    assert tab_id == "BOLA-Tab-01"
    assert "BOLA-Tab-01" in ctrl._repeater_tabs


def test_research_controller_compare_differential():
    ctrl = BurpResearchController()
    t1 = CanonicalTransaction(
        tx_id="t1",
        source=TrafficSource.PROXY,
        correlation=BurpCorrelationContext(transaction_id="t1"),
        request=CanonicalRequest(url="https://target.local/res"),
        response=CanonicalResponse(status_code=403, body="Access Denied"),
        identity=CanonicalIdentity(),
        state=TargetStateContext(),
    )
    t2 = CanonicalTransaction(
        tx_id="t2",
        source=TrafficSource.REPEATER,
        correlation=BurpCorrelationContext(transaction_id="t2", parent_transaction_id="t1"),
        request=CanonicalRequest(url="https://target.local/res?admin=true"),
        response=CanonicalResponse(status_code=200, body="Welcome Administrator to private tenant!"),
        identity=CanonicalIdentity(),
        state=TargetStateContext(),
    )
    ctrl.ingest_canonical(t1)
    ctrl.ingest_canonical(t2)

    diff = ctrl.compare("t1", "t2")
    assert diff.status_code_changed is True
    assert diff.verdict == "CONFIRMED_ANOMALY"
    assert diff.invariant_violation is not None
    assert "INV-AUTHZ-BYPASS" in diff.invariant_violation


def test_research_controller_scope_violation_blocked():
    guard = ScopeGuard(in_scope=["authorized.local"], out_of_scope=["169.254.169.254", "*.evilcorp.com"])
    ctrl = BurpResearchController(scope_guard=guard)

    base_tx = CanonicalTransaction(
        tx_id="tx_safe",
        source=TrafficSource.PROXY,
        correlation=BurpCorrelationContext(transaction_id="tx_safe"),
        request=CanonicalRequest(method="GET", url="https://authorized.local/page"),
        response=CanonicalResponse(status_code=200),
        identity=CanonicalIdentity(),
        state=TargetStateContext(),
    )
    ctrl.ingest_canonical(base_tx)

    # Attempt mutation to cloud metadata IP
    with pytest.raises(ScopeViolationError):
        ctrl.replay(
            request_id="tx_safe",
            mutation={"url": "http://169.254.169.254/latest/meta-data"},
        )

    # Attempt mutation to out-of-scope evilcorp.com domain
    with pytest.raises(ScopeViolationError):
        ctrl.replay(
            request_id="tx_safe",
            mutation={"url": "https://api.evilcorp.com/steal"},
        )


def test_research_controller_risk_budget_enforcement():
    risk_mgr = RiskBudgetManager(high_limit=0)  # zero high-risk allowance
    ctrl = BurpResearchController(risk_budget_manager=risk_mgr)

    base_tx = CanonicalTransaction(
        tx_id="tx_base",
        source=TrafficSource.PROXY,
        correlation=BurpCorrelationContext(transaction_id="tx_base"),
        request=CanonicalRequest(method="GET", url="https://api.target.local/item"),
        response=CanonicalResponse(status_code=200),
        identity=CanonicalIdentity(),
        state=TargetStateContext(),
    )
    ctrl.ingest_canonical(base_tx)

    res = ctrl.replay(
        request_id="tx_base",
        risk_tier=RiskTier.HIGH_RISK,
        reason="High risk probe"
    )
    assert res.receipt.status == ActionStatus.DENIED_RISK_BUDGET


# ── 4. BurpExperimentQueue Tests ────────────────────────────────────────────

def test_experiment_queue_eig_prioritization():
    queue = BurpExperimentQueue(rate_limit_rps=50.0)

    # Low EIG item
    it_low_eig = BurpExperimentItem(
        request=CanonicalRequest(url="https://target.local/low"),
        priority=5,
        expected_info_gain=0.1
    )
    # High EIG item with same nominal priority
    it_high_eig = BurpExperimentItem(
        request=CanonicalRequest(url="https://target.local/high"),
        priority=5,
        expected_info_gain=0.9
    )

    queue.enqueue(it_low_eig)
    queue.enqueue(it_high_eig)

    # it_high_eig has rank 5*0.5 - 0.9*0.5 = 2.05 vs it_low_eig 5*0.5 - 0.1*0.5 = 2.45
    dispatched = queue.dispatch_next()
    assert dispatched is not None
    assert dispatched.experiment_id == it_high_eig.experiment_id


def test_experiment_queue_rate_limiting():
    limiter = TokenBucketRateLimiter(rate_per_second=2.0, capacity=2.0)
    assert limiter.allow_request() is True
    assert limiter.allow_request() is True
    # Bucket exhausted
    assert limiter.allow_request() is False


def test_experiment_queue_cancellation_and_metrics():
    queue = BurpExperimentQueue()
    item = BurpExperimentItem(request=CanonicalRequest(url="https://target.local/test"))
    eid = queue.enqueue(item)

    assert queue.get_metrics()["pending_in_queue"] == 1
    cancelled = queue.cancel(eid)
    assert cancelled is True
    assert queue.get_metrics()["cancelled"] == 1
    assert queue.get_metrics()["pending_in_queue"] == 0

    # Dispatching when empty returns None
    assert queue.dispatch_next() is None


# ── 5. BurpLiveEventStream Tests ────────────────────────────────────────────

def test_live_event_stream_sync_listener():
    stream = BurpLiveEventStream()
    received = []

    def on_event(evt):
        received.append(evt)

    stream.add_sync_listener(on_event)
    stream.publish_event("TEST_EVENT", {"payload": "hello"})

    assert len(received) == 1
    assert received[0].event_type == "TEST_EVENT"
    assert received[0].data["payload"] == "hello"


@pytest.mark.asyncio
async def test_live_event_stream_async_subscribe():
    stream = BurpLiveEventStream()

    async def reader():
        async for evt in stream.subscribe(event_filter=["FILTERED_EVENT"], timeout=0.5):
            return evt

    task = asyncio.create_task(reader())
    await asyncio.sleep(0.02)

    # Publish ignored event then target event
    stream.publish_event("IGNORED_EVENT", {})
    stream.publish_event("FILTERED_EVENT", {"match": True})

    result = await task
    assert result.event_type == "FILTERED_EVENT"
    assert result.data["match"] is True


def test_live_event_stream_bounded_ring_buffer():
    stream = BurpLiveEventStream(max_buffer_size=5)
    for i in range(10):
        stream.publish_event(f"EVENT_{i}", {"index": i})

    events = stream.get_recent_events(limit=10)
    assert len(events) == 5
    # Oldest events 0-4 should be evicted; 5-9 kept
    assert events[0].data["index"] == 5
    assert events[-1].data["index"] == 9


# ── 6. E2E Gateway REST API & AutonomousBrain Integration Tests ──────────────

def test_burp_gateway_research_endpoints():
    from fastapi.testclient import TestClient
    from core.burp_gateway.gateway import BurpGateway

    scope = ScopeGuard(in_scope=["api.target.local"])
    gw = BurpGateway(scope_engine=scope)
    client = TestClient(gw.app)

    # Seed an ingested transaction in the gateway
    can_tx = CanonicalTransaction(
        tx_id="tx_gw_test",
        source=TrafficSource.PROXY,
        correlation=BurpCorrelationContext(transaction_id="tx_gw_test"),
        request=CanonicalRequest(method="GET", url="https://api.target.local/api/item?id=1", host="api.target.local"),
        response=CanonicalResponse(status_code=403, body="Denied"),
        identity=CanonicalIdentity(),
        state=TargetStateContext(),
    )
    gw.research_controller.ingest_canonical(can_tx)

    # 1. Test /api/research/replay
    resp = client.post("/api/research/replay", json={
        "request_id": "tx_gw_test",
        "mutation": {"params": {"id": "102"}},
        "reason": "Testing Replay via Gateway"
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["receipt"]["status"] == "EXECUTED"

    # 2. Test /api/research/repeater
    resp2 = client.post("/api/research/repeater", json={
        "request_id": "tx_gw_test",
        "tab_name": "API-Tab-1"
    })
    assert resp2.status_code == 200
    assert resp2.json()["tab_id"] == "API-Tab-1"

    # 3. Test /api/research/queue
    resp3 = client.post("/api/research/queue", json={
        "url": "https://api.target.local/api/probe",
        "priority": 3,
        "eig": 0.85
    })
    assert resp3.status_code == 200
    assert "experiment_id" in resp3.json()

    # 4. Test /api/stream/events
    resp4 = client.get("/api/stream/events")
    assert resp4.status_code == 200
    assert "events" in resp4.json()


def test_burp_sensor_research_integration():
    sensor = BurpSensor()
    assert hasattr(sensor, "research_controller")
    assert hasattr(sensor, "experiment_queue")
    assert hasattr(sensor, "event_stream")

    # Ingest and verify active controller integration
    tx_ctx = CanonicalTransaction(
        tx_id="tx_sensor_test",
        source=TrafficSource.PROXY,
        correlation=BurpCorrelationContext(transaction_id="tx_sensor_test"),
        request=CanonicalRequest(method="GET", url="https://api.target.local/res?id=1", host="api.target.local"),
        response=CanonicalResponse(status_code=403),
        identity=CanonicalIdentity(),
        state=TargetStateContext(),
    )
    sensor.research_controller.ingest_canonical(tx_ctx)

    # Active replay directly from sensor
    res = sensor.replay("tx_sensor_test", mutation={"params": {"id": "102"}})
    assert res.receipt.status == ActionStatus.EXECUTED


def test_autonomous_brain_v26_binding():
    from core.brain.autonomous_brain import AutonomousBrain

    brain = AutonomousBrain(
        resource_manager=MagicMock(),
        tool_manager=MagicMock(),
        dry_run=True,
    )
    assert hasattr(brain, "burp_research_controller")
    assert brain.burp_research_controller is not None
    assert hasattr(brain, "burp_experiment_queue")
    assert brain.burp_experiment_queue is not None
    assert hasattr(brain, "burp_event_stream")
    assert brain.burp_event_stream is not None
    assert hasattr(brain, "burp_normalizer")
    assert brain.burp_normalizer is not None
