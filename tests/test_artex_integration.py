"""
Unit and Integration Tests for ARTEX-Grade Subsystems:
1. Dual-Graph Architecture (Asset Graph, Exploration Graph, and Anchors)
2. Worker Trace Exchange Engine (Multi-worker activity observation sharing)
3. Dependency-Chain Attack Planner (Persistent shared todolist with prerequisite gates)
4. Traffic Recorder & Evidence Store (Cryptographic exchange recording & evidence binding)
5. Tool Interceptor Gate (Pre-execution command safety & scope enforcement)
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.architecture.dual_graph import (
    AssetKind,
    DualGraphManager,
    ExplorationEdgeType,
    ExplorationKind,
)
from core.guard.interceptor_gate import InterceptAction, ToolInterceptorGate
from core.memory.worker_trace_exchange import WorkerTraceStore
from core.task_planner.dependency_chain_planner import (
    DependencyChainPlanner,
    MilestoneStatus,
)
from core.traffic.traffic_recorder import TrafficRecorder


def test_dual_graph_asset_and_exploration_anchors():
    graph = DualGraphManager()

    # 1. Asset Graph Hierarchy
    comp = graph.upsert_asset(kind=AssetKind.COMPANY, value="Acme Corp")
    sub = graph.upsert_asset(kind=AssetKind.SUBDOMAIN, value="api.acme.com", parent_id=comp.id)
    ep = graph.upsert_asset(kind=AssetKind.ENDPOINT, value="/v1/users", parent_id=sub.id)

    assert len(graph.list_assets()) == 3
    # Check deduplication
    sub_duplicate = graph.upsert_asset(kind=AssetKind.SUBDOMAIN, value="API.ACME.COM", parent_id=comp.id)
    assert sub_duplicate.id == sub.id
    assert len(graph.list_assets()) == 3

    # 2. Exploration Graph Nodes
    goal = graph.add_exploration_node(
        kind=ExplorationKind.GOAL,
        title="Extract User Database",
        task_id="task_101",
    )
    intent = graph.add_exploration_node(
        kind=ExplorationKind.INTENT,
        title="Probe /v1/users for BOLA",
        task_id="task_101",
        anchored_asset_ids=[ep.id],
    )
    fact = graph.add_exploration_node(
        kind=ExplorationKind.FACT,
        title="Endpoint /v1/users reflects SSN",
        task_id="task_101",
        anchored_asset_ids=[ep.id],
    )
    finding = graph.add_exploration_node(
        kind=ExplorationKind.FINDING,
        title="BOLA Confirmed on /v1/users",
        task_id="task_101",
        anchored_asset_ids=[ep.id],
    )

    # 3. Edges & Lineage
    graph.add_edge(goal.id, intent.id, ExplorationEdgeType.SPAWNS, task_id="task_101")
    graph.add_edge(intent.id, fact.id, ExplorationEdgeType.YIELDS, task_id="task_101")
    graph.add_edge(fact.id, finding.id, ExplorationEdgeType.PROVES, task_id="task_101")

    # 4. Bidirectional Anchors Verification
    anchored_assets = graph.get_anchored_assets(finding.id)
    assert len(anchored_assets) == 1
    assert anchored_assets[0].value == "/v1/users"

    anchored_exps = graph.get_anchored_exploration(ep.id)
    assert len(anchored_exps) == 3  # intent, fact, finding

    # 5. Lineage Traversal
    chain = graph.get_exploration_chain(goal.id)
    assert len(chain) == 3
    assert [e[1] for e in chain] == ["spawns", "yields", "proves"]


def test_worker_trace_exchange_search_and_retrieve():
    store = WorkerTraceStore()

    # Worker A executes step revealing a secret token in output
    step_a1 = store.record_step(
        intent_id="intent_12",
        worker_id="worker_alpha",
        tool_name="curl",
        command_or_input="curl -s http://target/internal/debug",
        full_output="200 OK - DEBUG MODE: JWT_SECRET=super_secret_jwt_key_9981 in memory.",
    )

    # Worker B executes step
    step_b1 = store.record_step(
        intent_id="intent_34",
        worker_id="worker_beta",
        tool_name="jwt_tool",
        command_or_input="jwt_tool --verify",
        full_output="Token signature invalid without secret.",
    )

    # Worker B searches for "super_secret" across other workers
    hits = store.search_all_worker_traces(
        query="super_secret",
        caller_worker_id="worker_beta",
        caller_intent_id="intent_34",
    )

    assert len(hits) == 1
    hit = hits[0]
    assert hit.worker_id == "worker_alpha"
    assert hit.intent_id == "intent_12"
    assert "super_secret_jwt_key_9981" in hit.summary_snippet

    # Worker B retrieves full trace of Intent 12
    trace = store.get_worker_trace(intent_id="intent_12")
    assert len(trace) == 1
    assert trace[0].step_id == step_a1.step_id
    assert "JWT_SECRET=super_secret_jwt_key_9981" in trace[0].full_output


def test_dependency_chain_planner_lifecycle():
    graph = DualGraphManager()
    planner = DependencyChainPlanner(task_id="task_202", graph=graph)

    # Stage 1: Recon
    m1 = planner.add_milestone(
        stage_name="Reconnaissance",
        description="Discover endpoints on target",
    )
    # Stage 2: Exploit (Requires Stage 1 DONE and Fact keyword 'admin_endpoint')
    m2 = planner.add_milestone(
        stage_name="PrivilegeEscalation",
        description="Exploit admin endpoint",
        prerequisites=[m1.milestone_id],
        required_fact_keyword="admin_endpoint",
    )

    # First wake: M1 should be dispatched as intent, M2 blocked
    intent1 = planner.evaluate_and_dispatch_next()
    assert intent1 is not None
    assert "Reconnaissance" in intent1.title
    assert m1.status == MilestoneStatus.IN_PROGRESS
    assert m2.status == MilestoneStatus.BLOCKED

    # Second wake while M1 is in progress: No new intent should dispatch
    assert planner.evaluate_and_dispatch_next() is None

    # M1 completes and yields a fact in graph
    fact = graph.add_exploration_node(
        kind=ExplorationKind.FACT,
        title="Discovered admin_endpoint at /api/admin",
        task_id="task_202",
    )
    planner.mark_milestone_completed(m1.milestone_id, fact_id=fact.id)

    # Third wake: M1 is DONE, fact is verified -> M2 dispatches!
    intent2 = planner.evaluate_and_dispatch_next()
    assert intent2 is not None
    assert "PrivilegeEscalation" in intent2.title
    assert m2.status == MilestoneStatus.IN_PROGRESS

    # Overview
    ov = planner.get_progress_overview()
    assert ov["completed"] == 1
    assert ov["in_progress"] == 1


def test_traffic_recorder_and_evidence_binding(tmp_path: Path):
    db_file = str(tmp_path / "traffic.sqlite")
    recorder = TrafficRecorder(db_path=db_file)

    # Record exchange
    exc = recorder.record_exchange(
        url="http://127.0.0.1:8080/api/v1/user/10",
        method="GET",
        status_code=200,
        req_headers={"Authorization": "Bearer hacker_token"},
        req_body="",
        resp_headers={"Content-Type": "application/json"},
        resp_body='{"user_id": 10, "email": "victim@corp.com", "role": "admin"}',
        duration_ms=45.2,
    )

    assert exc.exchange_id.startswith("exch_")
    assert len(exc.resp_hash) == 64  # SHA-256

    # Search traffic
    hits = recorder.search_traffic("victim@corp.com")
    assert len(hits) == 1
    assert hits[0].exchange_id == exc.exchange_id

    # Bind evidence to finding
    finding_id = "FIND-BOLA-001"
    recorder.bind_evidence_to_finding(finding_id, [exc.exchange_id])

    evidence = recorder.get_evidence_for_finding(finding_id)
    assert len(evidence) == 1
    assert evidence[0].status_code == 200
    assert "victim@corp.com" in evidence[0].resp_body


def test_tool_interceptor_gate_safety():
    gate = ToolInterceptorGate(allowed_scope=["127.0.0.1", "target.local"])

    # 1. Block destructive filesystem formatting / deletion
    allowed1, reason1 = gate.evaluate_pre_tool_use("bash", {"command": "rm -rf / --no-preserve-root"})
    assert allowed1 is False
    assert "destructive" in reason1.lower()

    allowed2, reason2 = gate.evaluate_pre_tool_use("bash", {"command": "mkfs.ext4 /dev/sda1"})
    assert allowed2 is False

    # 2. Block out-of-scope target
    allowed3, reason3 = gate.evaluate_pre_tool_use("httpx", {"target": "http://malicious-external-bank.com"})
    assert allowed3 is False
    assert "outside" in reason3.lower() and "authorized scope" in reason3.lower()

    # 3. Allow authorized in-scope tool call
    allowed4, reason4 = gate.evaluate_pre_tool_use("nmap", {"target": "http://127.0.0.1:8080", "command": "nmap -sV 127.0.0.1"})
    assert allowed4 is True

    # Audit log verification
    assert len(gate.audit_log) == 4
    assert gate.audit_log[0].action == InterceptAction.BLOCK
    assert gate.audit_log[3].action == InterceptAction.ALLOW
