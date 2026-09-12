"""
Tests for HunterAI Full Computer Security Agent
================================================
Comprehensive verification of:
1. Immutable PolicyGate (Destructive command prevention & Scope enforcement)
2. ComputerControl (Terminal execution, Audited history, Filesystem operations)
3. FailureMemory (Anti-Loop mechanism: do_not_repeat_without_new_evidence)
4. AuthContextManager (Multi-role session tracking & IDOR differential test generation)
5. ToolRegistry & CapabilityMatrix (Risk gating & Authorization checks)
6. DecisionCore (Signal-driven track dispatching: WordPress, GraphQL, SSRF)
7. StageManifest & Confidence != Verification rule in EvidenceGraph
8. TrafficBridge (Network event ingestion into traffic.db & EvidenceGraph)
"""
import json
import os
import pytest
from pathlib import Path

from core.scope_engine import ScopePolicy
from core.control_plane.policy_gate import (
    PolicyGate,
    ActionCategory,
    ActionRequest,
    PolicyDecision,
)
from core.control_plane.computer_control import ComputerControl, ExecutionRecord
from core.memory.failure_memory import FailureMemory
from core.auth_context import AuthContextManager, AuthRole
from core.tool_registry import ToolRegistry, CapabilityMatrix, ToolCategory, RiskLevel
from core.decision_core import DecisionCore, AttackTrack
from core.evidence_graph import (
    EvidenceGraph,
    DeterministicEvidenceValidator,
    NodeStatus,
    StageManifest,
)
from core.browser.traffic_bridge import TrafficBridge


# ── 1. POLICY GATE TESTS ──────────────────────────────────────────────────────

def test_policy_gate_blocks_destructive_commands():
    """Verify PolicyGate unconditionally blocks destructive commands regardless of target"""
    policy = ScopePolicy(allowed_targets=["test.local"])
    gate = PolicyGate(scope_policy=policy, authorized=True)

    req = ActionRequest(
        category=ActionCategory.TERMINAL_COMMAND,
        target="test.local",
        command="rm -rf / --no-preserve-root",
        reason="Testing destructive bomb block"
    )
    decision = gate.evaluate(req)
    assert decision.allowed is False
    assert "Destructive command pattern" in decision.reason


def test_policy_gate_enforces_cloud_metadata_inviolable():
    """Verify cloud metadata remains blocked even when lab_mode and authorized are True"""
    policy = ScopePolicy(
        allowed_targets=["10.0.0.0/8", "169.254.169.254"],
        allow_private_ips_override=True
    )
    gate = PolicyGate(scope_policy=policy, authorized=True)

    req = ActionRequest(
        category=ActionCategory.HTTP_REQUEST,
        target="169.254.169.254",
        url="http://169.254.169.254/latest/meta-data/",
        reason="Testing metadata bypass"
    )
    decision = gate.evaluate(req)
    assert decision.allowed is False
    assert "inviolable subnet" in decision.reason.lower()


def test_policy_gate_allows_valid_authorized_action():
    """Verify valid targets within scope pass cleanly"""
    policy = ScopePolicy(allowed_targets=["api.target.com", "*.target.com"])
    gate = PolicyGate(scope_policy=policy, authorized=False)

    req = ActionRequest(
        category=ActionCategory.BROWSER_NAVIGATE,
        target="api.target.com",
        url="https://api.target.com/v1/health",
        reason="Passive observation"
    )
    decision = gate.evaluate(req)
    assert decision.allowed is True
    assert "Authorized within verified engagement scope" in decision.reason


# ── 2. COMPUTER CONTROL TESTS ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_computer_control_terminal_execution_and_audit(tmp_path):
    """Verify terminal executor runs command, captures outputs, and logs JSONL audit"""
    policy = ScopePolicy(allowed_targets=["target.com"])
    gate = PolicyGate(scope_policy=policy, authorized=True)
    ctrl = ComputerControl(workspace_dir=str(tmp_path), policy_gate=gate)

    rec = await ctrl.execute_command(
        command="python -c \"print('HunterAI Control Plane OK')\"",
        tool="python",
        stage="init",
        reason="Health check",
        timeout=10,
    )
    assert rec.exit_code == 0
    assert rec.success is True
    assert "HunterAI Control Plane OK" in rec.stdout
    assert rec.duration_ms > 0

    # Verify audit log JSONL file exists and contains record
    audit_file = tmp_path / "terminal_history.jsonl"
    assert audit_file.exists()
    with open(audit_file, "r", encoding="utf-8") as f:
        line = f.readline()
        entry = json.loads(line)
        assert entry["tool"] == "python"
        assert entry["exit_code"] == 0


def test_computer_control_filesystem_operations(tmp_path):
    """Verify filesystem sandbox operations within workspace"""
    policy = ScopePolicy(allowed_targets=["target.com"])
    gate = PolicyGate(scope_policy=policy)
    ctrl = ComputerControl(workspace_dir=str(tmp_path), policy_gate=gate)

    # 1. Write file
    ok, path = ctrl.write_file("evidence/sample.txt", "Canary Data 12345")
    assert ok is True
    assert Path(path).exists()

    # 2. Read file
    ok, content = ctrl.read_file("evidence/sample.txt")
    assert ok is True
    assert content == "Canary Data 12345"

    # 3. List directory
    items = ctrl.list_directory("evidence")
    assert len(items) == 1
    assert items[0]["name"] == "sample.txt"

    # 4. Search files
    matches = ctrl.search_files("*.txt")
    assert len(matches) == 1
    assert "sample.txt" in matches[0]


# ── 3. FAILURE MEMORY TESTS ──────────────────────────────────────────────────

def test_failure_memory_anti_loop_policy(tmp_path):
    """Verify failure memory prevents repeating identical failed actions without new evidence"""
    mem_file = tmp_path / "failure_memory.json"
    mem = FailureMemory(storage_file=str(mem_file))

    action = "ffuf_fuzzing"
    target = "https://api.target.com/admin"

    # Before failure: execution allowed
    should_run, _ = mem.should_execute(action, target)
    assert should_run is True

    # Record failure with initial evidence fingerprint
    mem.record_failure(action, target, "404 Not Found", evidence_fingerprint="fp_baseline")

    # Repeat with SAME fingerprint: blocked
    should_run, reason = mem.should_execute(action, target, current_evidence_fingerprint="fp_baseline")
    assert should_run is False
    assert "Anti-Loop" in reason

    # With NEW evidence fingerprint: allowed
    should_run, _ = mem.should_execute(action, target, current_evidence_fingerprint="fp_new_auth_token")
    assert should_run is True


def test_failure_memory_rejected_hypothesis_tracking(tmp_path):
    """Verify rejected hypotheses are stored and queried"""
    mem = FailureMemory(storage_file=str(tmp_path / "mem.json"))
    hyp_key = "idor::/api/v1/user::id"

    assert mem.is_hypothesis_rejected(hyp_key) is False
    mem.record_rejected_hypothesis(hyp_key, "Differential check yielded identical responses")
    assert mem.is_hypothesis_rejected(hyp_key) is True


# ── 4. AUTH CONTEXT MANAGER TESTS ────────────────────────────────────────────

def test_auth_context_multi_role_differential(tmp_path):
    """Verify authentication context registers roles and formulates differential IDOR tests"""
    auth_dir = tmp_path / "auth_context"
    mgr = AuthContextManager(storage_dir=str(auth_dir))

    # Register User A (owner of resource 101)
    mgr.register_user(
        role=AuthRole.USER_A,
        username="alice",
        cookies={"session": "alice_cookie_123"},
        tokens={"bearer_token": "token_alice"},
        owned_object_ids=["101"]
    )

    # Register User B (attacker / tester)
    mgr.register_user(
        role=AuthRole.USER_B,
        username="bob",
        cookies={"session": "bob_cookie_456"},
        tokens={"bearer_token": "token_bob"},
        owned_object_ids=["102"]
    )

    # Generate differential test for object 101
    diff_test = mgr.generate_differential_test(
        endpoint="/api/v1/users/101",
        method="GET",
        target_object_id="101",
        owner_role=AuthRole.USER_A,
        tester_role=AuthRole.USER_B
    )

    assert diff_test is not None
    assert diff_test.tester_role == AuthRole.USER_B
    assert diff_test.test_headers["Authorization"] == "Bearer token_bob"
    assert diff_test.test_cookies["session"] == "bob_cookie_456"
    assert "user_b to access object '101' owned by user_a" in diff_test.hypothesis_text


# ── 5. TOOL REGISTRY & CAPABILITY MATRIX TESTS ────────────────────────────────

def test_tool_registry_and_capability_matrix():
    """Verify tool categories, risk gating, and authorization limits"""
    # 1. Unauthorized mode
    safe_caps = CapabilityMatrix(authorized=False)
    registry = ToolRegistry(capability_matrix=safe_caps)

    # Passive low-risk tool allowed
    subfinder = registry.get_tool("subfinder")
    assert subfinder is not None
    allowed, _ = registry.is_action_allowed("subfinder")
    assert allowed is True

    # High-risk active tool blocked without authorization
    allowed, reason = registry.is_action_allowed("nuclei")
    assert allowed is False
    assert "requires explicit authorization" in reason

    # 2. Authorized mode
    auth_caps = CapabilityMatrix(authorized=True)
    auth_registry = ToolRegistry(capability_matrix=auth_caps)
    allowed, _ = auth_registry.is_action_allowed("nuclei")
    assert allowed is True


# ── 6. DYNAMIC DECISION CORE TESTS ───────────────────────────────────────────

def test_decision_core_signal_dispatching():
    """Verify DecisionCore dispatches appropriate tracks based on technology and path signals"""
    registry = ToolRegistry()
    core = DecisionCore(tool_registry=registry)

    # Signal: WordPress
    recs = core.evaluate_signals(
        target_host="blog.target.com",
        endpoints=["/wp-json/wp/v2/posts", "/wp-content/themes/"],
        parameters=[],
        technologies=["WordPress 6.4", "PHP 8.2"],
    )
    tracks = [r.track for r in recs]
    assert AttackTrack.WORDPRESS in tracks
    assert "wpscan" in recs[0].recommended_tools

    # Signal: GraphQL
    recs_gql = core.evaluate_signals(
        target_host="api.target.com",
        endpoints=["/v1/graphql"],
        parameters=[],
        technologies=["Node.js", "Express"],
    )
    tracks_gql = [r.track for r in recs_gql]
    assert AttackTrack.GRAPHQL in tracks_gql

    # Signal: Redirect parameter
    recs_ssrf = core.evaluate_signals(
        target_host="auth.target.com",
        endpoints=["/login"],
        parameters=["redirect", "client_id"],
        technologies=["Nginx"],
    )
    tracks_ssrf = [r.track for r in recs_ssrf]
    assert AttackTrack.REDIRECT_SSRF in tracks_ssrf


# ── 7. STAGE MANIFEST & CONFIDENCE != VERIFICATION TESTS ─────────────────────

def test_stage_manifest_serialization(tmp_path):
    """Verify StageManifest creates and saves valid stage lifecycle metadata"""
    manifest = StageManifest(
        stage="09_javascript",
        started_at="2026-09-12T10:00:00Z",
        completed_at="2026-09-12T10:02:15Z",
        inputs=["data/engagements/target/08_crawl/urls.json"],
        outputs=["data/engagements/target/09_javascript/endpoints.json"],
        artifacts=["raw.txt", "parsed.json", "lineage.json"],
        status="completed"
    )
    out_file = manifest.save(str(tmp_path / "09_javascript"))
    assert Path(out_file).exists()

    with open(out_file, "r", encoding="utf-8") as f:
        data = json.load(f)
        assert data["stage"] == "09_javascript"
        assert len(data["artifacts"]) == 3


def test_confidence_does_not_equal_verification():
    """
    Verify rule: 'Confidence != Verification'.
    High confidence without verified differential hashes remains CANDIDATE, not VERIFIED.
    """
    graph = EvidenceGraph("target.com")
    p = graph.get_or_create_parameter("api.target.com", "https://api.target.com/user", "/user", "user_id")

    # Attach partial evidence without request/response hashes
    from core.evidence_graph import EvidenceItem
    unverified_ev = EvidenceItem(
        evidence_type="heuristic",
        request_hash="",
        response_hash="",
        differential_analysis="Observation only, no differential replay yet"
    )
    p.evidence.append(unverified_ev)
    p.confidence_score = 0.95  # High confidence

    finding = DeterministicEvidenceValidator.decide_finding(p, "https://api.target.com/user", "IDOR")
    assert finding is not None
    # Must be CANDIDATE, NOT confirmed/verified!
    assert finding["status"] == "CANDIDATE"
    assert p.status == NodeStatus.CANDIDATE


# ── 8. TRAFFIC BRIDGE TESTS ──────────────────────────────────────────────────

def test_traffic_bridge_ingests_and_updates_graph(tmp_path):
    """Verify TrafficBridge ingests network requests into SQLite and feeds EvidenceGraph"""
    db_file = tmp_path / "test_traffic.db"
    graph = EvidenceGraph("target.com")

    discovered = []
    def on_endpoint(host, path, params):
        discovered.append((host, path, params))

    bridge = TrafficBridge(
        db_path=str(db_file),
        evidence_graph=graph,
        on_new_endpoint_cb=on_endpoint
    )

    # Simulate intercepted Playwright request
    bridge.ingest_request({
        "url": "https://api.target.com/v1/users?org_id=99&limit=10",
        "method": "GET",
        "headers": {"User-Agent": "HunterAI-Browser"},
        "resource_type": "fetch",
        "timestamp": 1234567.89
    })

    assert bridge.get_captured_endpoints_count() == 1
    assert len(discovered) == 1
    assert discovered[0] == ("api.target.com", "/v1/users", ["org_id", "limit"])

    # Verify EvidenceGraph received the parameters
    tree = graph.to_dict()
    assert "api.target.com" in tree["subdomains"]
    ep = tree["subdomains"]["api.target.com"]["endpoints"]["GET:https://api.target.com/v1/users?org_id=99&limit=10"]
    assert "org_id" in ep["parameters"]
    assert "limit" in ep["parameters"]


# ── 9. AUTONOMOUS ACTION LOOP TEST ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_autonomous_action_loop_cycle(tmp_path):
    """Verify AutonomousActionLoop coordinates observe->think->plan->act->validate->decide"""
    from core.control_plane.action_loop import AutonomousActionLoop

    policy = ScopePolicy(allowed_targets=["test.target.com"])
    gate = PolicyGate(scope_policy=policy, authorized=True)
    ctrl = ComputerControl(workspace_dir=str(tmp_path), policy_gate=gate)
    graph = EvidenceGraph("test.target.com")
    registry = ToolRegistry()
    decision_core = DecisionCore(tool_registry=registry)
    fail_mem = FailureMemory(storage_file=str(tmp_path / "fail.json"))

    events = []
    def progress_cb(evt):
        events.append(evt["phase"])

    loop = AutonomousActionLoop(
        target_domain="test.target.com",
        policy_gate=gate,
        computer_control=ctrl,
        evidence_graph=graph,
        decision_core=decision_core,
        failure_memory=fail_mem,
        progress_cb=progress_cb,
    )

    cycle_res = await loop.run_cycle(
        active_endpoints=["/v1/graphql", "/login?redirect=test"],
        active_parameters=["redirect"],
        detected_technologies=["Node.js"],
        raw_evidence=["GraphQL endpoint exposed"],
    )

    assert cycle_res.cycle_index == 1
    assert cycle_res.hypotheses_proposed >= 1
    assert "start" in events
    assert "observe" in events
    assert "think" in events
    assert "plan" in events
    assert "complete" in events

