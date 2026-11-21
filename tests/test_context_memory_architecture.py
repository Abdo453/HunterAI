"""
Unit & Integration Tests for the 3-Pillar Anti-Context-Collapse Memory Architecture:
  1. Empirical Knowledge Graph (Trinity pattern)
  2. Persistent Task & Clue Cache + Triple Agents (MazeRunner pattern)
  3. Statistical RAG + Pre-Execution Syntax Validator (COAPT pattern)
  4. 7-Stage ReasoningLoopSkill Integration
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from agents.security_intelligence.task_clue_cache import TaskClueCache
from core.graph.knowledge_graph import KnowledgeGraph
from core.workspace_manager import WorkspaceManager
from hunter_ai.hypo_engine.rag_hypo import RAGHypothesisEngine
from hunter_ai.knowledge.rag_engine import PreExecutionSyntaxValidator, RAGEngine
from hunter_ai.orchestration.triple_agents import TripleAgentSystem
from skills.agent_core.reasoning_loop.skill import ReasoningLoopSkill
from skills.base_skill import SkillContext
from tools.tool_manager import ToolManager


def test_pillar1_empirical_knowledge_graph_and_persistence(tmp_path: Path):
    storage_dir = tmp_path / "memory"
    kg = KnowledgeGraph(root_asset="example.com", storage_dir=str(storage_dir))

    # Register verified host, open port, endpoint, and confirmed finding
    kg.register_host("api.example.com", ip_address="93.184.216.34", empirically_verified=True)
    kg.register_port_service("api.example.com", port=443, service_name="https", version="nginx/1.24", empirically_verified=True)
    kg.register_endpoint("/v1/orders", method="GET", params=["order_id", "user_id"], empirically_verified=True, host="api.example.com")
    kg.register_cve_finding(
        finding_id="F-001",
        host="api.example.com",
        vuln_class="IDOR",
        cve_id="CWE-639",
        severity="High",
        confidence=0.95,
        endpoint_or_port="GET:/v1/orders",
        empirically_verified=True,
        evidence_ref="HTTP 200 cross-tenant order record",
    )

    # Register an unverified hypothesis — should NOT pollute verified facts export
    kg.register_cve_finding(
        finding_id="F-UNVERIFIED",
        host="api.example.com",
        vuln_class="THEORETICAL_BUG",
        empirically_verified=False,
    )

    facts = kg.export_verified_facts_context()
    assert facts["verified_hosts_count"] == 1
    assert facts["verified_ports_count"] == 1
    assert facts["verified_endpoints_count"] == 1
    assert facts["verified_findings_count"] == 1
    assert "[FACT:HOST] api.example.com" in facts["facts_prompt"]
    assert "[FACT:PORT] api.example.com:443 -> https/nginx/1.24" in facts["facts_prompt"]
    assert "[FACT:FINDING] F-001: IDOR (CWE-639)" in facts["facts_prompt"]
    assert "F-UNVERIFIED" not in facts["facts_prompt"]

    # Test persistence on disk
    saved_path = kg.save()
    assert Path(saved_path).exists()

    kg_loaded = KnowledgeGraph(root_asset="example.com", storage_dir=str(storage_dir))
    assert kg_loaded.load() is True
    loaded_facts = kg_loaded.export_verified_facts_context()
    assert loaded_facts["verified_findings_count"] == 1
    assert loaded_facts["verified_ports_count"] == 1


def test_pillar2_task_clue_cache_and_triple_agents_recovery(tmp_path: Path):
    cache_file = tmp_path / "task_clue_cache.json"
    cache = TaskClueCache(storage_file=str(cache_file), persist=True)
    triple = TripleAgentSystem(graph_id="test_tdg", clue_cache=cache, persist_cache=True)

    target = "api.example.com"
    plan = triple.plan_and_execute(
        target=target,
        technique="bfla_auth_bypass_skill",
        description="Test privileged admin endpoint /api/v1/admin/export",
    )
    exec_task_id = plan["executor_task"]
    review_task_id = plan["reviewer_task"]

    # Simulate early-phase discovery of distant clues (an API token + an endpoint)
    cache.add_clue(
        target=target,
        source_tool="js_secret_hunter",
        clue_type="token",
        content="Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.admin",
        confidence=0.92,
    )
    cache.add_clue(
        target=target,
        source_tool="katana",
        clue_type="endpoint",
        content="/api/v1/admin/export",
        confidence=0.88,
    )

    # Simulate task blocked with 401/403 during review
    triple.execute_task(exec_task_id)
    triple.review_task(review_task_id, court_verdict="blocked")

    assert len(cache.get_failed_tasks()) == 1

    # Run Failure-Oriented Reviewer to recover missing prerequisites and link distant clues
    recovery_report = triple.review_and_recover_failed_tasks(target)
    assert recovery_report["failed_inspected"] == 1
    assert recovery_report["recovered_count"] == 1
    assert len(recovery_report["distant_clue_links"]) >= 1

    recovered_state = cache.get_task_state(review_task_id)
    assert recovered_state is not None
    assert recovered_state.status == "pending"
    assert len(recovered_state.clue_ids) >= 1


def test_pillar3_statistical_rag_and_pre_execution_syntax_validator():
    rag = RAGEngine()
    results = rag.retrieve_statistically("SQL injection database query parameter cwe-89", top_k=3, min_score=0.05)
    assert len(results) >= 1
    top = results[0]
    assert "statistical_breakdown" in top.metadata
    breakdown = top.metadata["statistical_breakdown"]
    assert "semantic_similarity" in breakdown
    assert "prevalence_weight" in breakdown
    assert "historical_success_rate" in breakdown
    assert "final_score" in breakdown

    # Record outcome and verify statistical update
    stats_after = rag.record_technique_outcome(top.item_id, success=True)
    assert stats_after["success"] == 3
    assert stats_after["total"] == 4

    # Pre-Execution Syntax Validator checks
    v_ok = PreExecutionSyntaxValidator.validate_command_syntax(
        "httpx -u <target> -silent -status-code",
        allowed_tools=["httpx", "nuclei", "subfinder"],
        target="https://example.com",
    )
    assert v_ok["valid"] is True
    assert "https://example.com" in v_ok["repaired_command"]
    assert v_ok["tool"] == "httpx"

    # Unresolved placeholder must be caught before execution
    v_bad_ph = PreExecutionSyntaxValidator.validate_command_syntax("nuclei -u <target> -t cves/")
    assert v_bad_ph["valid"] is False
    assert "placeholder" in v_bad_ph["reason"].lower()

    # Malformed flag must be caught
    v_bad_flag = PreExecutionSyntaxValidator.validate_command_syntax("httpx ---invalid-flag https://example.com")
    assert v_bad_flag["valid"] is False


def test_pillar4_7stage_reasoning_loop_integration(tmp_path: Path):
    ws = WorkspaceManager(str(tmp_path / "ws"))
    tm = ToolManager()
    kg = KnowledgeGraph(root_asset="example.com", storage_dir=str(tmp_path / "mem"))
    cache = TaskClueCache(storage_file=str(tmp_path / "mem" / "clues.json"), persist=True)
    triple = TripleAgentSystem(graph_id="loop_test", clue_cache=cache, persist_cache=True)

    ctx = SkillContext(
        target="example.com",
        session_id="sess_01",
        workspace=ws,
        tool_manager=tm,
        extra={
            "phase": "web",
            "findings_so_far": [
                {
                    "task_id": "F-101",
                    "title": "IDOR on user_id parameter",
                    "vuln_class": "IDOR",
                    "target": "example.com",
                    "verdict": "CONFIRMED",
                    "confidence": 0.91,
                    "url": "https://example.com/api/profile?user_id=123",
                }
            ],
            "surface": {
                "domains": ["api.example.com"],
                "live_hosts": ["https://api.example.com"],
                "endpoints": ["https://api.example.com/api/profile?user_id=123"],
                "open_ports": ["api.example.com:443"],
            },
            "scope_authorized": True,
            "knowledge_graph": kg,
            "clue_cache": cache,
            "triple_agents": triple,
        },
    )

    skill = ReasoningLoopSkill()
    res = asyncio.run(skill.execute(ctx))
    assert res.success is True

    trace = json.loads(res.raw_output["thinking_trace"])
    assert [step["stage"] for step in trace] == [
        "Observe",
        "Think",
        "Plan",
        "Act",
        "Parse",
        "Update Graph",
        "Decide",
    ]
    # Check Observe has verified_facts_prompt
    assert "[FACT:" in trace[0]["data"]["verified_facts_prompt"]
    # Check Think has rag_hypotheses
    assert isinstance(trace[1]["data"]["rag_hypotheses"], list)
    # Check Act has syntax_validation
    assert trace[3]["data"]["syntax_validation"]["valid"] is True
    # Check Update Graph persisted verified facts
    assert trace[5]["data"]["verified_facts"]["verified_findings_count"] >= 1
    # Check Decide includes reviewer_recovery
    assert "reviewer_recovery" in trace[6]["data"]


def test_law1_law2_law3_deterministic_3plane_architecture(tmp_path: Path):
    import pytest
    from core.architecture.deterministic_planes import (
        AgentStateMachine,
        DeterministicControlPlane,
        ExecutionPlane,
        FSMState,
        ReasoningIntent,
        ReasoningPlane,
    )

    kg = KnowledgeGraph(root_asset="example.com", storage_dir=str(tmp_path / "mem"))
    kg.register_host("api.example.com", empirically_verified=True)

    control = DeterministicControlPlane(
        target="example.com",
        scope_domains=["example.com"],
        phase="web",
    )
    reasoning = ReasoningPlane()
    execution = ExecutionPlane()

    # Law 2: Illegal FSM transition (skipping GATE_VERIFICATION from THINKING -> EXECUTING) must fail deterministically
    control.fsm.transition_to(FSMState.OBSERVING)
    control.fsm.transition_to(FSMState.THINKING)
    with pytest.raises(RuntimeError):
        control.fsm.transition_to(FSMState.EXECUTING)

    # Legal transition to PLANNING
    control.fsm.transition_to(FSMState.PLANNING)
    compact = control.fsm.export_compact_state(kg)
    assert compact["chat_history_messages_retained"] == 0
    assert "[FACT:HOST] api.example.com" in compact["verified_facts_prompt"]

    # Law 1: ReasoningPlane formulates intent; ControlPlane validates & signs; ExecutionPlane verifies HMAC
    intent = reasoning.formulate_intent(
        compact,
        {"next_tool": "httpx", "next_skill": "idor_tester", "confidence": 0.85, "reasoning": "Probe verified host"},
        target="api.example.com",
    )
    directive = control.authorize_intent(intent, target="api.example.com")
    assert directive.safety_decision.allowed is True
    assert directive.safety_decision.directive_token is not None

    exec_res = execution.execute_directive(directive, control)
    assert exec_res["executed"] is True
    assert control.fsm.current_state == FSMState.EXECUTING

    # Law 1 tampering check: ExecutionPlane must reject a tampered/unsigned directive
    control_tamper = DeterministicControlPlane(target="example.com", scope_domains=["example.com"])
    control_tamper.fsm.transition_to(FSMState.OBSERVING)
    control_tamper.fsm.transition_to(FSMState.THINKING)
    control_tamper.fsm.transition_to(FSMState.PLANNING)
    tampered_directive = control_tamper.authorize_intent(
        intent, target="api.example.com"
    )
    tampered_directive.safety_decision.directive_token = "forged-hmac-token"
    with pytest.raises(PermissionError):
        execution.execute_directive(tampered_directive, control_tamper)

    # Law 3: Deterministic Code-Enforced Scope Block (even if LLM injects an out-of-scope URL in command args)
    control_oos = DeterministicControlPlane(target="example.com", scope_domains=["example.com"])
    control_oos.fsm.transition_to(FSMState.OBSERVING)
    control_oos.fsm.transition_to(FSMState.THINKING)
    control_oos.fsm.transition_to(FSMState.PLANNING)
    oos_intent = ReasoningIntent(
        phase="web",
        classifications=[],
        proposed_tool="httpx",
        proposed_skill=None,
        proposed_command="httpx -u https://unauthorized-external-domain.org/admin",
        confidence=0.9,
        rationale="Hallucinated out-of-scope target",
    )
    oos_dir = control_oos.authorize_intent(oos_intent, target="example.com")
    assert oos_dir.safety_decision.allowed is False
    assert "unauthorized-external-domain.org" in oos_dir.safety_decision.policy_reason
    assert control_oos.fsm.current_state == FSMState.HALTED_BLOCKED

    # Law 3: Deterministic Shell Chaining / Destructive Command Block
    control_inj = DeterministicControlPlane(target="example.com", scope_domains=["example.com"])
    control_inj.fsm.transition_to(FSMState.OBSERVING)
    control_inj.fsm.transition_to(FSMState.THINKING)
    control_inj.fsm.transition_to(FSMState.PLANNING)
    inj_intent = ReasoningIntent(
        phase="web",
        classifications=[],
        proposed_tool="httpx",
        proposed_skill=None,
        proposed_command="httpx -u https://example.com; rm -rf /tmp/data",
        confidence=0.9,
        rationale="Injected command chain",
    )
    inj_dir = control_inj.authorize_intent(inj_intent, target="example.com")
    assert inj_dir.safety_decision.allowed is False
    assert "forbidden pattern" in inj_dir.safety_decision.policy_reason.lower()


def test_binary_framed_websocket_protocol_codec():
    from core.protocols.websocket_agent import BinaryFramedProtocolCodec

    # Varint roundtrip
    for n in (0, 1, 127, 128, 16384, 1 << 20):
        enc = BinaryFramedProtocolCodec.encode_varint(n)
        dec, off = BinaryFramedProtocolCodec.decode_varint(enc, 0)
        assert dec == n and off == len(enc)

    # Request frame + partial buffer reassembly
    raw = BinaryFramedProtocolCodec.encode_request(42, "service.room.enter", {"roomId": 1})
    partial_buf = bytearray(raw[:5])
    pkgs, consumed = BinaryFramedProtocolCodec.decode_packages_from_buffer(partial_buf)
    assert pkgs == [] and consumed == 0

    partial_buf.extend(raw[5:])
    pkgs, consumed = BinaryFramedProtocolCodec.decode_packages_from_buffer(partial_buf)
    assert len(pkgs) == 1 and consumed == len(raw)

    msg = BinaryFramedProtocolCodec.decode_message(pkgs[0][1])
    assert msg["type"] == "request"
    assert msg["req_id"] == 42
    assert msg["route"] == "service.room.enter"
    assert msg["body"] == {"roomId": 1}


def test_live_local_server_omnihunter_end_to_end(tmp_path: Path):
    import socket
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from core.engine.omni_hunter_engine import AssessmentConfig, OmniHunterEngine

    class LocalLabHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Server", "Apache/2.2.8 (Ubuntu) DAV/2")
            self.send_header("X-Powered-By", "PHP/5.2.4")
            self.end_headers()
            html = (
                "<html><body>"
                "<a href='/dvwa/login.php?id=1'>DVWA</a>"
                "<a href='/mutillidae/index.php?page=user-info.php'>Mutillidae</a>"
                "<form action='/api/v1/profile' method='POST'>"
                "<input name='user_id' value='101'/>"
                "</form>"
                "</body></html>"
            )
            self.wfile.write(html.encode("utf-8"))

    server = HTTPServer(("127.0.0.1", 0), LocalLabHandler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        target_url = f"http://127.0.0.1:{port}"
        cfg = AssessmentConfig(
            target_url=target_url,
            scope_domains=["127.0.0.1", f"127.0.0.1:{port}"],
            max_cycles=3,
            enable_browser=False,
            enable_burp=False,
            enable_elite_skills=False,
            snapshot_dir=str(tmp_path / "snaps"),
        )
        engine = OmniHunterEngine(cfg)
        engine._run_recon_phase()
        engine._run_web_phase()
        engine._run_verification_phase()

        # Verify real server tech detected (Apache & PHP, NOT fake Cloudflare!)
        assert engine.surface.get("waf_name") is None
        assert "apache" in engine.surface.get("tech_stack", [])
        assert "php" in engine.surface.get("tech_stack", [])
        # Verify real links discovered from HTML
        discovered_eps = " ".join(engine.surface.get("endpoints", []))
        assert "/dvwa/login.php?id=1" in discovered_eps
        assert "/mutillidae/index.php?page=user-info.php" in discovered_eps
    finally:
        server.shutdown()
        server.server_close()



