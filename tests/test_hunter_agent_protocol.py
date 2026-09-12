"""
Unit and Integration Tests for Hunter Agent Protocol v1 & Blackboard Memory System
"""
import os
import json
import pytest
import sqlite3
import asyncio
from pathlib import Path

from hunter_ai.protocol.contract import AgentContract, ModelTierPreference
from hunter_ai.protocol.blackboard import (
    ThreeTierBlackboardMemory,
    Level1Summary,
    Level2EvidenceItem
)
from hunter_ai.protocol.handoff import HandoffEnvelope, HandoffPriority
from hunter_ai.protocol.result import StructuredTaskResult, StructuredFinding
from hunter_ai.brain.model_router import AIModelRouter, TaskIntent
from hunter_ai.brain.memory_hierarchy import MemoryHierarchy
from hunter_ai.brain.agent_manager import HunterAgentManager, BaseContractAgent
from hunter_ai.agents.recon_contract_agent import ReconContractAgent
from hunter_ai.agents.web_contract_agent import WebContractAgent
from hunter_ai.agents.report_contract_agent import ReportContractAgent


# ─────────────────────────────────────────────────────────────────────────────
# 1. Agent Contract Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_agent_contract_declaration_and_matching():
    contract = AgentContract(
        name="ReconAgent",
        skills=["subdomain discovery", "port scanning", "technology detection"],
        input_format="TargetDomain_v1",
        output_format="ReconReport_v1",
        preferred_model_tier=ModelTierPreference.CLOUD_FAST
    )

    assert contract.name == "ReconAgent"
    assert contract.matches_task("subdomain discovery", "TargetDomain_v1")
    assert contract.matches_task("port scanning", "*")
    assert not contract.matches_task("SQLi", "TargetDomain_v1")
    assert not contract.matches_task("port scanning", "WrongFormat_v2")

    d = contract.to_dict()
    assert d["preferred_model_tier"] == "cloud_fast"


# ─────────────────────────────────────────────────────────────────────────────
# 2. Three-Tier Blackboard Shared Memory Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_three_tier_blackboard_memory(tmp_path):
    storage_dir = tmp_path / "storage_jobs"
    blackboard = ThreeTierBlackboardMemory(base_storage_dir=str(storage_dir))

    job_id = "job_test_100"
    target = "example.com"

    # Level 1: Summary
    s = blackboard.get_or_create_summary(job_id, target)
    assert s.job_id == job_id
    assert s.target == target

    blackboard.update_summary(
        job_id=job_id,
        tags_to_add=["API found", "Laravel detected"],
        endpoints_delta=5,
        subdomains_delta=2,
        active_agent="ReconAgent"
    )

    s_dict = blackboard.get_summary_dict(job_id)
    assert s_dict["endpoints_count"] == 5
    assert "Laravel detected" in s_dict["important_tags"]

    # Level 2: Evidence Item
    ev = Level2EvidenceItem(
        evidence_id="ev_sqli_1",
        url="https://example.com/api/items?id=1",
        method="GET",
        parameter="id",
        vulnerability_type="SQLi",
        request_snippet="GET /api/items?id=1' AND 1=1 --",
        response_snippet="200 OK Record found",
        differential_notes="Boolean differential verified"
    )
    blackboard.add_evidence(job_id, ev)

    retrieved_ev = blackboard.get_evidence(job_id, "ev_sqli_1")
    assert retrieved_ev is not None
    assert retrieved_ev.parameter == "id"

    # Level 3: Raw Data Storage
    raw_payload = {"endpoints": ["/api/v1", "/api/v2"], "tokens": ["xyz123"]}
    raw_path = blackboard.save_raw_data(target, "recon_raw.json", raw_payload)
    assert Path(raw_path).exists()

    loaded_raw = blackboard.read_raw_data(raw_path)
    assert loaded_raw["tokens"] == ["xyz123"]


# ─────────────────────────────────────────────────────────────────────────────
# 3. Handoff Envelope & 5-Question Task Result Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_handoff_envelope_structure():
    env = HandoffEnvelope(
        from_agent="ReconAgent",
        to_agent="WebAgent",
        task="Analyze possible SQL Injection",
        context_id="job_5566",
        priority=HandoffPriority.HIGH,
        summary={"target": "example.com", "important": ["API found"]},
        evidence_ref="ev_123",
        raw_data_path="/path/to/recon.json"
    )

    d = env.to_dict()
    assert d["from_agent"] == "ReconAgent"
    assert d["to_agent"] == "WebAgent"
    assert d["priority"] == "high"


def test_structured_task_result_5_questions():
    res = StructuredTaskResult(
        task_id="task_99",
        agent_name="WebAgent",
        completed=True,
        action_summary="Performed differential boolean checks on parameter id",
        findings=[
            StructuredFinding(
                type="SQLi",
                title="SQL Injection on id",
                severity="High",
                confidence=0.95,
                endpoint="https://example.com/api/items",
                param_name="id",
                cwe_id="CWE-89"
            )
        ],
        confidence_score=0.95,
        next_step="Synthesize CWE-89 final report",
        next_agent="ReportAgent",
        need="Report compilation and CVSS calculation"
    )

    d = res.to_dict()
    assert d["q1_action_summary"] != ""
    assert len(d["q2_findings"]) == 1
    assert d["q3_confidence_score"] == 0.95
    assert d["q4_next_step"] != ""
    assert d["q5_handoff"]["next_agent"] == "ReportAgent"


# ─────────────────────────────────────────────────────────────────────────────
# 4. AI Model Router Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_ai_model_router_intents():
    router = AIModelRouter()

    # Code Analysis -> Qwen 2.5 Coder
    r_code = router.route_task("Decompile javascript bundle and parse AST")
    assert r_code.model_name == "qwen2.5-coder:14b"
    assert r_code.tier == ModelTierPreference.LOCAL_CODE

    # Offensive Vectors -> WhiteRabbitNeo
    r_off = router.route_task("Craft WAF bypass payload for SQL Injection filter breakout")
    assert r_off.model_name == "WhiteRabbitNeo"
    assert r_off.tier == ModelTierPreference.LOCAL_OFFENSIVE

    # Massive Recon -> Gemini Flash
    r_recon = router.route_task("Parse massive 1M tokens sitemap and DOM graph")
    assert r_recon.model_name == "gemini-2.0-flash"
    assert r_recon.tier == ModelTierPreference.CLOUD_FAST

    # Deep Threat Logic -> Llama 70B
    r_logic = router.route_task("Evaluate multi-tenant business logic and complex RBAC matrix")
    assert "llama-3.3-70b" in r_logic.model_name
    assert r_logic.tier == ModelTierPreference.CLOUD_DEEP


# ─────────────────────────────────────────────────────────────────────────────
# 5. Memory Hierarchy System Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_memory_hierarchy_partitions(tmp_path):
    mem_dir = tmp_path / "memory_root"
    memory = MemoryHierarchy(root_memory_dir=str(mem_dir))

    # Short-Term
    memory.save_short_term("job_1", "state", {"step": "recon", "progress": 50})
    loaded_st = memory.load_short_term("job_1", "state")
    assert loaded_st["progress"] == 50

    # Knowledge Base
    kb = memory.query_knowledge("CWE-89")
    assert kb is not None
    assert kb["name"] == "SQL Injection"

    # Agent Learned Memory
    memory.record_agent_lesson(
        agent_name="WebAgent",
        lesson_key="laravel_sqli_filter",
        lesson_data={"mutation": "comment_inline", "success": True}
    )
    lessons = memory.get_agent_lessons("WebAgent")
    assert "laravel_sqli_filter" in lessons
    assert lessons["laravel_sqli_filter"]["data"]["success"] is True

    # Long-Term Mission DB
    memory.record_completed_mission(
        job_id="job_1",
        target="target.local",
        start_time=100.0,
        findings=[{"finding_id": "fnd_1", "type": "SQLi", "severity": "High", "cwe_id": "CWE-89"}]
    )
    db_file = mem_dir / "long_term" / "historical_missions.db"
    assert db_file.exists()


# ─────────────────────────────────────────────────────────────────────────────
# 6. Master Multi-Agent Mission Integration Test
# ─────────────────────────────────────────────────────────────────────────────

def test_hunter_agent_manager_e2e_mission(tmp_path):
    async def _run():
        storage_dir = tmp_path / "storage"
        memory_dir = tmp_path / "memory"

        manager = HunterAgentManager(
            base_storage_dir=str(storage_dir),
            root_memory_dir=str(memory_dir)
        )

        # Register Contract Agents
        recon_agent = ReconContractAgent()
        web_agent = WebContractAgent()
        report_agent = ReportContractAgent()

        manager.register_agent(recon_agent)
        manager.register_agent(web_agent)
        manager.register_agent(report_agent)

        assert len(manager.list_contracts()) == 3

        # Execute end-to-end mission
        mission_res = await manager.execute_mission(
            target_url="test-target.com",
            initial_agent_name="ReconAgent"
        )

        assert mission_res["status"] == "completed"
        assert mission_res["target"] == "test-target.com"
        assert mission_res["findings_count"] >= 1
        assert mission_res["handoffs_executed"] == 2  # Recon -> Web -> Report

        # Verify Blackboard Level 1 state
        summary = mission_res["level1_summary"]
        assert "Laravel detected" in summary["important_tags"]

        # Verify Level 2 Evidence in Blackboard
        evidences = manager.blackboard.list_evidence_for_job(mission_res["job_id"])
        assert len(evidences) >= 1
        assert evidences[0].parameter == "id"

        # Verify Level 3 Raw Data was written to disk
        job_storage = storage_dir / "test-target.com"
        assert (job_storage / "recon.json").exists()
        assert (job_storage / f"{mission_res['job_id']}_final_report.json").exists()

    asyncio.run(_run())


# ─────────────────────────────────────────────────────────────────────────────
# 7. FastAPI Endpoint Integration Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_fastapi_hunter_endpoints():
    async def _run():
        from ui.web.app import app
        from httpx import ASGITransport, AsyncClient

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            # 1. List contracts
            r_contracts = await ac.get("/api/hunter/contracts")
            assert r_contracts.status_code == 200
            data_contracts = r_contracts.json()
            assert data_contracts["registered_agents_count"] == 3

            # 2. Execute mission
            r_mission = await ac.post("/api/hunter/mission/execute", json={"target_url": "api.testtarget.local"})
            assert r_mission.status_code == 200
            data_mission = r_mission.json()
            assert data_mission["status"] == "completed"
            job_id = data_mission["mission"]["job_id"]

            # 3. Query Blackboard state
            r_bb = await ac.get(f"/api/hunter/blackboard/{job_id}")
            assert r_bb.status_code == 200
            data_bb = r_bb.json()
            assert data_bb["job_id"] == job_id
            assert data_bb["level2_evidence_count"] >= 1

            # 4. Query Agent Memory
            r_mem = await ac.get("/api/hunter/memory/agent/WebAgent")
            assert r_mem.status_code == 200
            data_mem = r_mem.json()
            assert data_mem["agent_name"] == "WebAgent"

    asyncio.run(_run())
