"""
Test Suite for Cognitive Architecture:
- KnowledgeDB (traffic.db)
- UI ↔ Traffic Correlator (Playwright + Burp)
- Hypothesis Reasoning Engine (Observation -> Hypothesis -> Validation)
- Adaptive Skill Router
- Application Topology & State Graph Mapper
"""
from __future__ import annotations

import asyncio
import shutil
import tempfile
import time
from pathlib import Path

import pytest

from agents.autonomous_mission_agent import AutonomousMissionAgent
from agents.base_agent import AgentTask
from core.app_mapper import ApplicationMapper
from core.correlation.ui_traffic_correlator import UITrafficCorrelator
from core.database.knowledge_db import KnowledgeDB
from core.mission_state import MissionState
from core.reasoning.hypothesis_reasoning_engine import HypothesisReasoningEngine
from core.skill_registry import SkillRegistry
from core.skill_router import SkillRouter
from skills.base_skill import BaseSkill, SkillContext, SkillResult
from tools.tool_manager import ToolManager


@pytest.fixture
def temp_workspace():
    tmp = tempfile.mkdtemp()
    yield Path(tmp)
    shutil.rmtree(tmp, ignore_errors=True)


def test_knowledge_db_crud(temp_workspace):
    db_file = temp_workspace / "traffic.db"
    db = KnowledgeDB(db_file)

    # 1. Insert Endpoints & Parameters
    ep1_id = db.insert_endpoint("https://target.com/api/v1/users", method="GET", category="api", source_tool="crawler")
    assert ep1_id > 0

    ep2_id = db.insert_endpoint("https://target.com/api/v1/user/edit", method="POST", category="user", source_tool="browser")
    assert ep2_id > 0

    p_id = db.insert_parameter(endpoint_id=ep2_id, name="id", location="body_json", sample_value="1337", is_identifier=True)
    assert p_id > 0

    # Query with parameter
    results = db.get_endpoints_with_param("id")
    assert len(results) >= 1
    assert results[0]["param_name"] == "id"

    # Query by method
    post_eps = db.get_endpoints_by_method("POST")
    assert len(post_eps) >= 1
    assert post_eps[0]["method"] == "POST"

    # 2. Insert Traffic & UI Actions
    req_id = db.insert_traffic(
        method="POST",
        url="https://target.com/api/v1/user/edit",
        headers={"Content-Type": "application/json"},
        post_data='{"id": 1337, "role": "admin"}',
        status_code=200,
        resource_type="xhr"
    )
    assert req_id.startswith("req_")

    act_id = db.insert_ui_action(
        page_url="https://target.com/profile",
        element_type="button",
        locator='button:has-text("Save Changes")',
        text_label="Save Changes"
    )
    assert act_id.startswith("act_")

    # 3. Insert Correlation
    corr_id = db.insert_correlation(action_id=act_id, req_id=req_id, endpoint="POST /api/v1/user/edit")
    assert corr_id > 0

    corr_list = db.get_correlated_traffic()
    assert len(corr_list) == 1
    assert corr_list[0]["text_label"] == "Save Changes"

    stats = db.get_stats()
    assert stats["endpoints"] == 2
    assert stats["parameters"] == 1
    assert stats["traffic_records"] == 1
    assert stats["ui_correlations"] == 1


def test_ui_traffic_correlator(temp_workspace):
    db_file = temp_workspace / "traffic.db"
    db = KnowledgeDB(db_file)
    correlator = UITrafficCorrelator(db, max_time_delta_seconds=2.0)

    t0 = time.time()
    ui_actions = [
        {"action_id": "act_btn_profile", "element_type": "button", "locator": "#btn-profile", "text_label": "Profile", "timestamp": t0},
        {"action_id": "act_btn_logout", "element_type": "button", "locator": "#btn-logout", "text_label": "Logout", "timestamp": t0 + 10.0},
    ]

    traffic = [
        {"req_id": "req_1", "method": "GET", "url": "https://target.com/api/profile", "status_code": 200, "post_data": None, "timestamp": t0 + 0.3},
        {"req_id": "req_2", "method": "POST", "url": "https://target.com/api/logout", "status_code": 302, "post_data": None, "timestamp": t0 + 10.2},
    ]

    correlations = correlator.correlate_events(ui_actions, traffic)
    assert len(correlations) == 2

    # Verify high confidence on matching label and time delta
    assert correlations[0].confidence >= 0.85
    assert correlations[0].element_label == "Profile"
    assert "profile" in correlations[0].endpoint_url.lower()

    # Export graph
    export_path = temp_workspace / "correlations.json"
    correlator.export_correlation_graph(export_path)
    assert export_path.exists()


def test_hypothesis_reasoning_and_confidence(temp_workspace):
    db_file = temp_workspace / "traffic.db"
    db = KnowledgeDB(db_file)
    engine = HypothesisReasoningEngine(db)

    endpoints = [
        {"url": "https://target.com/api/v1/profile?id=42", "path": "/api/v1/profile"},
        {"url": "https://target.com/graphql", "path": "/graphql"},
    ]
    parameters = [
        {"name": "id", "sample_value": "42", "is_identifier": True},
    ]
    techs = ["Amazon Web Services (AWS)", "React"]

    # Generate Hypotheses
    hypotheses = engine.generate_hypotheses_from_observations(
        target="target.com",
        endpoints=endpoints,
        parameters=parameters,
        technologies=techs
    )
    assert len(hypotheses) == 3

    idor_hyp = next(h for h in hypotheses if "idor" in h.vuln_type)
    assert idor_hyp.confidence == 0.55
    assert idor_hyp.recommended_skill == "authorization_analysis"

    graphql_hyp = next(h for h in hypotheses if "graphql" in h.vuln_type)
    assert graphql_hyp.confidence == 0.75

    cloud_hyp = next(h for h in hypotheses if "cloud" in h.vuln_type)
    assert cloud_hyp.confidence == 0.60

    # Test Validation and Confidence progression (0.55 -> 0.85 -> 0.98 validated)
    c1 = engine.record_validation_result(idor_hyp.hyp_id, corroborating=True, evidence_snippet="State changed for another tenant", confidence_delta=0.30)
    assert round(c1, 2) == 0.85

    c2 = engine.record_validation_result(idor_hyp.hyp_id, corroborating=True, evidence_snippet="Full data leaked", confidence_delta=0.15)
    assert c2 >= 0.98

    updated_hyps = db.get_hypotheses(status="validated")
    assert len(updated_hyps) == 1
    assert updated_hyps[0]["hyp_id"] == idor_hyp.hyp_id


def test_adaptive_skill_router(temp_workspace):
    db_file = temp_workspace / "traffic.db"
    db = KnowledgeDB(db_file)
    registry = SkillRegistry()
    registry.discover(force=True)

    router = SkillRouter(registry, db)
    state = MissionState.create_new(target="target.com")

    # When no hypotheses exist, route standard DAG
    next_skill, reason = router.route_next_skill(state)
    assert next_skill is not None
    assert "Standard progression" in reason

    # When high priority hypothesis exists
    db.insert_hypothesis(
        target="target.com",
        title="Audit Cloud Metadata SSRF",
        vuln_type="ssrf.cloud",
        observation="AWS hosting identified",
        rationale="IMDS exposed",
        confidence=0.70,
        recommended_skill="cloud_metadata_audit"
    )

    state.mark_skill_done("tech_detection") # Satisfies dependency for cloud_metadata_audit
    routed_skill, hyp_reason = router.route_next_skill(state)
    assert routed_skill is not None
    assert routed_skill.name == "cloud_metadata_audit"
    assert "Testing hypothesis" in hyp_reason


def test_application_mapper(temp_workspace):
    db_file = temp_workspace / "traffic.db"
    db = KnowledgeDB(db_file)
    mapper = ApplicationMapper(db)

    db.insert_endpoint("https://target.com/login", method="GET", category="auth")
    db.insert_endpoint("https://target.com/profile", method="GET", category="user")
    db.insert_endpoint("https://target.com/api/v1/orders", method="POST", category="api")
    db.insert_endpoint("https://target.com/admin/dashboard", method="GET", category="admin")

    tree = mapper.build_application_tree("target.com")
    assert len(tree["authentication"]) == 1
    assert len(tree["user_features"]) == 1
    assert len(tree["api_layer"]) == 1
    assert len(tree["admin_surface"]) == 1

    ascii_map = mapper.generate_ascii_tree("target.com")
    assert "Authentication Surface" in ascii_map
    assert "Admin & Internal Perimeter" in ascii_map

    mermaid = mapper.generate_mermaid_diagram("target.com")
    assert "```mermaid" in mermaid
    assert "graph TD" in mermaid

    exported = mapper.export_all(temp_workspace, "target.com")
    assert exported["json"].exists()
    assert exported["ascii"].exists()
    assert exported["mermaid"].exists()


@pytest.mark.asyncio
async def test_autonomous_mission_agent_with_cognitive_db(temp_workspace):
    tm = ToolManager()
    agent = AutonomousMissionAgent(tool_manager=tm, workspace_root=str(temp_workspace))

    # Pre-seed a completed skill so mission completes with success
    state_file = agent.workspace.get_state_file("testphp.vulnweb.com", "cognitive_sess_01")
    state = MissionState.create_new(target="testphp.vulnweb.com")
    state.mark_skill_done("subdomain_enum")
    state.mark_skill_done("live_host_detection")
    state.save(state_file)

    task = AgentTask(
        target="testphp.vulnweb.com",
        mode="quick",
        session_id="cognitive_sess_01",
        extra={"max_iterations": 2, "total_timeout": 30}
    )

    result = await agent.run(task)
    assert result.success is True

    # Check that traffic.db was created and populated
    db_file = temp_workspace / "testphp.vulnweb.com" / "cognitive_sess_01" / "traffic.db"
    assert db_file.exists()

    db = KnowledgeDB(db_file)
    stats = db.get_stats()
    assert isinstance(stats, dict)

    # Check that application maps were exported
    app_map_dir = temp_workspace / "testphp.vulnweb.com" / "cognitive_sess_01" / "app_map"
    assert (app_map_dir / "application_map.json").exists()
    assert (app_map_dir / "application_map.txt").exists()
