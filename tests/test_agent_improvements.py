"""
Comprehensive Test Suite for Autonomous Mission Agent Improvements:
- CVSS v3.1 Base Score Calculator
- Mission State Retry Tracking & Health Scoring
- Evidence Deduplication & Source Merging
- BaseSkill Per-Skill Timeout & Structured Errors
- Parallel Batch Grouping & Priority Ordering
- WebSocket Broadcaster & Resilient Execution
"""
from __future__ import annotations

import asyncio
import shutil
import tempfile
from pathlib import Path

import pytest

from agents.autonomous_mission_agent import (
    AutonomousMissionAgent,
    MISSION_EVENT_LISTENERS,
    register_mission_listener,
    unregister_mission_listener,
)
from agents.base_agent import AgentTask
from core.cvss_calculator import CVSSCalculator, CVSSMetrics
from core.evidence_manager import EvidenceManager
from core.mission_planner import MissionPlanner
from core.mission_state import MissionState
from core.skill_registry import SkillRegistry
from core.workspace_manager import WorkspaceManager
from skills.base_skill import BaseSkill, SkillContext, SkillResult
from tools.tool_manager import ToolManager


@pytest.fixture
def temp_workspace():
    tmp = tempfile.mkdtemp()
    yield Path(tmp)
    shutil.rmtree(tmp, ignore_errors=True)


def test_cvss_calculator():
    # Test RCE metrics (Network, Low complexity, None privs, None UI, Scope Changed, High CIA) -> 10.0
    rce_metrics = CVSSMetrics(
        attack_vector="N", attack_complexity="L", privileges_required="N",
        user_interaction="N", scope="C", confidentiality="H", integrity="H", availability="H"
    )
    rce_score = CVSSCalculator.calculate_base_score(rce_metrics)
    assert rce_score == 10.0

    # Test IDOR metrics (Network, Low complexity, Low privs, None UI, Scope Unchanged, High Confidentiality) -> ~6.5 - 8.1
    idor_metrics = CVSSMetrics(
        attack_vector="N", attack_complexity="L", privileges_required="L",
        user_interaction="N", scope="U", confidentiality="H", integrity="H", availability="N"
    )
    idor_score = CVSSCalculator.calculate_base_score(idor_metrics)
    assert 7.0 <= idor_score <= 8.5

    # Test VRT derivation
    derived_rce = CVSSCalculator.derive_from_vrt("server_side_injection.remote_code_execution")
    assert derived_rce >= 9.5

    derived_idor = CVSSCalculator.derive_from_vrt("broken_access_control.idor")
    assert derived_idor >= 7.0


def test_mission_state_retries_and_health(temp_workspace):
    state = MissionState.create_new(target="example.com")
    assert state.health_score == 100.0

    # Track retries
    attempt1 = state.increment_retry("port_scan")
    assert attempt1 == 1
    assert state.get_retry_count("port_scan") == 1

    # Add timeline events
    state.mark_skill_done("subdomain_enum")
    state.mark_skill_failed("port_scan", "timeout error")

    # Health score should be calculated with penalty
    state_file = temp_workspace / "state.json"
    state.save(state_file)
    assert state.health_score < 100.0
    assert len(state.timeline) >= 3

    # Load state
    loaded = MissionState.load(state_file)
    assert loaded.retry_counts.get("port_scan") == 1
    assert loaded.health_score == state.health_score


def test_evidence_deduplication():
    em = EvidenceManager()

    # Add first evidence
    e1_id = em.add_evidence(
        title="IDOR on User Profile",
        content="First observation from katana crawler",
        tool="katana",
        severity="High",
        vuln_type="idor",
        target="api.test.com",
        url="https://api.test.com/v1/users/42"
    )

    # Add duplicate evidence from different tool
    e2_id = em.add_evidence(
        title="IDOR on User Profile",
        content="Second richer observation from manual probe with full payload",
        tool="manual_probe",
        severity="High",
        vuln_type="idor",
        target="api.test.com",
        url="https://api.test.com/v1/users/42"
    )

    # Should be deduplicated into same evidence ID
    assert e1_id == e2_id
    ev = em.get_evidence(e1_id)
    assert len(ev.sources) == 2
    assert "katana" in ev.sources
    assert "manual_probe" in ev.sources
    assert "Second richer observation" in ev.content
    assert ev.cvss_score >= 7.0


@pytest.mark.asyncio
async def test_base_skill_timeout_enforcement(temp_workspace):
    class SlowTestSkill(BaseSkill):
        name = "slow_skill"
        category = "test"
        timeout_seconds = 0.5 # 500ms timeout

        async def execute(self, ctx: SkillContext) -> SkillResult:
            await asyncio.sleep(2.0) # sleeps longer than timeout
            return SkillResult(skill_name=self.name, success=True)

    wm = WorkspaceManager(root=temp_workspace)
    wm.create_workspace("test.local", "sess_slow")
    ctx = SkillContext(
        target="test.local",
        session_id="sess_slow",
        workspace=wm,
        tool_manager=ToolManager()
    )

    skill = SlowTestSkill()
    res = await skill.run(ctx)

    assert res.success is False
    assert len(res.structured_errors) == 1
    assert res.structured_errors[0].category == "timeout"
    assert "exceeded" in res.errors[0]


def test_mission_planner_parallel_batching():
    registry = SkillRegistry()
    registry.discover(force=True)
    planner = MissionPlanner(registry)

    state = MissionState.create_new(target="example.com")
    ready = planner.get_ready_skills(state)
    assert len(ready) >= 2

    # Group into batches of max 2
    batches = planner.group_independent_skills(ready, max_batch_size=2)
    assert len(batches) >= 1
    for b in batches:
        assert len(b) <= 2

    # Test fallback skill suggestions
    fallbacks = planner.get_fallback_skills("subdomain_enum", state)
    assert len(fallbacks) >= 1
    assert any(f.name == "dns_enum" for f in fallbacks)


@pytest.mark.asyncio
async def test_websocket_broadcaster_and_agent_execution(temp_workspace):
    received_events = []

    def mock_ws_listener(event):
        received_events.append(event)

    session_id = "sess_ws_test"
    register_mission_listener(session_id, mock_ws_listener)

    tm = ToolManager()
    agent = AutonomousMissionAgent(tool_manager=tm, workspace_root=str(temp_workspace))

    task = AgentTask(
        target="127.0.0.1",
        mode="quick",
        session_id=session_id,
        extra={"max_iterations": 4, "total_timeout": 60}
    )

    result = await agent.run(task)
    unregister_mission_listener(session_id, mock_ws_listener)

    assert result.agent_name == "autonomous_mission_agent"
    assert len(received_events) >= 2
    assert any(ev.get("event") == "mission_started" for ev in received_events)
    assert any(ev.get("event") == "mission_completed" for ev in received_events)
