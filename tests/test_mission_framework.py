"""
Unit & Integration Tests for Autonomous Security Mission Framework
"""
from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

import pytest
import pytest_asyncio

from agents.autonomous_mission_agent import AutonomousMissionAgent
from agents.base_agent import AgentTask
from core.evidence_manager import EvidenceManager
from core.mission_planner import MissionPlanner
from core.mission_reporter import MissionReporter
from core.mission_state import MissionState
from core.skill_registry import SkillRegistry
from core.workspace_manager import WorkspaceManager
from tools.tool_manager import ToolManager


@pytest.fixture
def temp_workspace():
    tmp = tempfile.mkdtemp()
    yield Path(tmp)
    shutil.rmtree(tmp, ignore_errors=True)


def test_mission_state_lifecycle(temp_workspace):
    state = MissionState.create_new(target="example.com", mode="full")
    assert state.target == "example.com"
    assert state.status == "running"
    assert len(state.completed_skills) == 0

    state.mark_skill_done("subdomain_enum", {"subdomains.txt": "/path/to/subdomains.txt"})
    assert state.is_skill_done("subdomain_enum")
    assert not state.is_skill_failed("subdomain_enum")

    state.mark_skill_failed("port_scan", "timeout")
    assert state.is_skill_failed("port_scan")
    assert len(state.errors) == 1

    state_file = temp_workspace / "state.json"
    state.save(state_file)
    assert state_file.exists()

    loaded = MissionState.load(state_file)
    assert loaded.target == "example.com"
    assert "subdomain_enum" in loaded.completed_skills
    assert "port_scan" in loaded.failed_skills


def test_workspace_manager(temp_workspace):
    wm = WorkspaceManager(root=temp_workspace)
    ws_path = wm.create_workspace("test.local", session_id="sess_001")
    assert ws_path.exists()
    assert (ws_path / "recon").is_dir()
    assert (ws_path / "web").is_dir()
    assert (ws_path / "reports").is_dir()
    assert (ws_path / "agent.log").is_file()

    p = wm.write_file("test.local", "recon", "subdomains.txt", "sub1.test.local\nsub2.test.local", session_id="sess_001")
    assert p.exists()

    content = wm.read_file("test.local", "recon", "subdomains.txt", session_id="sess_001")
    assert "sub1.test.local" in content

    files = wm.list_files("test.local", session_id="sess_001")
    assert len(files) >= 1


def test_evidence_manager(temp_workspace):
    em = EvidenceManager()
    eid = em.add_evidence(
        title="Sensitive Endpoint Found",
        content="GET /admin/backup.zip returned HTTP 200",
        tool="endpoint_discovery",
        severity="High",
        vuln_type="information_disclosure",
        target="example.com",
        url="http://example.com/admin/backup.zip"
    )
    assert eid.startswith("ev_")
    ev = em.get_evidence(eid)
    assert ev.severity == "High"
    assert len(em.get_critical_and_high()) == 1

    bundle_dir = temp_workspace / "evidence"
    written = em.export_bundle(bundle_dir)
    assert len(written) >= 2  # Evidence file + index.md
    assert (bundle_dir / "index.md").exists()


def test_skill_registry_discovery():
    registry = SkillRegistry()
    count = registry.discover(force=True)
    assert count >= 8, f"Expected at least 8 skills, found {count}"

    all_names = registry.list_names()
    assert "subdomain_enum" in all_names
    assert "live_host_detection" in all_names
    assert "crawling" in all_names
    assert "report_generator" in all_names

    # Test instantiation
    skill_inst = registry.instantiate("report_generator")
    assert skill_inst is not None
    assert skill_inst.name == "report_generator"


def test_mission_planner_dependencies():
    registry = SkillRegistry()
    registry.discover()
    planner = MissionPlanner(registry)

    state = MissionState.create_new(target="example.com", mode="full")

    # Initial ready skills should be entry points (no dependencies, like subdomain_enum, dns_enum, port_scan)
    ready = planner.get_ready_skills(state)
    ready_names = [m.name for m in ready]

    assert "subdomain_enum" in ready_names
    # live_host_detection depends on subdomain_enum, so should NOT be ready yet
    assert "live_host_detection" not in ready_names

    # Now mark subdomain_enum as completed
    state.mark_skill_done("subdomain_enum")
    next_ready = planner.get_ready_skills(state)
    next_ready_names = [m.name for m in next_ready]

    # live_host_detection should now be unlocked
    assert "live_host_detection" in next_ready_names


@pytest.mark.asyncio
async def test_autonomous_mission_agent_quick_run(temp_workspace):
    tm = ToolManager()
    events = []

    async def cb(ev):
        events.append(ev)

    agent = AutonomousMissionAgent(tool_manager=tm, progress_callback=cb, workspace_root=str(temp_workspace))

    # Run in quick mode with low max iterations to test full orchestration
    task = AgentTask(
        target="127.0.0.1",
        mode="quick",
        session_id="test_quick_01",
        extra={"max_iterations": 5}
    )

    result = await agent.run(task)
    assert result.agent_name == "autonomous_mission_agent"
    assert result.target == "127.0.0.1"

    # Workspace and final report should exist
    report_path = agent.workspace.get_report_path("127.0.0.1", "test_quick_01")
    assert report_path.exists()
    assert "Autonomous Security Assessment Report" in report_path.read_text(encoding="utf-8")
    assert len(events) > 0
