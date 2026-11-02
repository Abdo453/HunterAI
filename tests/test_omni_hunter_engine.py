"""
HunterAI OmniHunter Engine & Multi-Agent Swarm Test Suite
=========================================================
Tests:
  1. Skill Matrix authoritative mapping
  2. Persistence Watchdog & Stall Detection
  3. Information Gain Planner & Phase Promotion
  4. Scope Firewall hard abort on unauthorized targets
  5. End-to-end Autonomous Execution Loop
"""
from __future__ import annotations

import time
from pathlib import Path

import pytest

from core.contracts.task_contracts import AgentTeam, TaskLifecycleStatus
from core.coverage.coverage_ledger import CoverageLedger
from core.engine.omni_hunter_engine import (
    AssessmentConfig,
    AssessmentPhase,
    InformationGainPlanner,
    OmniHunterEngine,
)
from core.engine.persistence_watchdog import (
    AssessmentSnapshot,
    PersistenceWatchdog,
    ProgressSnapshot,
    RetryPolicy,
    StallDetector,
)
from core.engine.skill_matrix import (
    SKILL_MATRIX,
    ToolCategory,
    VulnClass,
    get_team_for_asset,
    get_teams_for_vuln,
    skill_gap_analysis,
)
from core.system.task_scheduler import TaskScheduler


# ── 1. Skill Matrix Tests ───────────────────────────────────────────────────────

def test_skill_matrix_contains_all_core_teams():
    core_teams = [
        AgentTeam.RECON,
        AgentTeam.NETWORK,
        AgentTeam.WEB,
        AgentTeam.API,
        AgentTeam.JAVASCRIPT,
        AgentTeam.VERIFICATION,
    ]
    for team in core_teams:
        assert team in SKILL_MATRIX, f"Team {team} must be defined in SKILL_MATRIX"


def test_skill_matrix_profiles_are_robust():
    for team, profile in SKILL_MATRIX.items():
        assert len(profile.detectable_vulns) > 0, f"{team} must have detectable vulns"
        assert len(profile.tool_categories) > 0, f"{team} must have tool categories"
        assert 0.0 < profile.max_confidence <= 1.0, f"{team} has invalid max_confidence"
        assert len(profile.hard_limits) > 0, f"{team} must document hard limits honestly"


def test_get_team_for_asset_routing():
    teams = get_team_for_asset("ENDPOINT")
    assert AgentTeam.WEB in teams
    assert AgentTeam.API in teams


def test_get_teams_for_vuln_idor():
    teams = get_teams_for_vuln(VulnClass.IDOR)
    assert AgentTeam.API in teams
    assert AgentTeam.VERIFICATION in teams


def test_skill_gap_analysis():
    assets = {"DOMAIN", "ENDPOINT", "API"}
    gaps = skill_gap_analysis(assets)
    assert "DOMAIN" in gaps
    assert "API" in gaps
    assert AgentTeam.RECON in gaps["DOMAIN"]


# ── 2. Persistence Watchdog Tests ──────────────────────────────────────────────

def test_progress_snapshot_roundtrip(tmp_path):
    snapper = ProgressSnapshot(snapshot_dir=tmp_path)
    snap = AssessmentSnapshot(
        target="https://target.corp",
        phase="RECON",
        discovered_assets={"domains": ["target.corp"]},
        coverage_pct=25.0,
    )
    saved_path = snapper.save(snap)
    assert saved_path.exists()

    loaded = snapper.load(snap.snapshot_id)
    assert loaded is not None
    assert loaded.target == "https://target.corp"
    assert loaded.phase == "RECON"
    assert loaded.coverage_pct == 25.0


def test_stall_detector_identifies_frozen_tasks(tmp_path):
    sched = TaskScheduler(
        tasks_file=tmp_path / "tasks.json",
        logs_dir=tmp_path / "logs",
        state_file=tmp_path / "state.json",
    )
    task = sched.add_task("Frozen Probe", "probe_action", target="https://target.corp", team=AgentTeam.RECON)
    sched.dispatch_task(task.task_id, "ReconWorker")
    
    # Backdate started_at
    task.started_at = time.time() - 500

    detector = StallDetector(stall_timeout_secs=300)
    stalled = detector.detect_stalled_tasks(sched)
    assert any(t.task_id == task.task_id for t in stalled)


def test_retry_policy_re_queues_and_fails_after_limit(tmp_path):
    sched = TaskScheduler(
        tasks_file=tmp_path / "tasks.json",
        logs_dir=tmp_path / "logs",
        state_file=tmp_path / "state.json",
    )
    task = sched.add_task("Retriable Task", "action", target="https://target.corp", team=AgentTeam.WEB)
    sched.dispatch_task(task.task_id, "WebWorker")

    policy = RetryPolicy(max_retries=2)
    assert policy.should_retry(task)

    # First retry
    ok1 = policy.record_retry(task, sched)
    assert ok1
    assert task.status == TaskLifecycleStatus.PENDING

    # Second retry
    sched.dispatch_task(task.task_id, "WebWorker")
    ok2 = policy.record_retry(task, sched)
    assert ok2

    # Third attempt exceeds max_retries=2
    sched.dispatch_task(task.task_id, "WebWorker")
    ok3 = policy.record_retry(task, sched)
    assert not ok3
    assert task.status == TaskLifecycleStatus.FAILED


# ── 3. Information Gain Planner Tests ──────────────────────────────────────────

def test_planner_phase_advancement():
    planner = InformationGainPlanner()
    ledger = CoverageLedger()
    surface = {}

    p1 = planner.next_phase(AssessmentPhase.RECON, ledger, surface)
    assert p1 == AssessmentPhase.NETWORK

    p2 = planner.next_phase(AssessmentPhase.NETWORK, ledger, surface)
    assert p2 == AssessmentPhase.WEB


def test_planner_should_continue():
    planner = InformationGainPlanner()
    ledger = CoverageLedger()

    # Low coverage should continue
    assert planner.should_continue(ledger, threshold=0.85, cycle=1, max_cycles=10)

    # Exceeding max cycles should stop
    assert not planner.should_continue(ledger, threshold=0.85, cycle=10, max_cycles=10)


# ── 4. Scope Firewall & OmniHunter Engine Tests ────────────────────────────────

def test_omni_hunter_aborts_on_unauthorized_scope(tmp_path):
    config = AssessmentConfig(
        target_url="https://unauthorized-evil.com",
        scope_domains=["authorized-corp.com"],
        snapshot_dir=str(tmp_path / "snapshots"),
        engagement_id="TEST-UNAUTH-ENG",
    )
    engine = OmniHunterEngine(config)
    result = engine.run()

    # Strict Scope Firewall must block execution
    assert result.phase_reached == AssessmentPhase.INIT
    assert len(result.confirmed_findings) == 0
    assert result.coverage_pct == 0.0
    assert any("OUT_OF_SCOPE" in str(s) for s in result.untestable_surfaces)


def test_omni_hunter_executes_authorized_loop(tmp_path):
    config = AssessmentConfig(
        target_url="https://authorized-corp.com",
        scope_domains=["authorized-corp.com", "api.authorized-corp.com"],
        coverage_threshold=0.01,  # Short run for hermetic test
        max_cycles=3,
        force_tool_fallback=True,
        snapshot_dir=str(tmp_path / "snapshots"),
        engagement_id="TEST-AUTH-ENG",
    )
    engine = OmniHunterEngine(config)
    result = engine.run()

    # Must complete cleanly
    assert result.engagement_id == "TEST-AUTH-ENG"
    assert result.target == "https://authorized-corp.com"
    assert result.phase_reached == AssessmentPhase.REPORT
    assert result.total_tasks > 0
    assert 0.0 <= result.coverage_pct <= 100.0

    # Snapshot checkpoint must exist
    snap_files = list((tmp_path / "snapshots").glob("SNAP-*.json"))
    assert len(snap_files) > 0
