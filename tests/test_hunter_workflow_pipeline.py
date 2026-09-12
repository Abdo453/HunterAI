"""
Unit & Integration Tests for HunterAI Workflow Pipeline:
- Finite State Machine Transitions
- Invariant Enforcement (TEST -> REPORT strictly forbidden)
- Schemas & Data Contracts
- HunterPipelineOrchestrator Lifecycle and Artifact Generation
"""
import os
import shutil
import tempfile
import pytest

from hunter_ai.pipeline.state_machine import HunterState, HunterStateMachine, IllegalStateTransitionError
from hunter_ai.pipeline.schemas import (
    ScopeConfig,
    SubdomainRecord,
    LiveAssetRecord,
    EndpointRecord,
    ParameterRecord,
    SecretFindingRecord,
    VerificationEvidence,
    ReproductionArtifact,
    HunterFinding,
    FindingStatus,
    AssetCategory,
)
from hunter_ai.pipeline.pipeline_orchestrator import HunterPipelineOrchestrator
from tools.tool_manager import ToolManager


def test_fsm_valid_lifecycle_progression():
    fsm = HunterStateMachine(target="example.com", session_id="test_sess_01")
    assert fsm.current_state == HunterState.INIT

    # Walk through valid sequence
    states = [
        HunterState.SCOPE_CHECK,
        HunterState.DISCOVER,
        HunterState.ENUMERATE,
        HunterState.NORMALIZE,
        HunterState.MAP,
        HunterState.CLASSIFY,
        HunterState.SURFACE,
        HunterState.TRIAGE,
        HunterState.HYPOTHESIZE,
        HunterState.TEST,
        HunterState.VERIFY,
        HunterState.CORRELATE,
        HunterState.ASSESS_IMPACT,
        HunterState.REPORT,
        HunterState.COMPLETE,
    ]

    for st in states:
        fsm.transition_to(st, f"Transition to {st.value}")
        assert fsm.current_state == st

    assert len(fsm.history) == len(states) + 1


def test_fsm_forbidden_test_to_report():
    """CRITICAL INVARIANT: TEST -> REPORT directly is FORBIDDEN"""
    fsm = HunterStateMachine(target="example.com", session_id="test_sess_02")
    fsm.transition_to(HunterState.SCOPE_CHECK)
    fsm.transition_to(HunterState.DISCOVER)
    fsm.transition_to(HunterState.NORMALIZE)
    fsm.transition_to(HunterState.MAP)
    fsm.transition_to(HunterState.SURFACE)
    fsm.transition_to(HunterState.HYPOTHESIZE)
    fsm.transition_to(HunterState.TEST)

    assert fsm.current_state == HunterState.TEST

    # Must raise IllegalStateTransitionError
    with pytest.raises(IllegalStateTransitionError) as excinfo:
        fsm.transition_to(HunterState.REPORT)

    assert "CRITICAL INVARIANT VIOLATION" in str(excinfo.value)
    assert "TEST to REPORT" in str(excinfo.value)


def test_fsm_forbidden_arbitrary_transition():
    fsm = HunterStateMachine(target="example.com", session_id="test_sess_03")
    assert fsm.current_state == HunterState.INIT

    # Arbitrary skip: INIT -> TEST
    with pytest.raises(IllegalStateTransitionError):
        fsm.transition_to(HunterState.TEST)


def test_pipeline_schemas():
    scope = ScopeConfig(
        target="http://example.com",
        domain="example.com",
        in_scope=["example.com", "*.example.com"]
    )
    assert scope.is_authorized is True

    sub = SubdomainRecord(
        asset="api.example.com",
        domain="example.com",
        sources=["crt.sh", "subfinder"],
        confidence=0.95
    )
    assert sub.asset == "api.example.com"

    live = LiveAssetRecord(
        url="https://api.example.com",
        host="api.example.com",
        status_code=200,
        asset_class=AssetCategory.API
    )
    assert live.asset_class == AssetCategory.API

    param = ParameterRecord(
        parameter="id",
        endpoint="https://api.example.com/user",
        potential_classes=["IDOR", "SQLi"]
    )
    assert "IDOR" in param.potential_classes

    finding = HunterFinding(
        finding="SQL Injection",
        asset="api.example.com",
        endpoint="https://api.example.com/user",
        parameter="id",
        vuln_type="SQLi",
        status=FindingStatus.CONFIRMED,
        severity="Critical",
        cvss_score=9.8,
        evidence=[
            VerificationEvidence(
                type="controlled_execution",
                description="Database version extracted",
                proof_snippet="PostgreSQL 14.2",
                verified=True
            )
        ]
    )
    assert finding.status == FindingStatus.CONFIRMED
    assert len(finding.evidence) == 1
    assert finding.evidence[0].verified is True


@pytest.mark.asyncio
async def test_orchestrator_scope_rejection():
    # Out of scope target
    orch = HunterPipelineOrchestrator(
        target="evilcorp.com",
        in_scope=["onlyallowed.com"]
    )
    res = await orch.run()
    assert res["status"] == "aborted"
    assert res["reason"] == "out_of_scope"
    assert orch.fsm.current_state == HunterState.ABORTED


@pytest.mark.asyncio
async def test_orchestrator_stage_artifacts(tmp_path):
    orch = HunterPipelineOrchestrator(
        target="http://example.com",
        session_id="test_art_01",
        in_scope=["example.com"]
    )
    # Override artifact root with tmp_path
    orch.artifact_root = str(tmp_path)

    # Save artifact
    p = orch._save_stage_artifact("01_test_stage", "sample.json", {"key": "value"})
    assert os.path.isfile(p)

    with open(p, "r", encoding="utf-8") as f:
        data = f.read()
    assert '"key": "value"' in data
