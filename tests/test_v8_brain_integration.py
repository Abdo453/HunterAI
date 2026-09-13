"""
HunterAI V8.5 Brain Integration & Investigation OS Test Suite
=============================================================
Verifies deep core integration of Tri-Engine Apex into AutonomousBrain and
closed-loop investigation execution via AutonomousInvestigationKernel.
"""
import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock
from core.brain.autonomous_brain import AutonomousBrain
from core.orchestration.investigation_kernel import (
    AutonomousInvestigationKernel,
    InvestigationKernelConfig,
    InvestigationDossier,
)
from core.mission.mission_system import MissionType
from core.safety.constitutional_layer import AgentConstitution
from core.twin.security_digital_twin import SecurityDigitalTwin, RoleTier
from core.causal.causal_graph import CausalSecurityGraph, CausalNodeType
from core.court.evidence_court_v2 import EvidenceCourtV2


@pytest.fixture
def mock_brain():
    rm = MagicMock()
    tm = MagicMock()
    brain = AutonomousBrain(
        resource_manager=rm,
        tool_manager=tm,
        dry_run=True,
        max_probes=10
    )
    return brain


def test_brain_initializes_v8_tri_engine_fields(mock_brain):
    assert hasattr(mock_brain, "digital_twin")
    assert hasattr(mock_brain, "causal_graph")
    assert hasattr(mock_brain, "state_machine")
    assert hasattr(mock_brain, "consumed_requests")
    assert hasattr(mock_brain, "max_request_budget")
    assert mock_brain.max_request_budget == 5000


@pytest.mark.asyncio
async def test_brain_constitutional_gate_blocks_metadata_ip(mock_brain):
    # Probing cloud metadata 169.254.169.254 must be blocked by AgentConstitution
    res = await mock_brain._execute_tool(
        "SmartPoC",
        target="http://169.254.169.254/latest/meta-data/",
        params=["ami-id"],
        focus="sqli"
    )
    assert res == []
    audit_violations = [a for a in mock_brain._audit_log if a.get("event") == "constitutional_violation"]
    assert len(audit_violations) >= 1
    assert audit_violations[0]["invariant"] == "INVARIANT_1_ZERO_SCOPE_EGRESS"


@pytest.mark.asyncio
async def test_brain_constitutional_gate_blocks_unapproved_mutation(mock_brain):
    # POST probe without operator permit must be blocked
    res = await mock_brain._execute_tool(
        "SmartPoC",
        target="https://target.com/api/v1/users",
        method="POST",
        has_operator_approval=False
    )
    assert res == []
    audit_violations = [a for a in mock_brain._audit_log if a.get("event") == "constitutional_violation"]
    assert len(audit_violations) >= 1
    assert audit_violations[0]["invariant"] == "INVARIANT_3_ZERO_UNAPPROVED_MUTATIONS"


def test_causal_graph_standard_chain_builder():
    cg = CausalSecurityGraph("api.test.local")
    verif = cg.build_standard_injection_chain(
        finding_id="F-TEST-01",
        param="search_query",
        sink_name="POSTGRESQL_QUERY",
        differential_detail="Arithmetic evaluation ((53+19))->72 executed"
    )
    assert verif.is_causally_proven is True
    assert verif.confidence_score >= 0.90
    assert len(verif.unbroken_chain) == 4
    assert "search_query" in verif.unbroken_chain[0]
    assert "DATA_SINK" in verif.unbroken_chain[2]


def test_investigation_kernel_closed_loop_execution():
    kernel = AutonomousInvestigationKernel()
    cfg = InvestigationKernelConfig(
        target_url="https://juice-shop.local",
        mission_type=MissionType.FULL_SCOPE_ASSESSMENT
    )
    dossier = kernel.run(cfg)

    assert isinstance(dossier, InvestigationDossier)
    assert dossier.target_url == "https://juice-shop.local"
    assert dossier.is_mission_complete is True
    assert dossier.constitutional_checks_count >= 3
    assert dossier.twin_identities_count == 3
    assert dossier.causal_chains_verified >= 2
    assert dossier.ach_conclusive_count >= 2
    assert len(dossier.confirmed_findings) == 2
    assert len(dossier.state_invariants_violated) >= 1
    assert len(dossier.dossier_sha256) == 64

    # Terminal summary formatting check
    term_out = dossier.format_terminal_summary()
    assert "HunterAI Autonomous Security Investigation Dossier" in term_out
    assert "SQLI" in term_out
    assert "BOLA" in term_out
    assert "CWE-841" in term_out
