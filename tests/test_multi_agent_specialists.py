"""
Unit & Integration Tests for Multi-Agent Specialists and Lead Analyst Coordination
Tests: ReconSpecialist, WebSpecialist, APISpecialist, AuthSpecialist, VulnSpecialist, CriticSpecialist, and LeadAnalyst
"""
import pytest
from core.multi_agent.contracts import SpecialistRole, SpecialistTask, SpecialistReport
from core.multi_agent.specialists import (
    ReconSpecialist,
    WebSpecialist,
    APISpecialist,
    AuthSpecialist,
    VulnSpecialist,
    CriticSpecialist,
    LeadAnalyst
)
from agents.security_intelligence.schemas import EvidenceItem, EvidenceType


@pytest.mark.asyncio
async def test_specialists_task_execution():
    target = "api.testtarget.local"

    # Recon Specialist
    recon = ReconSpecialist()
    r_task = SpecialistTask(role=SpecialistRole.RECON, target=target, objective="Map ports")
    r_rep = await recon.execute_task(r_task)
    assert r_rep.success is True
    assert len(r_rep.discovered_nodes) >= 2

    # Web Specialist
    web = WebSpecialist()
    w_task = SpecialistTask(role=SpecialistRole.WEB, target=target, objective="Find endpoints")
    w_rep = await web.execute_task(w_task)
    assert w_rep.success is True
    assert any("/login" in n["label"] for n in w_rep.discovered_nodes)

    # API Specialist
    api = APISpecialist()
    a_task = SpecialistTask(role=SpecialistRole.API, target=target, objective="Find APIs")
    a_rep = await api.execute_task(a_task)
    assert a_rep.success is True
    assert any("invoices" in n["label"] for n in a_rep.discovered_nodes)

    # Auth Specialist
    auth = AuthSpecialist()
    au_task = SpecialistTask(role=SpecialistRole.AUTH, target=target, objective="Map users")
    au_rep = await auth.execute_task(au_task)
    assert au_rep.success is True
    assert len(au_rep.discovered_nodes) >= 2

    # Vuln Specialist
    vuln = VulnSpecialist()
    v_task = SpecialistTask(role=SpecialistRole.VULNERABILITY, target=target, objective="Test BOLA")
    v_rep = await vuln.execute_task(v_task)
    assert v_rep.success is True
    assert len(v_rep.evidence_items) >= 1
    assert v_rep.evidence_items[0].type == EvidenceType.BEHAVIOR_DIFF


def test_critic_specialist_verifies_evidence():
    critic = CriticSpecialist()

    # Report claiming vuln WITH differential evidence -> Approved
    good_rep = SpecialistReport(
        task_id="t1",
        role=SpecialistRole.VULNERABILITY,
        target="target.local",
        success=True,
        discovered_nodes=[{"node_type": "VULNERABILITY", "label": "BOLA"}],
        evidence_items=[EvidenceItem(type=EvidenceType.BEHAVIOR_DIFF, source="prober", description="diff verified")]
    )
    approved, msg = critic.review_report(good_rep)
    assert approved is True
    assert "Critic Approved" in msg

    # Report claiming vuln WITHOUT conclusive evidence -> Rejected
    bad_rep = SpecialistReport(
        task_id="t2",
        role=SpecialistRole.VULNERABILITY,
        target="target.local",
        success=True,
        discovered_nodes=[{"node_type": "VULNERABILITY", "label": "Speculative SQLi"}],
        evidence_items=[EvidenceItem(type=EvidenceType.STATUS_CODE, source="prober", description="only 200")]
    )
    rejected, reject_msg = critic.review_report(bad_rep)
    assert rejected is False
    assert "Critic Rejected" in reject_msg


@pytest.mark.asyncio
async def test_lead_analyst_end_to_end_coordination():
    analyst = LeadAnalyst(target="demo.target.local")
    result = await analyst.coordinate_investigation(target="demo.target.local")

    assert result["status"] == "COMPLETED"
    assert result["graph_summary"]["total_nodes"] > 0
    assert result["graph_summary"]["total_edges"] > 0
    assert result["hypotheses_active"] > 0
    assert len(result["investigation_trace"]) >= 4
    assert result["blast_radius"]["reachable_count"] > 0
