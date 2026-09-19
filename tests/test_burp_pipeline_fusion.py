"""
HunterAI Burp Pipeline Fusion & Full Utilization Integration Tests
==================================================================
Tests:
1. Auto-detection & Initialization of Burp Suite Subsystem in Pipeline Orchestrator.
2. Real-time traffic ingestion, parameter discovery, and CouncilState enrichment.
3. Triad Agent EvidenceBus sensory integration with Burp traffic.
4. Burp Repeater differential experiment creation and execution.
5. Bidirectional findings export to Burp Gateway and Target tab sync.
6. Desktop Workspace exporter generating 08_Burp_Suite artifacts.
"""
import asyncio
import os
import shutil
import tempfile
import pytest
from pathlib import Path

from hunter_ai.pipeline.pipeline_orchestrator import HunterPipelineOrchestrator
from hunter_ai.brain.cognitive_council import CognitiveCouncil, CouncilState, CouncilRole
from hunter_ai.brain.local_triad_agent import LocalTriadAgent, AgentEvidence
from hunter_ai.pipeline.desktop_exporter import DesktopExportManager
from hunter_ai.pipeline.schemas import EndpointRecord, ParameterRecord, HunterFinding, FindingTier


@pytest.fixture
def temp_workspace():
    tmp = tempfile.mkdtemp(prefix="hunter_burp_fusion_")
    yield tmp
    try:
        shutil.rmtree(tmp)
    except Exception:
        pass


@pytest.mark.asyncio
async def test_burp_subsystem_initialization_and_auto_detect(temp_workspace):
    """Verifies Burp subsystem attributes and initialization logic."""
    orch = HunterPipelineOrchestrator(
        target="http://testphp.vulnweb.com",
        profile="safe",
        dry_run=True,
        authorized=True,
        allow_no_ai=True,
        skip_ai_probe=True,
    )
    orch.artifact_root = temp_workspace

    assert hasattr(orch, "burp_detected")
    assert hasattr(orch, "burp_transactions")
    assert hasattr(orch, "burp_repeater_experiments")
    assert orch.burp_transactions == []
    assert orch.burp_repeater_experiments == []

    # Initialize subsystem
    await orch._init_burp_agent_subsystem()
    assert orch.burp_controller is not None
    assert orch.burp_research_controller is not None
    assert orch._burp_agent is not None


@pytest.mark.asyncio
async def test_burp_traffic_ingestion_and_council_enrichment(temp_workspace):
    """Verifies that incoming Burp traffic parses endpoints, parameters, and enriches CouncilState."""
    orch = HunterPipelineOrchestrator(
        target="http://testphp.vulnweb.com",
        profile="safe",
        dry_run=True,
        authorized=True,
        allow_no_ai=True,
        skip_ai_probe=True,
    )
    orch.artifact_root = temp_workspace
    await orch._init_burp_agent_subsystem()

    # Create dummy triad agent instance
    triad = LocalTriadAgent()
    orch._triad_instance = triad

    raw_request = (
        "GET /artists.php?artist=1&debug=true HTTP/1.1\r\n"
        "Host: testphp.vulnweb.com\r\n"
        "User-Agent: Mozilla/5.0\r\n"
        "Cookie: sessionid=abc12345; auth=token_xyz\r\n"
        "\r\n"
    )
    payload = {
        "request": raw_request,
        "host": "testphp.vulnweb.com",
        "port": 80,
        "protocol": "http",
        "tool": "proxy",
        "status_code": 200,
    }

    # Process traffic event
    await orch._process_burp_traffic_event(payload)

    # Verify transactions logged
    assert len(orch.burp_transactions) == 1
    tx = orch.burp_transactions[0]
    assert tx["method"] == "GET"
    assert "artists.php" in tx["url"]

    # Verify endpoint extracted
    endpoint_urls = [e.url for e in orch.endpoints]
    assert any("artists.php" in u for u in endpoint_urls)

    # Verify parameters extracted
    param_names = [p.parameter for p in orch.parameters]
    assert "artist" in param_names
    assert "debug" in param_names

    # Verify CouncilState updated with traffic
    assert len(orch.council.state.traffic_transactions) == 1
    council_slice = orch.council.state.get_context_slice_for_role(CouncilRole.OFFENSIVE_STRATEGIST)
    assert council_slice["traffic_count"] == 1
    assert len(council_slice["recent_traffic_samples"]) == 1

    # Verify Triad EvidenceBus received traffic evidence
    traffic_ev = triad.bus.get_evidence_by_category("traffic")
    assert len(traffic_ev) == 1
    assert "artists.php" in traffic_ev[0].observation


@pytest.mark.asyncio
async def test_burp_repeater_differential_experiments(temp_workspace):
    """Verifies that BurpController creates and executes repeater experiments with differential analysis."""
    orch = HunterPipelineOrchestrator(
        target="http://testphp.vulnweb.com",
        profile="safe",
        dry_run=False,
        authorized=True,
        allow_no_ai=True,
        skip_ai_probe=True,
    )
    orch.artifact_root = temp_workspace
    await orch._init_burp_agent_subsystem()

    # Create Repeater Experiment
    exp = orch.burp_controller.create_repeater_experiment(
        base_tx_id="tx_baseline_01",
        hypothesis="Differential SQLi probe on artist parameter",
        mutation_description="Injected SQL boolean differential payload",
        mutated_request={
            "method": "GET",
            "url": "http://testphp.vulnweb.com/artists.php?artist=1%27%20OR%20%271%27=%271",
            "headers": {"User-Agent": "HunterAI-Burp-Repeater/1.0", "X-Hunter-Probe": "SQLi"}
        }
    )

    executed = await orch.burp_controller.execute_experiment(exp.experiment_id)
    assert executed.experiment_id == exp.experiment_id
    assert executed.outcome_status == 200
    assert "Executed mutation" in executed.diff_summary
    assert executed.response_tx_id is not None


@pytest.mark.asyncio
async def test_burp_findings_registration_and_desktop_export(temp_workspace):
    """Verifies that confirmed findings register in BurpGateway and export to 08_Burp_Suite on Desktop."""
    orch = HunterPipelineOrchestrator(
        target="http://testphp.vulnweb.com",
        profile="safe",
        dry_run=True,
        authorized=True,
        allow_no_ai=True,
        skip_ai_probe=True,
    )
    orch.artifact_root = temp_workspace
    await orch._init_burp_agent_subsystem()

    # Add dummy finding
    finding = HunterFinding(
        finding="SQL Injection in artist parameter",
        category="Injection",
        asset="testphp.vulnweb.com",
        vuln_type="SQLi",
        endpoint="http://testphp.vulnweb.com/artists.php",
        parameter="artist",
        tier=FindingTier.VERIFIED_FINDING,
        severity="Critical",
        cvss_score=9.8,
        remediation="SQL injection verified via differential arithmetic reflection."
    )
    orch.findings.append(finding)

    # Register finding with gateway
    f_dict = finding.model_dump()
    orch._burp_agent.gateway.register_confirmed_finding({
        "title": f_dict["finding"],
        "severity": f_dict["severity"],
        "endpoint": f_dict["endpoint"],
        "vuln_type": "SQLi",
        "description": f_dict.get("remediation", f_dict["finding"]),
    })

    assert len(orch._burp_agent.gateway.confirmed_findings) == 1

    # Save artifacts in run directory
    burp_dir = Path(temp_workspace) / "08_burp_suite"
    burp_dir.mkdir(parents=True, exist_ok=True)
    with open(burp_dir / "burp_findings_issues.json", "w", encoding="utf-8") as f:
        f.write('{"status": "exported"}')

    # Test DesktopExportManager exports 08_Burp_Suite
    exported_folder = DesktopExportManager.export_engagement(
        domain="testphp.vulnweb.com",
        artifact_root=temp_workspace,
        reports_dict={"markdown": None, "html": None, "json": None},
        subdomains=[],
        live_assets=[],
        endpoints=[EndpointRecord(url="http://testphp.vulnweb.com/artists.php", path="/artists.php", method="GET", category="API")],
        parameters=[ParameterRecord(parameter="artist", endpoint="http://testphp.vulnweb.com/artists.php", method="GET")],
        findings=[finding],
        tool_logs=[],
        workflow="full",
        profile="safe"
    )

    desktop_burp_dir = Path(exported_folder) / "08_Burp_Suite"
    assert desktop_burp_dir.is_dir()
    assert (desktop_burp_dir / "burp_findings_issues.json").is_file()
