"""
Tests for HunterAI Artifact-Based Recon System
Verifies:
1. 15-Stage Directory Hierarchy creation
2. Target run isolation & latest.txt pointer
3. Triple Artifact Pattern (.raw.txt, .parsed.json, .meta.json)
4. Manifest, Timeline, and Lineage Graph persistence
5. Full orchestrator artifact generation end-to-end
"""
import json
import os
import shutil
import pytest
from pathlib import Path

from hunter_ai.pipeline.engagement_manager import EngagementManager
from hunter_ai.pipeline.pipeline_orchestrator import HunterPipelineOrchestrator
from hunter_ai.pipeline.tool_specs import MasterToolRegistry
from tools.tool_manager import ToolManager, ToolResult


@pytest.fixture
def temp_engagement_dir(tmp_path):
    base_dir = tmp_path / "engagements"
    return base_dir


def test_engagement_manager_directory_hierarchy(temp_engagement_dir):
    mgr = EngagementManager(
        target="https://app.target.com",
        base_dir=temp_engagement_dir,
        workflow="recon"
    )

    assert mgr.clean_target == "app_target_com"
    assert Path(mgr.run_dir).exists()

    latest_file = Path(mgr.target_dir) / "latest.txt"
    assert latest_file.exists()
    assert mgr.timestamp in latest_file.read_text(encoding="utf-8")

    for stage_code in [
        "00_scope", "01_osint", "02_subdomains", "03_dns", "04_alive",
        "05_ports", "06_content", "07_urls", "08_parameters", "09_javascript",
        "10_api", "11_technology", "12_vulnerabilities", "13_evidence", "14_reports"
    ]:
        stage_path = mgr.get_stage_path(stage_code)
        assert stage_path.exists() and stage_path.is_dir(), f"Stage {stage_code} was not created!"


def test_triple_artifact_pattern(temp_engagement_dir):
    mgr = EngagementManager(
        target="target.com",
        base_dir=temp_engagement_dir
    )

    mgr.start_stage("02_subdomains")
    raw_content = "[*] subfinder v2.6.0\nadmin.target.com\napi.target.com\n"
    parsed_items = ["admin.target.com", "api.target.com"]

    meta = mgr.save_tool_artifact(
        stage_name="02_subdomains",
        tool_name="subfinder",
        command_used="subfinder -d target.com -silent",
        raw_output=raw_content,
        parsed_data=parsed_items,
        duration_ms=450.5,
        input_source="target.com",
        next_stage="03_dns"
    )

    raw_file = Path(meta.raw_output_file)
    assert raw_file.exists()
    raw_text = raw_file.read_text(encoding="utf-8")
    assert "subfinder v2.6.0" in raw_text
    assert "admin.target.com" in raw_text

    parsed_file = Path(meta.parsed_data_file)
    assert parsed_file.exists()
    with open(parsed_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data == parsed_items

    meta_file = Path(meta.metadata_file)
    assert meta_file.exists()
    with open(meta_file, "r", encoding="utf-8") as f:
        meta_json = json.load(f)
    assert meta_json["tool_name"] == "subfinder"
    assert meta_json["item_count"] == 2
    assert meta_json["next_stage"] == "03_dns"

    mgr.complete_stage("02_subdomains", item_count=2)


def test_lineage_and_manifest_tracking(temp_engagement_dir):
    mgr = EngagementManager(
        target="example.com",
        base_dir=temp_engagement_dir
    )

    mgr.record_lineage(
        asset_id="example.com",
        asset_value="example.com",
        asset_type="domain",
        tool="scope_guard",
        stage="00_scope"
    )

    mgr.record_lineage(
        asset_id="api.example.com",
        asset_value="api.example.com",
        asset_type="domain",
        tool="subfinder",
        stage="02_subdomains",
        parent_id="example.com"
    )

    mgr.record_lineage(
        asset_id="https://api.example.com/v1/users",
        asset_value="https://api.example.com/v1/users",
        asset_type="endpoint",
        tool="crawler",
        stage="07_urls",
        parent_id="api.example.com"
    )

    manifest = mgr.finalize(findings_count=0, live_assets_count=1, endpoints_count=1)

    assert mgr.manifest_file.exists()
    with open(mgr.manifest_file, "r", encoding="utf-8") as f:
        mf = json.load(f)
    assert mf["target"] == "example.com"
    assert "00_scope" in mf["stages"]

    assert mgr.lineage_file.exists()
    with open(mgr.lineage_file, "r", encoding="utf-8") as f:
        lg = json.load(f)
    assert "example.com" in lg
    assert "api.example.com" in lg
    assert lg["api.example.com"]["parent_id"] == "example.com"

    assert mgr.timeline_file.exists()
    with open(mgr.timeline_file, "r", encoding="utf-8") as f:
        tl = json.load(f)
    assert len(tl) >= 2


@pytest.mark.asyncio
async def test_orchestrator_artifact_generation(tmp_path):
    base_dir = tmp_path / "engagements"

    orch = HunterPipelineOrchestrator(
        target="http://example.com",
        authorized=False,
        workflow="passive"
    )
    orch.engagement_mgr.base_dir = base_dir
    orch.engagement_mgr.target_dir = base_dir / orch.engagement_mgr.clean_target
    orch.engagement_mgr.run_dir = orch.engagement_mgr.target_dir / orch.engagement_mgr.timestamp
    for sc in orch.engagement_mgr.stages:
        (orch.engagement_mgr.run_dir / sc).mkdir(parents=True, exist_ok=True)
    orch.artifact_root = orch.engagement_mgr.run_dir

    result = await orch.run()

    assert result["status"] == "completed"
    assert "engagement_directory" in result
    assert "manifest_file" in result

    assert (orch.engagement_mgr.run_dir / "00_scope" / "scope.json").exists()
    assert (orch.engagement_mgr.run_dir / "01_osint" / "google_dorks.txt").exists()
    assert (orch.engagement_mgr.run_dir / "02_subdomains" / "all_subdomains.txt").exists()
    assert (orch.engagement_mgr.run_dir / "04_alive" / "alive_hosts.txt").exists()
    assert (orch.engagement_mgr.run_dir / "14_reports" / "bug_bounty_report.md").exists()
    assert (orch.engagement_mgr.run_dir / "14_reports" / "report.html").exists()

    assert orch.engagement_mgr.manifest_file.exists()
    assert orch.engagement_mgr.lineage_file.exists()
