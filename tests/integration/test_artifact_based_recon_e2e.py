"""
Integration: full HunterAI orchestrator artifact generation (LIVE).

This test drives the real orchestrator end-to-end: it performs live DNS/HTTP
recon against example.com, runs installed external tools, starts the local Burp
gateway on 127.0.0.1:8085 and executes a live AI inference preflight against
Ollama.  It is therefore an integration test and is excluded from the offline
unit suite (CI ignores ``tests/integration``).

Run explicitly with:
    python -m pytest tests/integration/test_artifact_based_recon_e2e.py -q -s
"""
import pytest

from hunter_ai.pipeline.pipeline_orchestrator import HunterPipelineOrchestrator

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_orchestrator_artifact_generation(tmp_path):
    base_dir = tmp_path / "engagements"

    orch = HunterPipelineOrchestrator(
        target="http://example.com",
        authorized=False,
        workflow="passive",
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
