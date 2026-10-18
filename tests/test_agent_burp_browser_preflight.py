import pytest

from hunter_ai.pipeline.pipeline_orchestrator import HunterPipelineOrchestrator


@pytest.mark.asyncio
async def test_strict_preflight_blocks_before_any_target_request(tmp_path):
    """A strict run must stop locally when the Burp path is unavailable."""
    orchestrator = HunterPipelineOrchestrator(
        target="https://example.test",
        in_scope=["example.test"],
        require_burp_browser=True,
        allow_no_ai=True,
    )
    orchestrator.artifact_root = str(tmp_path)

    ready = await orchestrator.stage_integration_preflight()

    assert ready is False
    assert orchestrator.integration_preflight["ready"] is False
    assert orchestrator.integration_preflight["proxy"]["reachable"] is False
