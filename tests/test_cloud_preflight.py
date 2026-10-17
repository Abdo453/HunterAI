"""LEDGER-023: cloud-aware AI preflight (pipeline triad → unified router).

When the local Ollama triad is unreachable but a cloud provider key is
configured, the preflight gate certifies the **cloud** cognitive layer instead
of aborting the scan. Truthfulness is preserved: ``online`` stays False (the
local host really is down) and ``backend``/``backend_detail`` record where the
cognition actually runs.
"""
from __future__ import annotations

import asyncio

from hunter_ai.brain.ai_preflight import AIPreflightGate

# A closed port: nothing listens here, so Tier-1 connectivity deterministically fails.
DEAD_HOST = "http://127.0.0.1:59999"


def test_offline_without_cloud_fails_closed():
    r = AIPreflightGate.run_preflight(host=DEAD_HOST, timeout_sec=0.5)
    assert r.online is False
    assert r.allowed is False
    assert r.status == "FAILED"
    assert r.backend == "ollama"


def test_offline_with_cloud_backend_is_ready_and_truthful():
    r = AIPreflightGate.run_preflight(
        host=DEAD_HOST, timeout_sec=0.5, cloud_backend="gemini:gemini-2.0-flash"
    )
    assert r.allowed is True
    assert r.status == "AI_READY"
    assert r.degraded is False
    assert r.backend == "cloud"
    assert r.backend_detail == "gemini:gemini-2.0-flash"
    # The local host is genuinely down — that fact is not papered over.
    assert r.online is False
    assert r.error_message is None


def test_offline_with_cloud_overrides_degraded():
    r = AIPreflightGate.run_preflight(
        host=DEAD_HOST, timeout_sec=0.5, allow_degraded=True,
        cloud_backend="gemini:gemini-2.0-flash",
    )
    # Cloud wins over degraded mode: real AI reasoning is available.
    assert r.status == "AI_READY"
    assert r.degraded is False


def test_banner_announces_cloud_backend():
    r = AIPreflightGate.run_preflight(
        host=DEAD_HOST, timeout_sec=0.5, cloud_backend="gemini:gemini-2.0-flash"
    )
    banner = AIPreflightGate.format_status_banner(r)
    assert "gemini:gemini-2.0-flash" in banner
    assert "Cloud" in banner


def test_result_dict_exposes_backend():
    r = AIPreflightGate.run_preflight(
        host=DEAD_HOST, timeout_sec=0.5, cloud_backend="gemini:gemini-2.0-flash"
    )
    d = r.to_dict()
    assert d["backend"] == "cloud"
    assert d["backend_detail"] == "gemini:gemini-2.0-flash"


def test_async_wrapper_passes_cloud_backend():
    r = asyncio.run(AIPreflightGate.run_preflight_async(
        host=DEAD_HOST, timeout_sec=0.5, cloud_backend="gemini:gemini-2.0-flash"
    ))
    assert r.allowed is True and r.backend == "cloud"


def test_pipeline_resolver_picks_configured_provider(monkeypatch):
    import hunter_ai.pipeline.pipeline_orchestrator as po

    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    class _Stub:  # _resolve_cloud_backend only needs self + the router
        pass

    resolved = asyncio.run(po.HunterPipelineOrchestrator._resolve_cloud_backend(_Stub()))
    assert resolved is not None
    assert resolved.startswith("gemini:")


def test_pipeline_resolver_returns_none_without_keys(monkeypatch):
    import hunter_ai.pipeline.pipeline_orchestrator as po
    from core.llm_router import CLOUD_PROVIDERS

    for spec in CLOUD_PROVIDERS:
        monkeypatch.delenv(spec.env_key, raising=False)

    class _Stub:
        pass

    assert asyncio.run(po.HunterPipelineOrchestrator._resolve_cloud_backend(_Stub())) is None


def test_pipeline_preflight_uses_cloud_when_ollama_down(monkeypatch, tmp_path):
    """End-to-end wiring: pipeline preflight must reach AI_READY via the cloud.

    Regression guard for the state-machine path: AI_CONNECTING must walk
    MODEL_VERIFYING -> INFERENCE_VERIFYING -> AI_READY (a direct jump is illegal).
    """
    import hunter_ai.pipeline.pipeline_orchestrator as po

    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setenv("HUNTER_UNRESTRICTED", "0")  # governed: cloud is the only way out

    events = []

    async def cb(ev):
        events.append(ev)

    async def scenario():
        orch = po.HunterPipelineOrchestrator(
            target="https://example.com",
            authorized=True,
            workflow="passive",
            ollama_host="http://127.0.0.1:59999",  # deterministic: nothing listens
            progress_cb=cb,
        )
        base = tmp_path
        orch.engagement_mgr.base_dir = base
        orch.engagement_mgr.target_dir = base / orch.engagement_mgr.clean_target
        orch.engagement_mgr.run_dir = orch.engagement_mgr.target_dir / orch.engagement_mgr.timestamp
        for sc in orch.engagement_mgr.stages:
            (orch.engagement_mgr.run_dir / sc).mkdir(parents=True, exist_ok=True)
        orch.artifact_root = orch.engagement_mgr.run_dir
        return orch, await orch.stage_ai_preflight()

    orch, ok = asyncio.run(scenario())

    assert ok is True, "cloud fallback should unblock the pipeline"
    assert orch.ai_backend == "cloud"
    assert orch.ai_degraded is False
    r = orch.ai_preflight_result
    assert r.status == "AI_READY"
    assert r.online is False                       # local Ollama genuinely unreachable
    assert r.backend_detail.startswith("gemini:")
    assert any(e.get("event") == "preflight_cloud" for e in events)
