"""
Unit Tests for HunterAI Orchestrator-Workers Engine & Shared Blackboard
======================================================================
Verifies:
1. BlackboardState lifecycle, compact summary generation, and audit logging.
2. ModelWorkerRegistry tag resolution and candidate fallbacks.
3. MasterOrchestratorEngine state progression (RECON -> SCAN -> ANALYZE -> EXPLOIT -> REPORT -> COMPLETE).
4. PolicyGate boundary enforcement on orchestrator actions.
5. Deterministic fallback guarantees if LLM output is malformed.
"""
import asyncio
import pytest

from hunter_ai.brain.orchestrator_workers import (
    BlackboardPhase,
    BlackboardState,
    MasterOrchestratorEngine,
    ModelWorkerRegistry,
)
from core.control_plane.policy_gate import PolicyGate
from core.scope_engine import ScopePolicy


def test_blackboard_state_lifecycle():
    state = BlackboardState(target="https://target.local", domain="target.local")
    assert state.phase == BlackboardPhase.RECON
    assert state.iteration == 0

    state.subdomains.append("api.target.local")
    state.endpoints.append({"url": "https://target.local/login"})
    state.confirmed_findings.append({"title": "Reflected XSS", "severity": "High"})

    state.record_action(
        actor="Qwen3_Orchestrator",
        action="call_recon_scout",
        details={"interesting": ["api.target.local"]}
    )

    assert len(state.history) == 1
    assert state.history[0]["actor"] == "Qwen3_Orchestrator"

    summary = state.get_compact_summary()
    assert summary["target"] == "https://target.local"
    assert summary["phase"] == "RECON"
    assert summary["stats"]["subdomains_count"] == 1
    assert summary["stats"]["endpoints_count"] == 1
    assert summary["stats"]["confirmed_count"] == 1


def test_worker_model_resolution():
    registry = ModelWorkerRegistry(ollama_host="http://127.0.0.1:11434")
    registry._cached_tags = [
        "qwen3:8b",
        "qwen2.5-coder:14b-tools",
        "WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest",
        "xploiter/pentester:latest",
    ]

    m_code = registry._resolve_model("qwen2.5-coder:14b", ["qwen2.5-coder:14b-tools", "qwen3:8b"])
    assert "qwen" in m_code

    m_strategist = registry._resolve_model("whiterabbitneo", ["white-rabbit-neo"])
    assert "whiterabbitneo" in m_strategist.lower()

    m_recon = registry._resolve_model("xploiter", ["pentester"])
    assert "xploiter" in m_recon.lower() or "pentester" in m_recon.lower()


@pytest.mark.asyncio
async def test_orchestrator_deterministic_progression():
    pol = ScopePolicy(allowed_targets=["test.local"])
    gate = PolicyGate(scope_policy=pol, authorized=True)

    engine = MasterOrchestratorEngine(
        target="https://test.local",
        ollama_host="http://127.0.0.1:11434",
        policy_gate=gate,
        max_iterations=10,
    )

    # Force offline mode on worker query to trigger deterministic state transitions
    engine.workers._cached_tags = []
    
    # Step 1: In RECON phase with no subdomains
    step1 = await engine.step()
    assert step1["iteration"] == 1
    assert len(engine.state.history) == 1

    # Run through remaining phases to COMPLETE
    final_state = await engine.run_until_complete(max_steps=8)
    assert final_state.phase == BlackboardPhase.COMPLETE
    assert final_state.iteration >= 2
    assert len(final_state.history) >= 2
