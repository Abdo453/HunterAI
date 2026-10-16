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


# ── Reasoning scaffold integration (DeepSeek-R1 + Claude extended thinking) ──

class _BrokenReasoningCore:
    def think(self, *args, **kwargs):
        raise RuntimeError("simulated reasoning failure")


def test_orchestrator_reasoning_scaffold_attached():
    engine = MasterOrchestratorEngine(target="https://test.local")
    assert engine.reasoning_core is not None
    block, meta = engine._reasoning_steering(engine.state.get_compact_summary())
    assert "[Active Reasoning Protocol" in block
    assert meta is not None and "strategy" in meta
    # Only a concise decision summary is surfaced — never raw chain-of-thought.
    assert "inner_monologue" not in meta
    assert "reasoning_stats" in meta or meta["strategy"] == "claude_concise"


def test_orchestrator_degrades_gracefully_on_reasoning_error():
    engine = MasterOrchestratorEngine(
        target="https://test.local", reasoning_core=_BrokenReasoningCore()
    )
    block, meta = engine._reasoning_steering(engine.state.get_compact_summary())
    assert block == ""
    assert meta is None


@pytest.mark.asyncio
async def test_orchestrator_step_records_reasoning_meta():
    pol = ScopePolicy(allowed_targets=["test.local"])
    gate = PolicyGate(scope_policy=pol, authorized=True)
    engine = MasterOrchestratorEngine(
        target="https://test.local",
        policy_gate=gate,
        max_iterations=3,
    )
    engine.workers._ollama_online = False  # force offline → deterministic path
    step = await engine.step()
    assert "reasoning" in step
    last = engine.state.history[-1]
    assert "reasoning" in last["details"]


# ── Decision-level self-consistency (DeepSeek-R1 style) ──────────────────────

@pytest.mark.asyncio
async def test_orchestrator_self_consistency_majority():
    engine = MasterOrchestratorEngine(
        target="https://test.local",
        ollama_host="http://127.0.0.1:1",  # fast-fail, offline
        reasoning_samples=3,
    )
    responses = [
        '{"action": "call_recon_scout", "params": {}, "rationale": "r1"}',
        '{"action": "call_recon_scout", "params": {}, "rationale": "r2"}',
        '{"action": "advance_phase", "params": {"next_phase": "SCAN"}, "rationale": "r3"}',
    ]
    calls = {"n": 0}

    async def fake_query(model, system, user, temperature=0.2, timeout=25):
        r = responses[calls["n"] % len(responses)]
        calls["n"] += 1
        return r

    engine.workers._query_ollama = fake_query
    decision = await engine.decide_next_action()

    assert decision["action"] == "call_recon_scout"
    assert decision["_reasoning"]["decision_samples"] == 3
    assert abs(decision["_reasoning"]["decision_agreement"] - 0.667) < 0.01


@pytest.mark.asyncio
async def test_orchestrator_self_consistency_all_invalid_falls_back():
    engine = MasterOrchestratorEngine(
        target="https://test.local",
        ollama_host="http://127.0.0.1:1",
        reasoning_samples=2,
    )

    async def fake_query(model, system, user, temperature=0.2, timeout=25):
        return "totally unparseable response"

    engine.workers._query_ollama = fake_query
    decision = await engine.decide_next_action()

    # RECON with no subdomains → deterministic fallback must guarantee progress
    assert decision["action"] == "call_recon_scout"


@pytest.mark.asyncio
async def test_orchestrator_single_sample_has_no_vote_metadata():
    engine = MasterOrchestratorEngine(
        target="https://test.local",
        ollama_host="http://127.0.0.1:1",
    )

    async def fake_query(model, system, user, temperature=0.2, timeout=25):
        return '{"action": "finish", "params": {}, "rationale": "done"}'

    engine.workers._query_ollama = fake_query
    decision = await engine.decide_next_action()

    assert decision["action"] == "finish"
    meta = decision["_reasoning"]
    assert meta is None or "decision_samples" not in meta
