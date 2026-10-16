"""
Tests: Unified Reasoning — DeepSeek-R1 + Claude + Hybrid Core
=============================================================
Validates the reflective reasoning scaffold end-to-end without requiring a live
model: decomposition, path exploration, independent verification, "wait"-
backtracking, self-consistency voting, rumination-halt, calibrated uncertainty,
and adaptive strategy routing.
"""
from __future__ import annotations

from core.cognitive import (
    ClaudeThinkingEngine,
    DeepSeekThinkingEngine,
    DeepSeekVerdict,
    HybridReasoningCore,
    ReasoningStrategy,
    ReasoningStepKind,
    ThinkingMode,
)


# ── DeepSeek-R1 engine ───────────────────────────────────────────────────────
def test_deepseek_decomposition_produces_subgoals():
    eng = DeepSeekThinkingEngine()
    subgoals = eng.decompose("Check if the login parameter allows SQL injection on the auth endpoint")
    assert len(subgoals) >= 2
    assert any("scope" in s.lower() or "authorization" in s.lower() for s in subgoals)


def test_deepseek_explore_paths_respects_cap():
    eng = DeepSeekThinkingEngine(max_paths=2)
    paths = eng.explore_paths("problem", ["g1"], candidate_answers=["a", "b", "c", "d"])
    assert len(paths) == 2


def test_deepseek_verify_refutes_missing_constraint():
    eng = DeepSeekThinkingEngine()
    p = eng.explore_paths("p", ["g"], candidate_answers=["vulnerable"])[0]
    eng.verify_path(p, constraints=["proof-of-execution"])
    assert p.verified is False
    assert "missing required constraint" in p.verification_note.lower()


def test_deepseek_verify_accepts_satisfied_constraint():
    eng = DeepSeekThinkingEngine()
    p = eng.explore_paths("p", ["g"], candidate_answers=["vulnerable with proof-of-execution"])[0]
    eng.verify_path(p, constraints=["proof-of-execution"])
    assert p.verified is True


def test_deepseek_self_consistency_majority():
    eng = DeepSeekThinkingEngine()
    paths = eng.explore_paths("p", ["g"], candidate_answers=["X", "X", "Y"])
    for p in paths:
        eng.verify_path(p)
    answer, ratio, votes = eng.self_consistency(paths)
    assert answer == "X"
    assert votes == 2
    assert 0.6 < ratio < 0.7


def test_deepseek_backtrack_marks_aha_and_lowers_confidence():
    eng = DeepSeekThinkingEngine()
    p = eng.explore_paths("p", ["g"], candidate_answers=["X"])[0]
    before = p.confidence
    step = eng.backtrack(p, "contradicted by evidence")
    assert step.is_aha is True
    assert "wait" in step.content.lower()
    assert p.confidence < before


def test_deepseek_rumination_halt_on_diminishing_returns():
    eng = DeepSeekThinkingEngine(rumination_epsilon=0.0, rumination_patience=2)
    assert eng.should_halt([1.0, 0.0, 0.0]) is True
    assert eng.should_halt([1.0, 0.0, 1.0]) is False
    assert eng.should_halt([0.0]) is False


def test_deepseek_think_converges_on_consistent_paths():
    eng = DeepSeekThinkingEngine()
    trace = eng.think("Is it vulnerable?", candidate_answers=["vulnerable", "vulnerable", "safe"])
    assert trace.verdict == DeepSeekVerdict.CONVERGED
    assert trace.chosen_answer == "vulnerable"
    assert trace.confidence >= 0.5


def test_deepseek_think_disproved_when_all_refuted():
    eng = DeepSeekThinkingEngine()
    trace = eng.think("q", constraints=["canary-leak"], candidate_answers=["irrelevant"])
    assert trace.verdict == DeepSeekVerdict.DISPROVED
    assert trace.chosen_answer == ""


def test_deepseek_think_uncertain_without_majority():
    eng = DeepSeekThinkingEngine()
    trace = eng.think("q", candidate_answers=["a", "b", "c"])
    assert trace.verdict in (DeepSeekVerdict.UNCERTAIN, DeepSeekVerdict.HALTED_RUMINATION)
    assert trace.agreement_ratio <= 0.5


def test_deepseek_think_counts_aha_from_backtracking():
    eng = DeepSeekThinkingEngine()
    trace = eng.think("q", constraints=["needed"], candidate_answers=["nope"])
    assert trace.aha_count >= 1


def test_deepseek_steering_prompt_shape():
    eng = DeepSeekThinkingEngine()
    prompt = eng.system_prompt_steering("target problem")
    assert "<deepseek_reasoning_protocol>" in prompt
    assert "wait, let me reconsider" in prompt.lower()
    assert "target problem" in prompt


def test_deepseek_step_kinds_present():
    eng = DeepSeekThinkingEngine()
    trace = eng.think("q", candidate_answers=["x", "x"])
    kinds = {s.kind for s in trace.steps}
    assert ReasoningStepKind.DECOMPOSE in kinds
    assert ReasoningStepKind.VERIFY in kinds
    assert ReasoningStepKind.CONCLUDE in kinds


# ── Hybrid core ──────────────────────────────────────────────────────────────
def test_hybrid_complexity_ordering():
    core = HybridReasoningCore()
    low = core.assess_complexity("list files", stakes="low")
    high = core.assess_complexity(
        "why how explain trade-off architecture multi hypothesis contradiction "
        "root cause chain exploit bypass reason",
        observations=["o1", "o2", "o3", "o4", "o5"],
        stakes="critical",
    )
    assert low < high
    assert 0.0 <= low <= 1.0 and 0.0 <= high <= 1.0


def test_hybrid_select_strategy_thresholds():
    core = HybridReasoningCore()
    assert core.select_strategy(0.1) == ReasoningStrategy.CLAUDE_CONCISE
    assert core.select_strategy(0.5) == ReasoningStrategy.DEEPSEEK_R1
    assert core.select_strategy(0.9) == ReasoningStrategy.HYBRID_DEEP


def test_hybrid_routes_trivial_to_concise():
    core = HybridReasoningCore()
    result = core.think("list files", stakes="low")
    assert result.strategy == ReasoningStrategy.CLAUDE_CONCISE
    assert result.claude_mode == ThinkingMode.CONCISE.value


def test_hybrid_routes_medium_to_deepseek():
    core = HybridReasoningCore()
    problem = (
        "Analyse the authentication boundary of the API and identify whether the "
        "session token can be replayed across tenants given the observed responses"
    )
    result = core.think(problem, candidate_answers=["replayable", "replayable"], stakes="medium")
    assert result.strategy == ReasoningStrategy.DEEPSEEK_R1
    assert result.chosen_answer == "replayable"


def test_hybrid_routes_complex_to_hybrid_deep():
    core = HybridReasoningCore()
    problem = (
        "why how explain trade-off architecture multi hypothesis contradiction "
        "root cause chain exploit bypass reason"
    )
    result = core.think(
        problem,
        observations=["o1", "o2", "o3", "o4", "o5"],
        candidate_answers=["vulnerable", "vulnerable"],
        stakes="critical",
    )
    assert result.strategy == ReasoningStrategy.HYBRID_DEEP
    assert result.claude_mode == ThinkingMode.DEEP_AUDIT.value


def test_hybrid_decision_summary_is_cot_free():
    core = HybridReasoningCore()
    result = core.think("q", candidate_answers=["a", "a"], stakes="medium")
    summary = core.decision_summary(result)
    # Concise, observable rationale only — no raw chain-of-thought field.
    assert "rationale" in summary
    assert "reasoning_stats" in summary or result.strategy == ReasoningStrategy.CLAUDE_CONCISE
    assert "inner_monologue" not in summary


# ── Claude engine (previously untested) ──────────────────────────────────────
def test_claude_steering_prompt_shape():
    eng = ClaudeThinkingEngine(mode=ThinkingMode.EXTENDED)
    prompt = eng.generate_system_prompt_steering("Strategist")
    assert "<anthropic_thinking_protocol>" in prompt
    assert "MULTIPLE HYPOTHESES" in prompt.upper()


def test_claude_spawns_competing_hypotheses():
    eng = ClaudeThinkingEngine()
    hyps = eng.spawn_competing_hypotheses("user id exposed in URL", "app.local")
    assert len(hyps) >= 2
    assert all(h.refutation_criteria for h in hyps)


def test_claude_interleaved_reflection_blocks():
    eng = ClaudeThinkingEngine()
    pre = eng.pre_tool_deliberation("ffuf", "app.local", {"w": "list"})
    post, hyp = eng.post_tool_deliberation("ffuf", 200, "substantive payload " * 3)
    assert "thinking" in pre
    assert "thinking" in post
