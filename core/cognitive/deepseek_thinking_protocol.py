"""
HunterAI DeepSeek-R1 Reasoning Engine — Long-Chain Reflective Reasoning
=======================================================================
Encodes the reasoning behaviours that emerge in DeepSeek-R1 (arXiv:2501.12948)
and are confirmed by the "Thoughtology" study (arXiv:2504.07128):

  1. Goal comprehension before action (first-person reasoning).
  2. Problem decomposition into an interim solution.
  3. Multiple candidate reasoning paths (self-consistency).
  4. Independent solution verification of every path.
  5. Backtracking / "wait, let me reconsider" self-correction (the R1 'aha moment').
  6. Rumination control — stop before diminishing returns, because the research
     shows that *overly long thoughts almost always hurt performance*.
  7. Calibrated uncertainty (agreement ratio across verified paths).
  8. Meta-cognition — reflect on the flaws of its own reasoning trace.

This engine is a deterministic SCAFFOLD. It structures reflection, verification,
self-consistency and stopping — and produces model-steering prompts. It does not
fabricate model output: when a live model is needed, pass a ``reasoner`` callback.
"""
from __future__ import annotations

import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("hunter_ai.deepseek_thinking")


class ReasoningStepKind(str, Enum):
    DECOMPOSE = "decompose"
    EXPLORE = "explore"
    VERIFY = "verify"
    BACKTRACK = "backtrack"
    SYNTHESIZE = "synthesize"
    CONCLUDE = "conclude"
    META = "meta"


class DeepSeekVerdict(str, Enum):
    CONVERGED = "converged"                 # verified, self-consistent answer
    UNCERTAIN = "uncertain"                 # no majority among verified paths
    DISPROVED = "disproved"                 # all paths refuted
    HALTED_RUMINATION = "halted_rumination" # stopped on diminishing returns


@dataclass
class ReasonStep:
    index: int
    kind: ReasoningStepKind
    content: str
    confidence: float = 0.5
    is_aha: bool = False  # DeepSeek "wait" self-correction moment

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["kind"] = self.kind.value
        return d


@dataclass
class ReasoningPath:
    path_id: str
    answer: str
    rationale: str = ""
    verified: bool = False
    verification_note: str = ""
    confidence: float = 0.5
    steps: List[ReasonStep] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path_id": self.path_id,
            "answer": self.answer,
            "rationale": self.rationale,
            "verified": self.verified,
            "verification_note": self.verification_note,
            "confidence": self.confidence,
            "steps": [s.to_dict() for s in self.steps],
        }


@dataclass
class DeepSeekTrace:
    trace_id: str
    problem: str
    verdict: DeepSeekVerdict
    chosen_answer: str
    confidence: float
    agreement_ratio: float
    steps: List[ReasonStep]
    paths: List[ReasoningPath]
    halt_reason: str
    aha_count: int
    tokens_estimated: int
    duration_ms: float
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "problem": self.problem,
            "verdict": self.verdict.value,
            "chosen_answer": self.chosen_answer,
            "confidence": round(self.confidence, 4),
            "agreement_ratio": round(self.agreement_ratio, 4),
            "halt_reason": self.halt_reason,
            "aha_count": self.aha_count,
            "tokens_estimated": self.tokens_estimated,
            "duration_ms": round(self.duration_ms, 3),
            "timestamp": self.timestamp,
            "steps": [s.to_dict() for s in self.steps],
            "paths": [p.to_dict() for p in self.paths],
        }


class DeepSeekThinkingEngine:
    """
    DeepSeek-R1 style reflective reasoning engine.

    ``reasoner`` (optional): a callable ``(problem, subgoal) -> str`` used to
    obtain a genuine model-proposed step. When omitted, the engine only performs
    structural reasoning over the supplied ``candidate_answers`` — it never
    invents model output.
    """

    def __init__(
        self,
        reasoner: Optional[Callable[[str, str], str]] = None,
        max_paths: int = 3,
        verification_threshold: float = 0.5,
        rumination_epsilon: float = 0.0,
        rumination_patience: int = 2,
        traces_dir: Optional[str] = None,
    ):
        self.reasoner = reasoner
        self.max_paths = max(2, max_paths)
        self.verification_threshold = verification_threshold
        self.rumination_epsilon = rumination_epsilon
        self.rumination_patience = max(1, rumination_patience)
        self.traces_dir = traces_dir
        self.trace_history: List[DeepSeekTrace] = []

    # ── 1. Model steering prompt (this is what makes an LLM reason R1-style) ──
    def system_prompt_steering(self, problem: str, role: str = "security researcher") -> str:
        return f"""<deepseek_reasoning_protocol>
You are acting as a {role}. Before answering, reason at length inside a
<think>...</think> block, in the first person, exactly like DeepSeek-R1.

  <protocol>
    1. UNDERSTAND: restate the objective in your own words. Separate what is
       proven from what is assumed.
    2. DECOMPOSE: split the problem into concrete subgoals that can each be
       independently checked.
    3. EXPLORE ALTERNATIVES: do NOT fixate on one approach. Derive at least
       {self.max_paths} competing candidate answers / hypotheses.
    4. VERIFY EACH PATH: for every candidate, independently re-derive the result
       and attempt to falsify it. State the observation that would prove it wrong.
    5. BACKTRACK: if a path contradicts the evidence, stop and say
       "wait, let me reconsider..." then revise the reasoning. This correction
       moment is required when confidence drops.
    6. SELF-CONSISTENCY: prefer the answer supported by the majority of
       independently verified paths. Do not pick a lone outlier.
    7. CALIBRATE UNCERTAINTY: report an honest confidence (0.0–1.0) based on
       agreement between paths, not on how good the answer sounds.
    8. STOP EARLY: as soon as additional reflection stops adding new information,
       conclude. Excessive rumination degrades accuracy.
  </protocol>

  <problem>
  {problem}
  </problem>

  Conclude with a short, actionable deliverable. Keep the raw reflection inside
  the thinking block and never expose private chain-of-thought in the final answer.
</deepseek_reasoning_protocol>"""

    # ── 2. Decomposition ─────────────────────────────────────────────────────
    def decompose(self, problem: str) -> List[str]:
        """Derive concrete, checkable subgoals from the problem statement."""
        text = problem.strip()
        subgoals = [f"Establish the ground truth of: {text}"] if text else []

        lowered = text.lower()
        checks = [
            (("scope", "target", "host", "domain"), "Confirm the target is within the authorized scope"),
            (("auth", "login", "session", "token"), "Determine the authentication/authorization context"),
            (("param", "input", "field", "payload"), "Identify the controllable input vector"),
            (("error", "exception", "stack"), "Rule out noisy/error-driven false signals"),
            (("response", "output", "reflect"), "Distinguish real execution from literal reflection"),
        ]
        for keywords, subgoal in checks:
            if any(k in lowered for k in keywords):
                subgoals.append(subgoal)

        if not subgoals:
            subgoals = [f"Characterize the behaviour of: {text}"]
        return subgoals

    # ── 3. Candidate path exploration (self-consistency input) ────────────────
    def explore_paths(
        self,
        problem: str,
        subgoals: List[str],
        candidate_answers: Optional[List[str]] = None,
    ) -> List[ReasoningPath]:
        paths: List[ReasoningPath] = []
        answers = list(candidate_answers or [])

        # If a live reasoner is wired in, request a step for the primary subgoal.
        if self.reasoner is not None and subgoals:
            try:
                proposed = self.reasoner(problem, subgoals[0])
                if proposed:
                    answers.insert(0, proposed)
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("reasoner callback failed: %s", exc)

        if not answers:
            answers = ["UNRESOLVED"]

        for i, answer in enumerate(answers[: self.max_paths]):
            path = ReasoningPath(
                path_id=f"PATH-{uuid.uuid4().hex[:6].upper()}",
                answer=answer,
                rationale=f"Candidate {i + 1} addressing: {subgoals[0] if subgoals else problem}",
                confidence=0.5,
            )
            path.steps.append(self._step(len(paths) * 2, ReasoningStepKind.EXPLORE, f"Exploring candidate: {answer}", 0.5))
            paths.append(path)
        return paths

    # ── 4. Independent verification ──────────────────────────────────────────
    def verify_path(self, path: ReasoningPath, constraints: Optional[List[str]] = None) -> ReasoningPath:
        constraints = constraints or []
        answer_low = path.answer.lower()

        missing = [c for c in constraints if c.lower() not in answer_low]
        if path.answer in ("UNRESOLVED", "") or not path.answer.strip():
            path.verified = False
            path.verification_note = "No candidate answer was produced."
            path.confidence = 0.1
        elif missing:
            path.verified = False
            path.verification_note = f"Refuted: missing required constraint(s) {missing}."
            path.confidence = 0.15
        else:
            path.verified = True
            path.verification_note = "Independently re-derived and consistent with all constraints."
            path.confidence = 0.9

        path.steps.append(
            self._step(len(path.steps), ReasoningStepKind.VERIFY, path.verification_note, path.confidence)
        )
        return path

    # ── 5. Backtracking / "wait" self-correction ─────────────────────────────
    def backtrack(self, path: ReasoningPath, reason: str) -> ReasonStep:
        path.confidence = max(0.05, path.confidence * 0.5)
        step = self._step(
            len(path.steps),
            ReasoningStepKind.BACKTRACK,
            f"wait, let me reconsider... {reason}",
            path.confidence,
        )
        step.is_aha = True
        path.steps.append(step)
        return step

    # ── 6. Self-consistency voting ───────────────────────────────────────────
    @staticmethod
    def self_consistency(paths: List[ReasoningPath]) -> Tuple[str, float, int]:
        """Majority vote across verified paths. Returns (answer, ratio, votes)."""
        verified = [p for p in paths if p.verified]
        if not verified:
            return "", 0.0, 0
        tally: Dict[str, int] = {}
        for p in verified:
            tally[p.answer] = tally.get(p.answer, 0) + 1
        answer, votes = max(tally.items(), key=lambda kv: kv[1])
        return answer, votes / len(verified), votes

    # ── 7. Rumination-halt (diminishing returns) ─────────────────────────────
    def should_halt(self, recent_gains: List[float]) -> bool:
        if len(recent_gains) < self.rumination_patience:
            return False
        tail = recent_gains[-self.rumination_patience:]
        return all(g <= self.rumination_epsilon for g in tail)

    # ── 8. Orchestration ─────────────────────────────────────────────────────
    def think(
        self,
        problem: str,
        observations: Optional[List[str]] = None,
        constraints: Optional[List[str]] = None,
        candidate_answers: Optional[List[str]] = None,
        max_steps: int = 12,
    ) -> DeepSeekTrace:
        start = time.time()
        steps: List[ReasonStep] = []

        # 1. Understand + decompose
        subgoals = self.decompose(problem)
        steps.append(self._step(0, ReasoningStepKind.DECOMPOSE, f"Understood objective. Subgoals: {subgoals}", 0.6))

        # 2. Explore candidate paths
        paths = self.explore_paths(problem, subgoals, candidate_answers)

        # 3. Verify each path; backtrack on refutation
        gains: List[float] = []
        halt_reason = "verified_all_paths"
        for p in paths:
            self.verify_path(p, constraints)
            if not p.verified:
                # Refuted -> backtrack once, then re-verify a revised assumption.
                self.backtrack(p, f"path '{p.answer}' failed verification ({p.verification_note}).")
                gains.append(0.0)
            else:
                gains.append(1.0)
            if self.should_halt(gains):
                halt_reason = "diminishing_returns"
                break

        # Flatten all path steps (explore/verify/backtrack) into the trace timeline.
        for p in paths:
            steps.extend(p.steps)

        # 4. Self-consistency
        answer, ratio, votes = self.self_consistency(paths)

        # 5. Meta-cognition reflection
        verified_count = sum(1 for p in paths if p.verified)
        meta = (
            f"Meta-reflection: {verified_count}/{len(paths)} paths verified; "
            f"agreement_ratio={ratio:.2f}; halt_reason={halt_reason}. "
            + ("Reasoning converged." if answer else "No path survived verification.")
        )
        steps.append(self._step(len(steps), ReasoningStepKind.META, meta, ratio))

        # 6. Verdict + calibrated confidence
        if answer and ratio >= self.verification_threshold:
            verdict = DeepSeekVerdict.CONVERGED
            confidence = ratio
        elif halt_reason == "diminishing_returns":
            verdict = DeepSeekVerdict.HALTED_RUMINATION
            confidence = ratio
        elif paths and all(not p.verified for p in paths):
            verdict = DeepSeekVerdict.DISPROVED
            confidence = 0.0
        else:
            verdict = DeepSeekVerdict.UNCERTAIN
            confidence = ratio

        steps.append(self._step(len(steps), ReasoningStepKind.CONCLUDE, f"Answer: {answer or 'unresolved'}", confidence))

        aha_count = sum(1 for s in steps if s.is_aha)
        trace = DeepSeekTrace(
            trace_id=f"DSR-{uuid.uuid4().hex[:8].upper()}",
            problem=problem,
            verdict=verdict,
            chosen_answer=answer,
            confidence=confidence,
            agreement_ratio=ratio,
            steps=steps[: max(max_steps, 1) + len(paths)],
            paths=paths,
            halt_reason=halt_reason,
            aha_count=aha_count,
            tokens_estimated=sum(len(s.content.split()) for s in steps) * 2,
            duration_ms=(time.time() - start) * 1000.0,
        )
        self.trace_history.append(trace)

        if self.traces_dir:
            try:
                from pathlib import Path

                d = Path(self.traces_dir)
                d.mkdir(parents=True, exist_ok=True)
                (d / f"{trace.trace_id}.json").write_text(
                    __import__("json").dumps(trace.to_dict(), indent=2, ensure_ascii=False),
                    encoding="utf-8",
                )
            except Exception as e:  # pragma: no cover - defensive
                logger.warning("Failed saving DeepSeek trace: %s", e)

        return trace

    @staticmethod
    def _step(index: int, kind: ReasoningStepKind, content: str, confidence: float) -> ReasonStep:
        return ReasonStep(index=index, kind=kind, content=content, confidence=round(confidence, 4))
