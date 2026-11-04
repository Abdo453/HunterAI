"""
MissionCritic — Metacognitive Self-Review Layer
===============================================
Closes the missing mission-level self-critique gap on top of the existing
per-tool (reflect_post_tool) and per-hypothesis (deliberate_strategy) layers:

- ``critique_phase()``  : after each engine phase, reviews whether the phase
  actually produced measurable progress. Emits concrete directives that the
  orchestrator feeds into the NEXT strategic deliberation, so the engine can
  adapt mid-mission instead of walking phases blindly.
- ``retrospective()``   : end-of-mission lesson writer. Emits lessons and a
  next-run checklist injected into the final result metadata (and usable by
  structured memory / failure-episodic recall in future runs).

Design constraints:
- Deterministic heuristics ONLY (no LLM dependency) so the critic can never
  block or slow the autonomous loop. The LLM reasoning layer remains in
  ``core.cognitive.cognitive_deliberator.CognitiveDeliberator``.
- Fail-soft: exceptions inside the critic never abort the mission.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

__all__ = [
    "PhaseCritique",
    "MissionRetrospective",
    "MissionCritic",
    "format_phase_trace",
    "format_retrospective_trace",
]


@dataclass
class PhaseCritique:
    """Self-review verdict for one executed engine phase."""
    phase: str
    verdict: str                    # PROGRESS | LIMITED_PROGRESS | STALLED
    score: float                    # 0.0-1.0 measured progress estimate
    gaps: List[str] = field(default_factory=list)
    directives: List[str] = field(default_factory=list)
    wasted_effort: List[str] = field(default_factory=list)
    blocked_hypotheses: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "phase": self.phase,
            "verdict": self.verdict,
            "score": round(self.score, 3),
            "gaps": list(self.gaps),
            "directives": list(self.directives),
            "wasted_effort": list(self.wasted_effort),
            "blocked_hypotheses": list(self.blocked_hypotheses),
        }


@dataclass
class MissionRetrospective:
    """End-of-mission retrospective across all executed phases."""
    target: str
    strengths: List[str] = field(default_factory=list)
    weaknesses: List[str] = field(default_factory=list)
    lessons: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    next_run_checklist: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "strengths": list(self.strengths),
            "weaknesses": list(self.weaknesses),
            "lessons": list(self.lessons),
            "recommendations": list(self.recommendations),
            "next_run_checklist": list(self.next_run_checklist),
        }


class MissionCritic:
    """
    Deterministic metacognition over the mission transcript.

    Instantiated once per OmniHunterEngine; called after every phase and once
    at mission end. Reviews the ENGINE's own behavior (plan rationality,
    effort allocation, untested surface) — explicitly NOT the findings
    themselves (findings already have the EvidenceCourt adversarial skeptic).
    """

    DEEP_PHASES = {"WEB", "API", "JAVASCRIPT", "VERIFICATION"}

    # ──────────────────────────────────────────────────────────────────────
    def critique_phase(
        self,
        phase: str,
        surface: Dict[str, Any],
        findings: List[Dict[str, Any]],
        task_stats: Optional[Dict[str, int]] = None,
        prior_directives: Optional[List[str]] = None,
    ) -> PhaseCritique:
        """Self-review of a just-executed phase. Never raises."""
        stats = task_stats or {}
        surface = surface or {}
        findings = findings or []
        prior = prior_directives or []

        crt = PhaseCritique(phase=phase, verdict="LIMITED_PROGRESS", score=0.5)
        total = stats.get("done", 0) + stats.get("failed", 0)
        fail_ratio = (stats.get("failed", 0) / total) if total else 0.0

        live = len(surface.get("live_hosts", []) or [])
        endpoints = len(surface.get("endpoints", []) or [])
        apis = len(surface.get("apis", []) or [])
        js = len(surface.get("js_files", []) or [])
        waf = surface.get("waf_name")

        # --- Verdict & score -------------------------------------------------
        progress_signals = 0
        if live > 0:
            progress_signals += 1
        if endpoints + apis + js > 0:
            progress_signals += 1
        if findings:
            progress_signals += 2
        if total and fail_ratio < 0.3:
            progress_signals += 1

        crt.score = min(1.0, progress_signals / 5.0)
        if crt.score >= 0.6:
            crt.verdict = "PROGRESS"
        elif total and fail_ratio > 0.6:
            crt.verdict = "STALLED"
        else:
            crt.verdict = "LIMITED_PROGRESS"

        # --- Phase-specific gaps ---------------------------------------------
        if phase == "RECON":
            if live == 0:
                crt.gaps.append(
                    "RECON produced no live hosts — check DNS resolution, "
                    "probing rate limits, and CDN-fronting before proceeding."
                )
            if endpoints + apis == 0:
                crt.gaps.append("No endpoints or APIs discovered yet — crawlers/URL sources may be blocked by WAF/robots.")
        elif phase in ("NETWORK",):
            if not surface.get("open_ports"):
                crt.gaps.append("No open ports enumerated — firewall/blocked ICMP may mask services; try protocol-specific probes.")
        elif phase in ("WEB", "API"):
            if endpoints + apis > 0 and not findings:
                crt.gaps.append(
                    f"{phase}: {endpoints + apis} surfaces enumerated but zero findings — "
                    "breadth exhausted; switch to depth (authorization, parameter tampering, business logic)."
                )
            if waf:
                crt.blocked_hypotheses.append(f"WAF '{waf}' may be absorbing probes — recommend WAF bypass ladder before repeating payload variants.")
        elif phase in ("JAVASCRIPT",):
            if js == 0:
                crt.gaps.append("No JS files harvested — modern SPA endpoints remain invisible; retry with browser-driven discovery.")
        elif phase == "VERIFICATION":
            if not findings:
                crt.gaps.append("Verification phase ran with no pending findings — nothing to adjudicate; earlier phases likely under-probed.")
        elif phase == "ADJUDICATION":
            crt.gaps.append("Adjudicated at current evidence level — untested court lines will not be revisited this run.")

        # --- Effort accounting ------------------------------------------------
        if total and fail_ratio > 0.6:
            crt.wasted_effort.append(
                f"{stats.get('failed', 0)}/{total} tasks failed — likely missing prerequisites "
                "(tool absent, auth context, or WAF); fix prerequisites before re-queuing variants."
            )
        for d in prior:
            if d in crt.gaps:
                crt.wasted_effort.append(
                    f"Directive repeated unchanged from prior phase: '{d}' — escalate or change approach."
                )

        # --- Directives for the NEXT deliberation ------------------------------
        crt.directives = self._directives_for(crt, phase, surface, findings, fail_ratio)
        return crt

    def _directives_for(
        self,
        crt: PhaseCritique,
        phase: str,
        surface: Dict[str, Any],
        findings: List[Dict[str, Any]],
        fail_ratio: float,
    ) -> List[str]:
        ds: List[str] = []
        waf = surface.get("waf_name")
        if crt.verdict == "STALLED":
            ds.append("CHANGE APPROACH: current phase strategy is failing; switch vector class entirely.")
        if fail_ratio > 0.6:
            ds.append("Diagnose task failure root cause (tool availability / auth / WAF) before re-queueing variants.")
        if waf and not findings:
            ds.append(f"Route payloads through WAF bypass ladder / padding skills (detected: {waf}).")
        if phase in self.DEEP_PHASES and not findings and (len(surface.get("endpoints", []) or []) > 10):
            ds.append("Prioritize authorization tests (IDOR/BOLA using identity matrix) over more endpoint discovery.")
        if not surface.get("js_files") and phase in ("WEB", "API"):
            ds.append("Harvest JS bundles for hidden routes, secrets, and unlinked endpoints.")
        if findings:
            ds.append("Feed confirmed findings into chain-builder: attempt A->B->C escalation before REPORT.")
        if crt.score >= 0.8:
            ds.append("Phase efficient: replicate this strategy verbatim on the next high-value asset.")
        return ds[:4]

    # ──────────────────────────────────────────────────────────────────────
    def retrospective(
        self,
        target: str,
        surface: Dict[str, Any],
        findings: List[Dict[str, Any]],
        critiques: List[PhaseCritique],
        coverage_pct: float = 0.0,
        duration_secs: float = 0.0,
        failed_tasks: int = 0,
        completed_tasks: int = 0,
    ) -> MissionRetrospective:
        """Whole-mission lesson writer. Never raises."""
        surface = surface or {}
        findings = findings or []
        critiques = critiques or []
        ret = MissionRetrospective(target=target)

        for c in critiques:
            if c.verdict == "PROGRESS":
                ret.strengths.append(f"{c.phase}: measurable progress (score {c.score:.2f}).")
            elif c.verdict == "STALLED":
                ret.weaknesses.append(f"{c.phase}: stalled (score {c.score:.2f}) — {c.wasted_effort[0] if c.wasted_effort else 'no move/attempt'}.")

        # Lessons (deterministic, feed structured memory next run)
        if not findings and coverage_pct < 50:
            ret.lessons.append(
                "No findings despite low coverage: surface mapping itself failed — "
                "next run: validate DNS/proxy transport BEFORE deep phases."
            )
        if findings and not surface.get("apis") :
            ret.lessons.append(
                "Findings confirmed with zero API surfaces enumerated: API-layer "
                "recon is the weaker pillar for this target profile."
            )
        if failed_tasks and completed_tasks and failed_tasks / max(1, completed_tasks) > 0.5:
            ret.lessons.append(
                "Task failure ratio >0.5: environment prerequisites (tools/auth/egress) "
                "were the bottleneck, not strategy."
            )
        for c in critiques:
            if c.verdict == "STALLED":
                for d in c.directives:
                    ret.lessons.append(f"Lesson [{c.phase}]: {d}")

        # Recommendations & checklist
        if surface.get("waf_name"):
            ret.recommendations.append(f"Next run: pre-arm WAF gene bank for '{surface['waf_name']}' before payload dispatch (waf-rl-train).")
        if coverage_pct < 85:
            ret.recommendations.append(f"Coverage {coverage_pct:.1f}% below 85% target: re-run with --max-cycles raised and identity contexts supplied.")
        ret.recommendations.append("Persist retrospective lessons into structured memory so pipeline recall skips proven-dead techniques.")
        ret.next_run_checklist = [
            f"Review weaknesses: {len(ret.weaknesses)} stalled phases",
            "Include both identity contexts (user A/B) for authorization testing",
            "Verify engagement scope grant validity window",
        ]
        return ret


def format_phase_trace(critique: PhaseCritique) -> str:
    """Human-readable phase self-review trace (mirrors deliberator traces)."""
    lines = [
        "",
        f"  ══ [MISSION-CRITIC] self-review of phase {critique.phase} ══",
        f"  verdict: {critique.verdict}  (score {critique.score:.2f})",
    ]
    if critique.gaps:
        lines.append("  gaps:")
        for g in critique.gaps:
            lines.append(f"    - {g}")
    if critique.blocked_hypotheses:
        lines.append("  blocked hypotheses:")
        for b in critique.blocked_hypotheses:
            lines.append(f"    - {b}")
    if critique.wasted_effort:
        lines.append("  wasted effort detected:")
        for w in critique.wasted_effort:
            lines.append(f"    - {w}")
    if critique.directives:
        lines.append("  directives pushed to next deliberation:")
        for d in critique.directives:
            lines.append(f"    -> {d}")
    lines.append("  " + "=" * 58)
    return "\n".join(lines)


def format_retrospective_trace(retro: MissionRetrospective) -> str:
    lines = [
        "",
        "  ══ [MISSION-CRITIC] end-of-mission retrospective ══",
    ]
    if retro.strengths:
        lines.append("  strengths:")
        lines += [f"    + {s}" for s in retro.strengths]
    if retro.weaknesses:
        lines.append("  weaknesses:")
        lines += [f"    - {w}" for w in retro.weaknesses]
    if retro.lessons:
        lines.append("  lessons for next runs:")
        lines += [f"    * {l}" for l in retro.lessons]
    if retro.recommendations:
        lines.append("  recommendations:")
        lines += [f"    >> {r}" for r in retro.recommendations]
    lines.append("  " + "=" * 58)
    return "\n".join(lines)
