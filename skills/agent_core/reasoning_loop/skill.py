"""
Reasoning Loop Skill — مهارة "حلقة التفكير" للوكيل
====================================================
هذه المهارة تجيب عن سؤال: "كيف يفكر الوكيل؟"

تطبق نمط ReAct (Reason + Act):
  Observe (رصد الحالة الحالية)  →  Think (اتخاذ قرار ماذا بعد)  →  Act (تنفيذ/تخطيط الأداة)  →  Reflect (تقييم الثقة)

لا تعتمد على أي أداة خارجية إلزاميًا؛ تعمل دون اتصال، وتستخدم نموذج LLM إن توفر عبر ctx.extra["llm"]
لإثراء التفكير، مع الاحتفاظ بتعقب (trace) كامل لكل قرار لاستعراضه لاحقًا.

مخرجات:
  - thinking_trace.json : سجل كل خطوة تفكير مع المبرر والثقة
  - next_action.json    : القرار التالي (أداة/مهارة، مع 이유를 والبدائل)
  - قرار finding إن وُجدت مؤشر على ثغرة تستحق المتابعة
"""
from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, List, Optional

from skills.base_skill import BaseSkill, SkillContext, SkillResult


class ReasoningLoopSkill(BaseSkill):
    name = "agent_reasoning_loop"
    category = "agent_core"
    description = "ReAct thinking loop: observe → think → act → reflect. Decides the next tool/skill to run."
    tools_required: List[str] = []
    fallback_tools: List[str] = []
    timeout_seconds = 60.0
    max_retries = 1

    # أنماط سريعة تشير إلى وجود هدف يستحق التحري العميق (بدون LLM)
    INTERESTING_PATTERNS = [
        r"id=", r"uid=", r"user_id=", r"account=", r"order=", r"invoice=",
        r"url=", r"callback=", r"webhook=", r"return=", r"next=", r"redirect=",
        r"price=", r"amount=", r"total=", r"coupon=", r"discount=",
        r"\.git/", r"\.env", r"config", r"admin", r"swagger", r"\.json$",
    ]

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=True, tool_used=self.name)
        target = ctx.target
        phase = ctx.extra.get("phase", "recon")
        findings_so_far: List[Dict[str, Any]] = ctx.extra.get("findings_so_far", []) or []
        goal = ctx.extra.get("goal", "Discover and validate security findings")

        trace: List[Dict[str, Any]] = []
        t0 = time.time()

        # ── 1. Observe ──────────────────────────────────────────────────────
        obs = self._observe(target, phase, findings_so_far, ctx)
        trace.append({"step": 1, "phase": "observe", "data": obs, "timestamp": time.time() - t0})
        self.logger.info(f"[Observe] {obs['summary']}")

        # ── 2. Think ────────────────────────────────────────────────────────
        decision = await self._think(goal, phase, obs, findings_so_far, ctx)
        trace.append({"step": 2, "phase": "think", "data": decision, "timestamp": time.time() - t0})
        self.logger.info(f"[Think] {decision['reasoning']} (confidence={decision['confidence']:.2f})")

        # ── 3. Act (plan the concrete action) ───────────────────────────────
        action = self._act(decision, obs, ctx)
        trace.append({"step": 3, "phase": "act", "data": action, "timestamp": time.time() - t0})
        self.logger.info(f"[Act] {action['tool']} → {action['reason']}")

        # ── 4. Reflect ──────────────────────────────────────────────────────
        reflection = self._reflect(action, decision, obs)
        trace.append({"step": 4, "phase": "reflect", "data": reflection, "timestamp": time.time() - t0})

        # Write trace + next action
        p_trace = ctx.workspace.write_file(target, "agent_core", "thinking_trace.json", json.dumps(trace, indent=2, ensure_ascii=False), ctx.session_id)
        p_action = ctx.workspace.write_file(target, "agent_core", "next_action.json", json.dumps(action, indent=2, ensure_ascii=False), ctx.session_id)
        result.output_files = {
            "thinking_trace.json": str(p_trace),
            "next_action.json": str(p_action),
        }

        # If the loop decided there's a finding worth chasing, record it
        if action.get("suggested_finding"):
            result.add_finding(
                title=action["suggested_finding"]["title"],
                evidence=action["suggested_finding"]["evidence"],
                severity=action["suggested_finding"].get("severity", "Medium"),
                vuln_type=action["suggested_finding"].get("type", "logic"),
                recommendation=action["suggested_finding"].get("recommendation", ""),
                url=action["suggested_finding"].get("url", ""),
            )

        result.next_skills = action.get("next_skills", [])
        result.raw_output = {
            "thinking_trace": json.dumps(trace, ensure_ascii=False),
            "next_action": json.dumps(action, ensure_ascii=False),
        }
        return result

    # ── Internal reasoning steps ────────────────────────────────────────────

    def _observe(self, target: str, phase: str, findings: List[Dict], ctx: SkillContext) -> Dict[str, Any]:
        available_tools = []
        try:
            # ToolManager may expose list; fall back gracefully
            for t in ("subfinder", "httpx", "nmap", "nuclei", "katana", "arjun", "ffuf", "sqlmap",
                      "dalfox", "subjack", "gitleaks", "trufflehog", "browser"):
                if ctx.tool_manager.is_available(t):
                    available_tools.append(t)
        except Exception:
            pass

        interesting_signals = []
        for f in findings:
            text = json.dumps(f, ensure_ascii=False)
            for pat in self.INTERESTING_PATTERNS:
                if re.search(pat, text, re.I):
                    interesting_signals.append(pat)
                    break

        return {
            "target": target,
            "phase": phase,
            "available_tools": available_tools,
            "findings_count": len(findings),
            "interesting_signals": sorted(set(interesting_signals))[:10],
            "retry_attempt": ctx.retry_attempt,
            "summary": f"Phase={phase}, tools={len(available_tools)}, findings={len(findings)}, signals={len(interesting_signals)}",
        }

    async def _think(self, goal: str, phase: str, obs: Dict, findings: List[Dict], ctx: SkillContext) -> Dict[str, Any]:
        """
        décide what to do next. Heuristic-based, enriched by LLM if provided.
        """
        reasoning_parts: List[str] = []
        confidence = 0.3
        next_tool = None
        next_skill = None

        signals = obs["interesting_signals"]
        tools = obs["available_tools"]

        # Priority rules (worst-impact first, per AGENTS.md rule #7)
        if any(s in signals for s in (r"url=", r"callback=", r"webhook=", r"return=", r"redirect=")):
            if "katana" in tools or "arjun" in tools:
                next_tool = "katana"
                next_skill = "agent_reasoning_loop"
                reasoning_parts.append("SSRF/redirect parameters detected → crawl endpoints with katana/arjun")
                confidence = 0.8
        if any(s in signals for s in (r"id=", r"uid=", r"user_id=", r"account=", r"order=", r"invoice=")):
            if "ffuf" in tools:
                next_tool = "ffuf"
                next_skill = "idor_tester"
                reasoning_parts.append("Sequential ID parameters detected → IDOR test")
                confidence = max(confidence, 0.75)
        if any(s in signals for s in (r"price=", r"amount=", r"total=", r"coupon=", r"discount=")):
            next_skill = "logic_flaw_hunter"
            reasoning_parts.append("Financial/logic parameters detected → business-logic tests")
            confidence = max(confidence, 0.7)
        if any(s in signals for s in (r"\.git/", r"\.env", r"config", r"\.json$")):
            if "gitleaks" in tools or "trufflehog" in tools:
                next_tool = "gitleaks"
                next_skill = "agent_reasoning_loop"
                reasoning_parts.append("Sensitive files/config detected → secret scan")
                confidence = max(confidence, 0.65)
        if any(s in signals for s in (r"admin", r"swagger")):
            if "katana" in tools:
                next_tool = "katana"
                reasoning_parts.append("Admin/swagger surface detected → endpoint crawling")
                confidence = max(confidence, 0.6)

        if phase == "recon" and not next_tool:
            if "subfinder" in tools:
                next_tool = "subfinder"
                reasoning_parts.append("Early recon phase → start with passive subdomain enum")
                confidence = 0.55
            elif "httpx" in tools:
                next_tool = "httpx"
                reasoning_parts.append("Recon phase → probe live hosts")
                confidence = 0.5

        if not next_tool and not next_skill:
            next_skill = "attack_surface_ranker"
            reasoning_parts.append("No specific signal → rank the collected attack surface")
            confidence = 0.4

        # Optional LLM enrichment
        llm = ctx.extra.get("llm")
        if llm:
            try:
                prompt = (
                    f"You are a senior bug-bounty agent. Target={obs['target']} Phase={obs['phase']}. "
                    f"Signals={signals}. Tools available={tools}. Goal={goal}. "
                    f"Pick the NEXT single action (tool or skill) and explain why, one sentence. "
                    f"Reply in JSON: {{\"tool\": ..., \"skill\": ..., \"reasoning\": ..., \"confidence\": 0.0-1.0}}"
                )
                llm_answer = await llm.execute_prompt(prompt) if hasattr(llm, "execute_prompt") else str(llm)
                reasoning_parts.append(f"LLM-enriched: {llm_answer[:200]}")
                confidence = min(confidence + 0.1, 0.95)
            except Exception as exc:
                self.logger.warning(f"LLM enrichment skipped: {exc}")

        return {
            "goal": goal,
            "phase": phase,
            "reasoning": " | ".join(reasoning_parts),
            "confidence": round(confidence, 2),
            "next_tool": next_tool,
            "next_skill": next_skill,
        }

    def _act(self, decision: Dict, obs: Dict, ctx: SkillContext) -> Dict[str, Any]:
        """Transform the thinking decision into a concrete action plan."""
        action = {
            "tool": decision.get("next_tool"),
            "skill": decision.get("next_skill"),
            "reason": decision["reasoning"],
            "confidence": decision["confidence"],
            "next_skills": [],
            "suggested_finding": None,
        }

        tool = decision.get("next_tool")
        if tool:
            action["next_skills"].append("agent_reasoning_loop")  # loop again after tool
            # Map common tools to follow-up skills
            follow_up = {
                "subfinder": ["live_host_detection", "dns_enum"],
                "httpx": ["tech_detection", "waf_detection"],
                "katana": ["arjun", "idor_tester", "ssrf_hunter"],
                "arjun": ["idor_tester", "ssrf_hunter"],
                "ffuf": ["idor_tester"],
                "nuclei": ["agent_reasoning_loop"],
                "gitleaks": ["report_generator"],
                "subjack": ["takeover_confirm"],
            }
            action["next_skills"].extend(follow_up.get(tool, []))

        # If confidence is high and we have a concrete vector, suggest a finding placeholder
        if decision["confidence"] >= 0.7 and decision.get("next_tool"):
            action["suggested_finding"] = {
                "title": f"Potential vector: {decision['next_tool']} on {obs['target']}",
                "evidence": decision["reasoning"],
                "severity": "Medium",
                "type": "recon_vector",
                "recommendation": "Run the selected tool then apply the 7-Question Gate before reporting.",
                "url": obs["target"],
            }

        return action

    def _reflect(self, action: Dict, decision: Dict, obs: Dict) -> Dict[str, Any]:
        """Self-critique: is this action safe and worth doing?"""
        risks = []
        if action["tool"] in ("sqlmap", "ffuf"):
            risks.append("Intrusive tool — ensure scope authorization first")
        if decision["confidence"] < 0.5:
            risks.append("Low confidence — prefer passive recon first")
        if not obs["available_tools"]:
            risks.append("No tools available — skill will degrade to passive HTTP checks")

        return {
            "verdict": "proceed" if not risks else "proceed_with_caution",
            "risks": risks,
            "confidence_after_action": round(min(decision["confidence"] + 0.05, 0.99), 2),
            "note": "Think → Act loop completed. Record trace and feed next_action to the orchestrator.",
        }


if __name__ == "__main__":
    import asyncio

    class FakeTM:
        def is_available(self, cmd):
            return cmd in ("subfinder", "httpx", "katana", "arjun")

    class FakeWS:
        def write_file(self, *a, **k):
            from pathlib import Path
            return Path("/tmp/x")

    class FakeCtx:
        target = "example.com"
        extra = {"phase": "recon", "findings_so_far": [{"title": "x", "evidence": "id=123"}, ], "goal": "find bugs"}
        retry_attempt = 0
        tool_manager = FakeTM()
        workspace = FakeWS()
        session_id = "s1"

    async def main():
        skill = ReasoningLoopSkill()
        res = await skill.run(FakeCtx())
        print(json.dumps(raw := res.raw_output, ensure_ascii=False, indent=2))

    asyncio.run(main())
