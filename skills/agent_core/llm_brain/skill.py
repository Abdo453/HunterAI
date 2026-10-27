"""
LLM Brain — مساعد النموذج اللغوي للوكيل
=========================================
يغني تفكير الوكيل بالنموذج اللغوي (إن توفر) مع العمل بدون اتصال كافتراضي.
يوفّر:
  - decide_next(target, phase, signals, tools) -> قرار JSON بأداة/مهارة مناسبة
  - enrich_reasoning(prompt) -> تفسير نصي للقرار
  - fallback إلى قواعد Heuristics إذا لم يتوفر نموذج
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

from skills.base_skill import BaseSkill, SkillContext, SkillResult


class LLMBrainSkill(BaseSkill):
    name = "agent_llm_brain"
    category = "agent_core"
    description = "يساعد الوكيل في اتخاذ القرارات باستخدام النموذج اللغوي مع قواعد احتياطية"
    tools_required: List[str] = []
    fallback_tools: List[str] = []
    timeout_seconds = 45.0
    max_retries = 1

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=True, tool_used=self.name)
        target = ctx.target
        phase = ctx.extra.get("phase", "recon")
        signals: List[str] = ctx.extra.get("signals", []) or []
        tools: List[str] = ctx.extra.get("tools", []) or []
        goal = ctx.extra.get("goal", "find security findings")

        decision: Dict[str, Any]
        llm = ctx.extra.get("llm")

        if llm:
            decision = await self._ask_llm(llm, target, phase, signals, tools, goal)
        else:
            decision = self._heuristic(phase, signals, tools)

        decision["source"] = "llm" if llm else "heuristic"
        decision["target"] = target
        decision["phase"] = phase
        decision["generated_at"] = time.time()

        p_out = ctx.workspace.write_file(target, "agent_core", "llm_decision.json", json.dumps(decision, indent=2, ensure_ascii=False), ctx.session_id)
        result.output_files = {"llm_decision.json": str(p_out)}
        result.raw_output = {"decision": json.dumps(decision, ensure_ascii=False)}

        if decision.get("suggested_finding"):
            result.add_finding(
                title=decision["suggested_finding"]["title"],
                evidence=decision["suggested_finding"]["evidence"],
                severity=decision["suggested_finding"].get("severity", "Medium"),
                vuln_type=decision["suggested_finding"].get("type", "logic"),
                recommendation=decision["suggested_finding"].get("recommendation", ""),
                url=decision["suggested_finding"].get("url", target),
            )
        result.next_skills = decision.get("next_skills", [])

        self.logger.info(f"[LLMBrain] phase={phase} source={decision['source']} tool={decision.get('tool')} skill={decision.get('skill')}")
        return result

    # ── heuristics (offline) ────────────────────────────────────────────

    def _heuristic(self, phase: str, signals: List[str], tools: List[str]) -> Dict[str, Any]:
        signal_text = " ".join(signals).lower()
        reasoning: List[str] = []
        confidence = 0.4
        next_tool = None
        next_skill = None
        next_skills: List[str] = []

        if any(k in signal_text for k in ("id=", "uid=", "user_id=", "order=", "invoice=")):
            next_skill = "idor_tester"
            reasoning.append("معرفات تسلسلية مكتشفة -> اختبار IDOR")
            confidence = 0.8
        if any(k in signal_text for k in ("url=", "callback=", "webhook=", "redirect=", "return=")):
            next_skill = "ssrf_hunter"
            next_tool = "katana" if "katana" in tools else None
            reasoning.append("معلمات URL خارجية -> اختبار SSRF")
            confidence = max(confidence, 0.75)
        if any(k in signal_text for k in ("price=", "amount=", "coupon=", "discount=")):
            next_skill = "logic_flaw_hunter"
            reasoning.append("معاملات مالية/حسابية -> اختبار منطق العمل")
            confidence = max(confidence, 0.7)
        if any(k in signal_text for k in (".git/", ".env", "config", ".json")):
            next_skill = "secrets_hunter"
            reasoning.append("ملفات حساسة/إعدادات -> البحث عن أسرار")
            confidence = max(confidence, 0.65)
        if any(k in signal_text for k in ("admin", "swagger", "graphql")):
            next_tool = "katana"
            reasoning.append("واجهة إدارية/대체 API -> زحف端点")
            confidence = max(confidence, 0.6)
        if phase == "recon" and not next_skill:
            next_tool = "subfinder"
            reasoning.append("مرحلة استطلاع أولية -> enumerate نطاقات فرعية")
            confidence = 0.55

        if not next_tool and not next_skill:
            next_skill = "attack_surface_ranker"
            reasoning.append("لا دليل محدد -> ترتيب سطح الهجوم")
            confidence = 0.4

        return {
            "tool": next_tool,
            "skill": next_skill,
            "next_skills": next_skills,
            "reasoning": " | ".join(reasoning),
            "confidence": round(confidence, 2),
        }

    # ── LLM enrichment ─────────────────────────────────────────────────

    async def _ask_llm(
        self,
        llm: Any,
        target: str,
        phase: str,
        signals: List[str],
        tools: List[str],
        goal: str,
    ) -> Dict[str, Any]:
        prompt = (
            f"أنت وكيل اختراق محترف. الهدف={target} المرحلة={phase}. "
            f"الإشارات={signals}. الأدوات المتاحة={tools}. الهدف={goal}. "
            f"اختر الأداة أو المهارة التالية التي يجب تشغيلها، واذكر السبب بجملة واحدة. "
            f"أجب بصيغة JSON فقط: {{\"tool\": ... أو null, \"skill\": ... أو null, \"reasoning\": ..., \"confidence\": 0-1, \"next_skills\": [...]}}"
        )
        try:
            if hasattr(llm, "execute_prompt"):
                raw = await llm.execute_prompt(prompt)
            elif hasattr(llm, "complete"):
                raw = await llm.complete(prompt)
            else:
                raw = str(llm)
            # استخراج JSON آمن
            start = raw.find("{")
            end = raw.rfind("}") + 1
            if start != -1 and end > start:
                return json.loads(raw[start:end])
        except Exception as exc:
            self.logger.warning(f"LLM answer parse failed, using heuristic: {exc}")
        return self._heuristic(phase, signals, tools)


if __name__ == "__main__":
    import asyncio

    class FakeWS:
        def write_file(self, *a, **k):
            from pathlib import Path
            return Path("/tmp/x")

    class FakeCtx:
        target = "example.com"
        extra = {"phase": "recon", "signals": ["id=5"], "tools": ["subfinder"], "goal": "find bugs"}
        retry_attempt = 0
        tool_manager = None
        workspace = FakeWS()
        session_id = "s1"

    async def main():
        skill = LLMBrainSkill()
        res = await skill.run(FakeCtx())
        print(res.raw_output["decision"][:300])

    asyncio.run(main())
