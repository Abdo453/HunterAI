"""
Autonomous Loop — الحلقة الذاتية المستقلة
==========================================
تنفّذ حلقة hunters المستقلة:
  plan → tool → validate → chain → report → remember
تستخدم SkillRegistry لاستدعاء المهارات بالاسم، وتُطبّق بوابة التحقق السباعية قبل أي تقرير.
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, List

from skills.base_skill import BaseSkill, SkillContext, SkillResult
from skills.agent_core.skill_registry import SKILL_REGISTRY


class AutonomousLoopSkill(BaseSkill):
    name = "autonomous_loop"
    category = "agent_core"
    description = "حلقة استكشاف مستقلة: التخطيط -> الأداة -> التحقق -> السلسلة -> التقرير -> الذاكرة"
    tools_required: List[str] = []
    fallback_tools: List[str] = []
    timeout_seconds = 300.0
    max_retries = 1

    # التسلسل الافتراضي للمهام (يمكن تخصيصه عبر ctx.extra["phases"])
    DEFAULT_PHASES: List[str] = [
        "recon",
        "scan",
        "analyze",
        "exploit",
        "validate",
        "report",
    ]

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=True, tool_used=self.name)
        target = ctx.target
        phases: List[str] = ctx.extra.get("phases", self.DEFAULT_PHASES)
        max_risk = ctx.extra.get("max_risk", "medium")
        scope_ok = bool(ctx.extra.get("scope_authorized", True))

        trace: List[Dict[str, Any]] = []
        findings: List[Dict[str, Any]] = []

        for phase in phases:
            t0 = time.time()
            step = {"phase": phase, "started_at": t0, "skill": None, "tool": None, "ok": False, "note": ""}

            try:
                if phase == "recon":
                    skill_res = await SKILL_REGISTRY.run("attack_surface_ranker", ctx)
                    step["skill"] = "attack_surface_ranker"
                    findings.extend(skill_res.findings)

                elif phase == "scan":
                    skill_res = await SKILL_REGISTRY.run("agent_tool_planner", ctx)
                    step["skill"] = "agent_tool_planner"
                    plan = json.loads(skill_res.raw_output["tool_plan"]) if skill_res.raw_output.get("tool_plan") else {}
                    step["tool"] = (plan.get("next_tool") or {}).get("tool")

                elif phase == "analyze":
                    # تشغيل مهارات التحليل المتوفرة بناءً على الإشارات
                    for sname in ("ssrf_hunter", "idor_tester", "logic_flaw_hunter", "takeover_confirm", "secrets_hunter"):
                        try:
                            s_res = await SKILL_REGISTRY.run(sname, ctx)
                            findings.extend(s_res.findings)
                            if s_res.has_findings:
                                step["note"] = step.get("note", "") + f"{sname}: {len(s_res.findings)} findings; "
                        except Exception as exc:
                            step["note"] += f"{sname} skipped: {exc}; "
                    step["skill"] = "multi_analyze"

                elif phase == "exploit":
                    # بناء سلاسل من النتائج المؤكدة
                    cb_res = await SKILL_REGISTRY.run("agent_chain_builder", ctx)
                    findings.extend(cb_res.findings)
                    step["skill"] = "agent_chain_builder"

                elif phase == "validate":
                    # بوابة التحقق السباعية (مدمجة في hunter_ai)
                    try:
                        from hunter_ai.validation_gate import validate_finding
                        validated = []
                        for f in findings:
                            vr = validate_finding(f)
                            if vr.get("status") == "PROVEN":
                                validated.append(vr)
                        findings = validated
                        step["note"] = f"{len(validated)} findings PROVEN by gate"
                    except Exception as exc:
                        step["note"] = f"gate skipped: {exc}"
                    step["skill"] = "validation_gate"

                elif phase == "report":
                    try:
                        rep = await SKILL_REGISTRY.run("report_generator", ctx)
                        findings.extend(rep.findings)
                        step["skill"] = "report_generator"
                    except Exception as exc:
                        step["note"] = f"report skipped: {exc}"

                step["ok"] = True
                step["duration"] = round(time.time() - t0, 2)

            except Exception as exc:
                step["ok"] = False
                step["note"] = f"error: {exc}"
                step["duration"] = round(time.time() - t0, 2)
                self.logger.warning(f"[AutonomousLoop] phase {phase} failed: {exc}")

            trace.append(step)

        # تسجيل في ذاكرة الصيد
        try:
            mem_ctx = ctx
            mem_ctx.extra = {"action": "remember", "note": f"Autonomous hunt on {target}: {len(findings)} proven findings"}
            await SKILL_REGISTRY.run("hunt_memory", mem_ctx)
        except Exception:
            pass

        payload = {
            "target": target,
            "phases": phases,
            "max_risk": max_risk,
            "scope_authorized": scope_ok,
            "trace": trace,
            "proven_findings": findings,
            "generated_at": time.time(),
        }

        p_out = ctx.workspace.write_file(target, "agent_core", "autonomous_hunt.json", json.dumps(payload, indent=2, ensure_ascii=False), ctx.session_id)
        result.output_files = {"autonomous_hunt.json": str(p_out)}
        result.raw_output = {"hunt": json.dumps(payload, ensure_ascii=False)}
        result.findings = findings
        result.next_skills = ["report_generator"]

        self.logger.info(f"[AutonomousLoop] {target}: phases={len(phases)} proven={len(findings)}")
        return result


if __name__ == "__main__":
    import asyncio

    class FakeWS:
        def get_workspace_path(self, t, s):
            from pathlib import Path
            return Path(f"/tmp/ws/{t}/{s}")
        def write_file(self, *a, **k):
            from pathlib import Path
            return Path("/tmp/x")
        def append_log(self, *a, **k):
            pass

    class FakeTM:
        def is_available(self, c):
            return True

    class FakeCtx:
        target = "example.com"
        extra = {"phases": ["recon", "analyze", "validate"], "max_risk": "medium", "scope_authorized": True}
        retry_attempt = 0
        tool_manager = FakeTM()
        workspace = FakeWS()
        session_id = "s1"

    async def main():
        skill = AutonomousLoopSkill()
        res = await skill.run(FakeCtx())
        print(json.dumps(res.raw_output["hunt"])[:500])

    asyncio.run(main())
