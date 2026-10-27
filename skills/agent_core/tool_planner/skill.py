"""
Tool Planner Skill — مهارة "مخطط الأدوات"
=============================================
تجيب عن سؤال: "أداة nào تُستخدم، ومتى، وبأي ترتيب؟"

تقوم بـ:
  1. قراءة أدوات النظام المتاحة من ToolManager / ToolRouter.
  2. فلترة الأدوات حسب المرحلة (recon → scan → analyze → exploit → report).
  3. فلترة حسب مستوى المخاطرة (LOW passive أولًا، ثم MEDIUM، ثم HIGH فقط إن لزم).
  4. التحقق من الترخيص (scope) عبر StrictScopeEngine إن توفر.
  5. إنتاج خطة منظمة: أداة رئيسية + أداة احتياطية لكل خطوة، مع المبرر.

مخرجات:
  - tool_plan.json : الخطة الكاملة المرتبة
  - next_tool.json : الأداة التالية للتنفيذ الفوري
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

from skills.base_skill import BaseSkill, SkillContext, SkillResult


# خريطة المرحلة -> أولويات الأدوات (بصورة أولية، تُحدث من ToolRouter عند التوفر)
PHASE_TOOLS: Dict[str, List[Dict[str, Any]]] = {
    "recon": [
        {"tool": "subfinder",  "risk": "low",  "desc": "Passive subdomain enumeration"},
        {"tool": "amass",      "risk": "low",  "desc": "Active/passive subdomain discovery"},
        {"tool": "crt_sh",     "risk": "low",  "desc": "Certificate transparency search"},
        {"tool": "waybackurls","risk": "low",  "desc": "Historical URL extraction"},
        {"tool": "httpx",      "risk": "medium","desc": "Live host / HTTP probing"},
    ],
    "scan": [
        {"tool": "nmap",       "risk": "medium","desc": "Port and service scan"},
        {"tool": "naabu",      "risk": "medium","desc": "Fast port discovery"},
        {"tool": "nuclei",     "risk": "medium","desc": "Vulnerability template scan"},
        {"tool": "whatweb",    "risk": "low",  "desc": "Web technology fingerprinting"},
        {"tool": "wafw00f",    "risk": "low",  "desc": "WAF detection"},
    ],
    "analyze": [
        {"tool": "katana",     "risk": "low",  "desc": "Web crawling and endpoint discovery"},
        {"tool": "arjun",      "risk": "low",  "desc": "Hidden HTTP parameter discovery"},
        {"tool": "linkfinder", "risk": "low",  "desc": "JS endpoint extraction"},
        {"tool": "ffuf",       "risk": "medium","desc": "Content / parameter fuzzing"},
        {"tool": "trufflehog", "risk": "low",  "desc": "Secret scanning in responses/JS"},
        {"tool": "gitleaks",   "risk": "low",  "desc": "Secret scanning"},
    ],
    "exploit": [
        {"tool": "sqlmap",     "risk": "high", "desc": "Safe SQLi verification (differential/timing)"},
        {"tool": "dalfox",     "risk": "medium","desc": "XSS verification"},
        {"tool": "ffuf",       "risk": "medium","desc": "IDOR / ID enumeration fuzzing"},
    ],
    "report": [
        {"tool": "report",     "risk": "low",  "desc": "Generate submission-ready report"},
    ],
}

# بدائل للأدوات عند غياب الأساسية
FALLBACKS: Dict[str, List[str]] = {
    "subfinder": ["amass", "crt_sh", "waybackurls"],
    "amass": ["subfinder", "crt_sh"],
    "httpx": ["naabu"],
    "nmap": ["naabu", "masscan"],
    "nuclei": ["nmap"],
    "katana": ["gospider", "waybackurls"],
    "arjun": ["paramspider"],
    "ffuf": ["feroxbuster"],
    "sqlmap": [],  # no safe fallback for high-risk
    "dalfox": ["katana"],
    "subjack": ["subzy"],
}


class ToolPlannerSkill(BaseSkill):
    name = "agent_tool_planner"
    category = "agent_core"
    description = "Plans which tool to use per phase/risk/scope, with primary + fallback."
    tools_required: List[str] = []
    fallback_tools: List[str] = []
    timeout_seconds = 30.0
    max_retries = 1

    def __init__(self):
        super().__init__()
        self._router = None

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=True, tool_used=self.name)
        target = ctx.target
        phase = ctx.extra.get("phase", "recon")
        allowed_risk = ctx.extra.get("max_risk", "medium")  # low | medium | high
        scope_ok = bool(ctx.extra.get("scope_authorized", True))

        t0 = time.time()
        steps: List[Dict[str, Any]] = []
        next_tool: Optional[Dict[str, Any]] = None

        # Optional: integrate hunter_ai ToolRouter if available
        router_specs: Dict[str, Any] = {}
        try:
            from hunter_ai.tools.tool_router import ToolRouter
            self._router = ToolRouter()
            for spec in self._router.list_tools():
                router_specs[spec["name"]] = spec
        except Exception:
            self._router = None

        risk_order = {"low": 0, "medium": 1, "high": 2}
        max_risk_level = risk_order.get(allowed_risk, 1)

        phase_tools = PHASE_TOOLS.get(phase, PHASE_TOOLS["recon"])

        for entry in phase_tools:
            tool = entry["tool"]
            risk_level = risk_order.get(entry["risk"], 1)
            if risk_level > max_risk_level:
                continue  # skip high-risk tools if user limited risk

            # Availability check
            available = False
            try:
                available = ctx.tool_manager.is_available(tool)
            except Exception:
                available = False
            if not available and router_specs.get(tool):
                available = True  # known tool spec even if binary not installed

            # Scope gate
            in_scope = scope_ok
            if self._router and entry.get("risk") != "low":
                try:
                    from core.control_plane.policy_gate import ActionRequest, ActionCategory
                    from hunter_ai.core.scope_engine import StrictScopeEngine
                    engine = StrictScopeEngine()
                    in_scope = engine.is_allowed(target)
                except Exception:
                    pass

            fallback = []
            for fb in FALLBACKS.get(tool, []):
                try:
                    fb_avail = ctx.tool_manager.is_available(fb)
                except Exception:
                    fb_avail = bool(router_specs.get(fb))
                if fb_avail:
                    fallback.append(fb)

            steps.append({
                "tool": tool,
                "risk": entry["risk"],
                "phase": phase,
                "description": entry["desc"],
                "available": available,
                "in_scope": in_scope,
                "fallback_tools": fallback,
                "reason": self._step_reason(tool, entry, available, in_scope),
            })

            if not next_tool and available and in_scope:
                next_tool = steps[-1].copy()

        # If nothing available in this phase, degrade gracefully to passive recon
        if not next_tool:
            passive = [s for s in steps if s["risk"] == "low" and s["available"] and s["in_scope"]]
            if passive:
                next_tool = passive[0]
            else:
                next_tool = {
                    "tool": "passive_http",
                    "risk": "low",
                    "phase": phase,
                    "description": "Passive HTTP header/title probe (no binary required)",
                    "available": True,
                    "in_scope": scope_ok,
                    "fallback_tools": [],
                    "reason": "No scanner binaries available — fall back to passive HTTP checks.",
                }

        plan = {
            "target": target,
            "phase": phase,
            "max_risk": allowed_risk,
            "scope_authorized": scope_ok,
            "generated_at": time.time(),
            "steps": steps,
            "next_tool": next_tool,
            "total_steps": len(steps),
            "available_steps": sum(1 for s in steps if s["available"]),
        }

        p_plan = ctx.workspace.write_file(target, "agent_core", "tool_plan.json", json.dumps(plan, indent=2, ensure_ascii=False), ctx.session_id)
        p_next = ctx.workspace.write_file(target, "agent_core", "next_tool.json", json.dumps(next_tool, indent=2, ensure_ascii=False), ctx.session_id)
        result.output_files = {
            "tool_plan.json": str(p_plan),
            "next_tool.json": str(p_next),
        }
        result.raw_output = {
            "tool_plan": json.dumps(plan, ensure_ascii=False),
            "next_tool": json.dumps(next_tool, ensure_ascii=False),
        }
        result.next_skills = [s["tool"] for s in steps if s["available"] and s["in_scope"]][:5]
        duration = time.time() - t0
        self.logger.info(f"[ToolPlanner] phase={phase} steps={len(steps)} next={next_tool['tool']} in {duration:.1f}s")
        return result

    def _step_reason(self, tool: str, entry: Dict, available: bool, in_scope: bool) -> str:
        if not available:
            return f"Tool '{tool}' not installed — use fallback or skip."
        if not in_scope:
            return f"Tool '{tool}' available but target out of authorized scope."
        return f"Use '{tool}' for {entry['desc']} (risk={entry['risk']})."


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
        extra = {"phase": "recon", "max_risk": "medium", "scope_authorized": True}
        retry_attempt = 0
        tool_manager = FakeTM()
        workspace = FakeWS()
        session_id = "s1"

    async def main():
        skill = ToolPlannerSkill()
        res = await skill.run(FakeCtx())
        print(res.raw_output["next_tool"])

    asyncio.run(main())
