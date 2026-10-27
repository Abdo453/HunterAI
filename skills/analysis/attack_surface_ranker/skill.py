"""
Attack Surface Ranker Skill — مهارة "تقييم وترتيب سطح الهجوم"
================================================================
تجيب عن سؤال: "أي جزء من الهدف يستحق الاختبار أولًا؟"

تقوم بـ:
  1. قراءة نتائج الاستطلاع (subdomains, live hosts, tech, ports, waf).
  2.给 كل أصل نقطة بناءً على:
     - وجود ثغرات سابقة
     - موانع protection ضعيفة (بدون WAF، ports مفتوحة حساسة)
     - تقنية معروفة بثغرات (مثلاً Old PHP, WordPress, exposed /admin)
     - proximité للمنطق المالي أو الحسابات (id=, price=, login)
  3. إنتاج قائمة مرتبة (ranked list) للأهداف الأعلى أولوية.

مخرجات:
  - surface_ranking.json : الأهداف مرتبة تنازليًا بالنتيجة
"""
from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, List

from skills.base_skill import BaseSkill, SkillContext, SkillResult


class AttackSurfaceRankerSkill(BaseSkill):
    name = "attack_surface_ranker"
    category = "analysis"
    description = "Ranks discovered assets by exploitability and value."
    tools_required: List[str] = []
    fallback_tools: List[str] = []
    timeout_seconds = 40.0
    max_retries = 1

    HIGH_VALUE_PATHS = ["/admin", "/login", "/api/", "/graphql", "/swagger", "/.env", "/.git/", "/config"]
    HIGH_VALUE_TECH = ["wordpress", "php", "asp.net", "node.js", "ruby on rails", "django", "laravel"]
    SENSITIVE_PORTS = {8080: 3, 8443: 3, 3306: 5, 5432: 5, 6379: 5, 27017: 5, 9200: 4, 5984: 4}

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=True, tool_used=self.name)
        target = ctx.target

        # inputs from previous skills (optional)
        subdomains: List[str] = ctx.extra.get("subdomains", []) or []
        live_hosts: List[str] = ctx.extra.get("live_hosts", []) or []
        tech_hints: Dict[str, str] = ctx.extra.get("tech", {}) or {}
        open_ports: Dict[str, List[int]] = ctx.extra.get("ports", {}) or {}
        waf_present: Dict[str, bool] = ctx.extra.get("waf", {}) or {}
        prior_findings: List[Dict] = ctx.extra.get("findings", []) or []

        assets = set(subdomains) | set(live_hosts)
        if not assets:
            assets.add(target.replace("https://", "").replace("http://", "").split("/")[0])

        ranked: List[Dict[str, Any]] = []
        for asset in assets:
            score, reasons = self._score_asset(
                asset, tech_hints, open_ports, waf_present, prior_findings
            )
            ranked.append({
                "asset": asset,
                "score": score,
                "reasons": reasons,
                "priority": "critical" if score >= 70 else ("high" if score >= 45 else ("medium" if score >= 20 else "low")),
            })

        ranked.sort(key=lambda r: r["score"], reverse=True)

        payload = {
            "target": target,
            "assets_scanned": len(ranked),
            "ranking": ranked[:50],
            "top_target": ranked[0] if ranked else None,
            "generated_at": time.time(),
            "methodology": "Score = tech value + exposed ports + missing WAF + prior findings + sensitive paths.",
        }

        p_rank = ctx.workspace.write_file(target, "analysis", "surface_ranking.json", json.dumps(payload, indent=2, ensure_ascii=False), ctx.session_id)
        result.output_files = {"surface_ranking.json": str(p_rank)}
        result.raw_output = {"ranking": json.dumps(payload, ensure_ascii=False)}

        if ranked:
            top = ranked[0]
            result.add_finding(
                title=f"Highest-value attack surface: {top['asset']} (score {top['score']})",
                evidence=" | ".join(top["reasons"][:5]),
                severity="Medium",
                vuln_type="attack_surface",
                recommendation="Focus automated testing on this asset first.",
                url=top["asset"],
            )
            result.next_skills = ["agent_tool_planner", "agent_reasoning_loop"]

        self.logger.info(f"[SurfaceRanker] {len(ranked)} assets ranked for {target}")
        return result

    def _score_asset(
        self,
        asset: str,
        tech: Dict[str, str],
        ports: Dict[str, List[int]],
        waf: Dict[str, bool],
        findings: List[Dict],
    ):
        score = 0
        reasons: List[str] = []

        t = tech.get(asset, "").lower()
        for hvt in self.HIGH_VALUE_TECH:
            if hvt in t:
                score += 20
                reasons.append(f"High-value tech: {hvt}")
                break

        # prior findings boost score heavily
        asset_findings = [f for f in findings if asset in json.dumps(f, ensure_ascii=False)]
        if asset_findings:
            score += 30 * min(len(asset_findings), 3)
            reasons.append(f"{len(asset_findings)} prior findings on this asset")

        # ports
        asset_ports = ports.get(asset, []) or ports.get(asset.replace("www.", ""), [])
        for p in asset_ports:
            if p in self.SENSITIVE_PORTS:
                score += self.SENSITIVE_PORTS[p]
                reasons.append(f"Sensitive port open: {p}")

        # missing WAF boosts
        if asset in waf and not waf[asset]:
            score += 15
            reasons.append("No WAF detected")

        # sensitive paths hinted in tech/paths
        for p in self.HIGH_VALUE_PATHS:
            if p in asset.lower():
                score += 10
                reasons.append(f"Sensitive path: {p}")
                break

        score = min(score, 100)
        return score, reasons


if __name__ == "__main__":
    import asyncio

    class FakeTM:
        def is_available(self, cmd):
            return True

    class FakeWS:
        def write_file(self, *a, **k):
            from pathlib import Path
            return Path("/tmp/x")

    class FakeCtx:
        target = "example.com"
        extra = {"subdomains": ["api.example.com", "admin.example.com"], "live_hosts": ["api.example.com"],
                 "tech": {"admin.example.com": "wordpress"}, "ports": {"api.example.com": [80, 8080, 3306]},
                 "waf": {"api.example.com": False}, "findings": []}
        retry_attempt = 0
        tool_manager = FakeTM()
        workspace = FakeWS()
        session_id = "s1"

    async def main():
        skill = AttackSurfaceRankerSkill()
        res = await skill.run(FakeCtx())
        print(res.raw_output["ranking"][:300])

    asyncio.run(main())
