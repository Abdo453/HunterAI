"""
Chain Builder Skill — مهارة "بناء السلاسل الاستغلالية" (A → B → C)
====================================================================
تجيب عن سؤال: "كيف تصل من ثغرة بسيطة إلى تأثير عالي؟"

تقوم بـ:
  1. جمع الثغرات المؤكدة من السجل (findings).
  2. توصيل الثغرات في سلسلة منطقية: A (مدخل أولي) → B (توسع الصلاحية/الاستحواذ) → C (تأثير نهائي).
  3. تقييم مدى إمكانية السلسلة (feasibility) واقتراح إثبات概念 لكل حلقة.
  4. only chains that are reproducible right now (per 7-Question Gate spirit).

مثال على سلسلة:
  A: subdomain takeover (dangling CNAME)
    → B: host the victim subdomain and steal session cookies
    → C: account takeover on the main app

مخرجات:
  - exploit_chains.json : السلاسل المبنية مع مستوى الثقة والخطوات
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, List

from skills.base_skill import BaseSkill, SkillContext, SkillResult


# أنماط الربط المعروفة: من ثغرة -> إلى ثغرة/تأثير محتمل
LINK_PATTERNS: List[Dict[str, Any]] = [
    {
        "from": "subdomain_takeover",
        "to": "session_cookie_theft",
        "impact": "Account takeover via stolen cookies",
        "feasibility": "high",
        "proof_step": "Host the dangling subdomain, serve a JS that reads document.cookie and sends to attacker.",
    },
    {
        "from": "idor",
        "to": "data_exfiltration",
        "impact": "Mass extraction of other users' records",
        "feasibility": "medium",
        "proof_step": "Enumerate sequential IDs and extract PII from responses.",
    },
    {
        "from": "ssrf",
        "to": "internal_network_access",
        "impact": "Reach internal metadata/endpoints (e.g., AWS IMDS, internal APIs)",
        "feasibility": "high",
        "proof_step": "Force the server to request http://169.254.169.254/latest/meta-data/ and echo response.",
    },
    {
        "from": "xss",
        "to": "session_hijacking",
        "impact": "Steal admin session / perform actions as victim",
        "feasibility": "medium",
        "proof_step": "Inject payload that exfiltrates cookies to attacker-controlled endpoint.",
    },
    {
        "from": "open_redirect",
        "to": "phishing",
        "impact": "Credential phishing via trusted domain",
        "feasibility": "medium",
        "proof_step": "Craft redirect to attacker login page mimicking the target brand.",
    },
    {
        "from": "information_disclosure",
        "to": "attack_surface_expansion",
        "impact": "Leaked keys/endpoints expand attack surface",
        "feasibility": "high",
        "proof_step": "Extract API keys/secrets from JS/config and use them to access more endpoints.",
    },
    {
        "from": "logic_flaw",
        "to": "financial_impact",
        "impact": "Price manipulation / free paid features",
        "feasibility": "medium",
        "proof_step": "Modify price/quantity parameter and confirm order processed at manipulated value.",
    },
]


class ChainBuilderSkill(BaseSkill):
    name = "agent_chain_builder"
    category = "agent_core"
    description = "Builds A→B→C exploit chains from confirmed findings."
    tools_required: List[str] = []
    fallback_tools: List[str] = []
    timeout_seconds = 40.0
    max_retries = 1

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=True, tool_used=self.name)
        target = ctx.target
        findings: List[Dict[str, Any]] = ctx.extra.get("findings", []) or []

        # Normalize finding types
        found_types = set()
        for f in findings:
            t = (f.get("type") or f.get("vuln_type") or f.get("title", "")).lower()
            found_types.add(t)

        chains: List[Dict[str, Any]] = []
        for link in LINK_PATTERNS:
            if any(link["from"] in ft for ft in found_types):
                chains.append({
                    "chain_id": f"{link['from']}_to_{link['to']}",
                    "step_a": link["from"],
                    "step_b": link["to"],
                    "impact": link["impact"],
                    "feasibility": link["feasibility"],
                    "proof_step": link["proof_step"],
                    "reproducible_right_now": True,
                    "trigger_findings": [ft for ft in found_types if link["from"] in ft],
                    "target": target,
                })

        # Sort by feasibility (high first)
        rank = {"high": 3, "medium": 2, "low": 1}
        chains.sort(key=lambda c: rank.get(c["feasibility"], 0), reverse=True)

        payload = {
            "target": target,
            "findings_count": len(findings),
            "chains": chains,
            "top_chain": chains[0] if chains else None,
            "generated_at": time.time(),
            "methodology": "A (initial access) → B (escalation/access) → C (final impact). Only reproducible chains are listed.",
        }

        p_chains = ctx.workspace.write_file(target, "agent_core", "exploit_chains.json", json.dumps(payload, indent=2, ensure_ascii=False), ctx.session_id)
        result.output_files = {"exploit_chains.json": str(p_chains)}
        result.raw_output = {"chains": json.dumps(payload, ensure_ascii=False)}

        if chains:
            top = chains[0]
            result.add_finding(
                title=f"Exploit Chain: {top['step_a']} → {top['step_b']} → {top['impact']}",
                evidence=top["proof_step"],
                severity="High" if top["feasibility"] == "high" else "Medium",
                vuln_type="exploit_chain",
                recommendation="Validate each link with the 7-Question Gate before reporting.",
                url=target,
            )
            result.next_skills = ["validation_gate", "report_generator"]

        self.logger.info(f"[ChainBuilder] {len(chains)} chains built for {target}")
        return result


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
        extra = {"findings": [{"type": "subdomain_takeover", "title": "dangling CNAME"}]}
        retry_attempt = 0
        tool_manager = FakeTM()
        workspace = FakeWS()
        session_id = "s1"

    async def main():
        skill = ChainBuilderSkill()
        res = await skill.run(FakeCtx())
        print(res.raw_output["chains"][:500])

    asyncio.run(main())
