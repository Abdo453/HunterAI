"""
Param Discover — اكتشاف معاملات HTTP مخفية
============================================
يدعم arjun/paramspider إن توفّرا، وإلا يستخرج المعاملات من عناوين Wayback Machine مخزّنة سابقاً.
"""
from __future__ import annotations

import asyncio
import json
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import quote

import httpx

from skills.base_skill import BaseSkill, SkillContext, SkillResult


class ParamDiscoverSkill(BaseSkill):
    name = "param_discover"
    category = "recon"
    description = "اكتشاف معاملات HTTP مخفية باستخدام arjun/paramspider أو wayback fallback"
    tools_required: List[str] = []
    fallback_tools: List[str] = ["arjun", "paramspider"]
    timeout_seconds = 90.0
    max_retries = 1

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=True, tool_used="param_discover")
        target = ctx.target
        discovered: List[str] = []
        tool = self._pick_tool(ctx.tool_manager)
        target_url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        clean_domain = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

        if tool:
            try:
                if tool == "arjun":
                    tmp_out = Path(tempfile.gettempdir()) / f"arjun_{int(time.time()*1000)}.txt"
                    try:
                        res = await ctx.tool_manager.execute(
                            ["arjun", "-u", target_url, "-oT", str(tmp_out), "--stable", "-q"],
                            timeout=90,
                        )
                        raw_out = tmp_out.read_text(encoding="utf-8", errors="ignore") if tmp_out.is_file() else (res.stdout or "")
                    finally:
                        tmp_out.unlink(missing_ok=True)
                else:
                    res = await ctx.tool_manager.execute(["paramspider", "-d", clean_domain, "--quiet"], timeout=90)
                    raw_out = res.stdout or ""
                for line in raw_out.splitlines():
                    line = line.strip()
                    if line and ("?" in line or "=" in line):
                        discovered.append(line)
            except Exception as exc:
                self.logger.warning(f"{tool} failed: {exc}")

        if not discovered:
            discovered = await self._wayback_params(clean_domain)

        payload = {
            "target": target,
            "urls_with_params": discovered[:200],
            "count": len(discovered),
            "tool_used": tool or "wayback_fallback",
            "generated_at": time.time(),
        }

        p_out = ctx.workspace.write_file(target, "recon", "params_discovered.json", json.dumps(payload, indent=2, ensure_ascii=False), ctx.session_id)
        result.output_files = {"params_discovered.json": str(p_out)}
        result.raw_output = {"params": json.dumps(payload, ensure_ascii=False)}

        result.add_finding(
            title=f"Hidden parameters discovered ({payload['count']})",
            evidence="\n".join(discovered[:30]),
            severity="Info",
            vuln_type="parameter_discovery",
            recommendation="فحص هذه المعاملات ضد IDOR و SSRF و SQLi و XSS.",
            url=target,
        )
        result.next_skills = ["idor_tester", "ssrf_hunter", "sqli_hunter", "xss_hunter"]

        self.logger.info(f"[ParamDiscover] {target}: {len(discovered)} URLs with params")
        return result

    def _pick_tool(self, tool_manager) -> str | None:
        for t in ("arjun", "paramspider"):
            try:
                if tool_manager and tool_manager.is_available(t):
                    return t
            except Exception:
                pass
        return None

    async def _wayback_params(self, target: str) -> List[str]:
        found: List[str] = []
        try:
            async with httpx.AsyncClient(timeout=20, verify=False, trust_env=False) as client:
                resp = await client.get(
                    f"https://web.archive.org/cdx/search/cdx?url={quote(target, safe='')}/*&output=text&fl=original&collapse=urlkey&limit=200"
                )
                if resp.status_code == 200:
                    for line in resp.text.splitlines():
                        if "?" in line:
                            found.append(line)
        except Exception:
            pass
        return found


if __name__ == "__main__":
    import asyncio

    class FakeTM:
        def is_available(self, c):
            return False

    class FakeWS:
        def write_file(self, *a, **k):
            return Path(tempfile.gettempdir()) / "params_discovered.json"

    class FakeCtx:
        target = "example.com"
        extra = {}
        retry_attempt = 0
        tool_manager = FakeTM()
        workspace = FakeWS()
        session_id = "s1"

    async def main():
        skill = ParamDiscoverSkill()
        res = await skill.run(FakeCtx())
        print(res.raw_output["params"][:400])

    asyncio.run(main())
