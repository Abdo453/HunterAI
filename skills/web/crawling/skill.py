"""
Crawling Skill — يجمع كل URLs من الـ Target
katana → gospider → gau → waybackurls
"""
from __future__ import annotations

from pathlib import Path

from skills.base_skill import BaseSkill, SkillContext, SkillResult


class CrawlingSkill(BaseSkill):
    name = "crawling"
    category = "web"
    description = "Crawl URLs using katana, gospider, gau"
    tools_required = ["katana"]
    fallback_tools = ["gospider", "gau", "waybackurls"]

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=True, tool_used="katana")

        target = ctx.target if ctx.target.startswith(("http://", "https://")) else f"http://{ctx.target}"
        all_urls: set = set()
        tool_invoked = False

        # 1. katana
        if ctx.tool_manager and ctx.tool_manager.is_available("katana"):
            tool_invoked = True
            res = await ctx.tool_manager.execute(
                ["katana", "-u", target, "-silent", "-depth", "3", "-jc"], timeout=180
            )
            urls = [l.strip() for l in (res.stdout or "").splitlines() if l.strip().startswith("http")]
            all_urls.update(urls)
            result.tool_used = "katana"

        # 2. gospider
        if ctx.tool_manager and ctx.tool_manager.is_available("gospider"):
            tool_invoked = True
            res = await ctx.tool_manager.execute(
                ["gospider", "-s", target, "-q", "-d", "2"], timeout=120
            )
            for line in (res.stdout or "").splitlines():
                parts = line.strip().split()
                for p in parts:
                    if p.startswith("http"):
                        all_urls.add(p)

        # 3. gau (historical URLs)
        clean = ctx.target.replace("https://", "").replace("http://", "").split("/")[0]
        if ctx.tool_manager and ctx.tool_manager.is_available("gau"):
            tool_invoked = True
            res = await ctx.tool_manager.execute(
                ["gau", clean, "--subs"], timeout=120
            )
            urls = [l.strip() for l in (res.stdout or "").splitlines() if l.strip().startswith("http")]
            all_urls.update(urls)

        # 4. waybackurls (cross-platform stdin pipe via create_subprocess_exec, no shell pipe)
        if ctx.tool_manager and ctx.tool_manager.is_available("waybackurls"):
            import asyncio
            tool_invoked = True
            wb_bin = ctx.tool_manager.resolve_binary("waybackurls")
            try:
                proc = await asyncio.create_subprocess_exec(
                    wb_bin,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                out, _ = await asyncio.wait_for(
                    proc.communicate((clean + "\n").encode("utf-8")),
                    timeout=90,
                )
                urls = [
                    l.strip()
                    for l in out.decode("utf-8", errors="replace").splitlines()
                    if l.strip().startswith("http")
                ]
                all_urls.update(urls)
            except Exception as exc:
                self.logger.warning(f"waybackurls failed: {exc}")

        if not tool_invoked:
            result.add_error("tool_missing", "No web crawling tool available (katana/gospider/gau/waybackurls)")
            result.success = False
            result.metadata = {"status": "UNAVAILABLE", "reason": "tool_missing"}
            return result

        if not all_urls:
            result.errors.append("No URLs found")
            result.success = False
            return result

        sorted_urls = sorted(all_urls)
        content = "\n".join(sorted_urls)
        p = ctx.workspace.write_file(ctx.target, "web", "urls.txt", content, ctx.session_id)
        result.output_files["urls.txt"] = str(p)

        result.add_finding(
            title=f"URLs Discovered ({len(sorted_urls)})",
            evidence="\n".join(sorted_urls[:30]),
            severity="Info",
            vuln_type="crawling",
            recommendation="Review discovered URLs for sensitive endpoints and parameters.",
        )
        return result
