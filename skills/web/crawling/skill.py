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

        target = ctx.target if ctx.target.startswith("http") else f"http://{ctx.target}"
        all_urls: set = set()

        # 1. katana
        if ctx.tool_manager.is_available("katana"):
            res = await ctx.tool_manager.execute(
                f"katana -u {target} -silent -depth 3 -jc", timeout=180
            )
            urls = [l.strip() for l in res.stdout.splitlines() if l.strip().startswith("http")]
            all_urls.update(urls)
            result.tool_used = "katana"

        # 2. gospider
        if ctx.tool_manager.is_available("gospider"):
            res = await ctx.tool_manager.execute(
                f"gospider -s {target} -q -d 2", timeout=120
            )
            for line in res.stdout.splitlines():
                parts = line.strip().split()
                for p in parts:
                    if p.startswith("http"):
                        all_urls.add(p)

        # 3. gau (historical URLs)
        clean = ctx.target.replace("https://", "").replace("http://", "").split("/")[0]
        if ctx.tool_manager.is_available("gau"):
            res = await ctx.tool_manager.execute(
                f"gau {clean} --subs", timeout=120
            )
            urls = [l.strip() for l in res.stdout.splitlines() if l.strip().startswith("http")]
            all_urls.update(urls)

        # 4. waybackurls
        if ctx.tool_manager.is_available("waybackurls"):
            res = await ctx.tool_manager.execute(
                f"echo {clean} | waybackurls", timeout=90
            )
            urls = [l.strip() for l in res.stdout.splitlines() if l.strip().startswith("http")]
            all_urls.update(urls)

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
