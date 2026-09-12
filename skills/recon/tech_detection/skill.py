"""
Technology Detection Skill
يكتشف التقنيات والـ Frameworks وCSM وWAF
"""
from __future__ import annotations

from pathlib import Path

from skills.base_skill import BaseSkill, SkillContext, SkillResult


class TechDetectionSkill(BaseSkill):
    name = "tech_detection"
    category = "recon"
    description = "Detect web technologies, CMS, frameworks and WAF"
    tools_required = ["whatweb"]
    fallback_tools = ["httpx", "wafw00f"]

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=True, tool_used="whatweb")

        # Build target list from live_hosts or fallback to single target
        targets = []
        live_file = ctx.state_files.get("live_host_detection", {})
        if isinstance(live_file, dict):
            live_path = live_file.get("live_hosts.txt", "")
        else:
            live_path = live_file

        if live_path and Path(live_path).exists():
            raw = Path(live_path).read_text(encoding="utf-8")
            # Extract URLs (first part of each line)
            targets = [ln.strip().split()[0] for ln in raw.splitlines() if ln.strip()]

        if not targets:
            t = ctx.target if ctx.target.startswith("http") else f"http://{ctx.target}"
            targets = [t]

        tech_lines = []

        if ctx.tool_manager.is_available("whatweb"):
            for t in targets[:20]:
                res = await ctx.tool_manager.execute(
                    f"whatweb -q {t}", timeout=30
                )
                if res.stdout.strip():
                    tech_lines.append(res.stdout.strip())
            result.tool_used = "whatweb"

        else:
            httpx_bin = ctx.tool_manager.resolve_binary("httpx")
            if ctx.tool_manager.is_available("httpx"):
                for t in targets[:20]:
                    res = await ctx.tool_manager.execute(
                        f"{httpx_bin} -u {t} -tech-detect -silent", timeout=20
                    )
                    if res.stdout.strip():
                        tech_lines.append(res.stdout.strip())
                result.tool_used = "httpx"

        # WAF detection
        waf_info = []
        if ctx.tool_manager.is_available("wafw00f"):
            for t in targets[:10]:
                url = t if t.startswith("http") else f"http://{t}"
                res = await ctx.tool_manager.execute(
                    f"wafw00f {url}", timeout=20
                )
                if "is behind" in res.stdout.lower() or "no waf" in res.stdout.lower():
                    waf_info.append(res.stdout.strip()[:200])

        if waf_info:
            tech_lines.append("\n# WAF Detection\n" + "\n".join(waf_info))

        if not tech_lines:
            result.errors.append("No technology information detected")
            result.success = False
            return result

        content = "\n".join(tech_lines)
        p = ctx.workspace.write_file(ctx.target, "recon", "technologies.txt", content, ctx.session_id)
        result.output_files["technologies.txt"] = str(p)

        result.add_finding(
            title=f"Technologies Detected ({ctx.target})",
            evidence=content[:1500],
            severity="Info",
            vuln_type="tech_detection",
            recommendation="Review detected technologies for known CVEs and outdated versions.",
        )
        return result
