"""
Parameter Discovery Skill — arjun / paramspider
"""
from __future__ import annotations

from pathlib import Path

from skills.base_skill import BaseSkill, SkillContext, SkillResult


class ParameterDiscoverySkill(BaseSkill):
    name = "parameter_discovery"
    category = "web"
    description = "Discover hidden GET/POST parameters using arjun or paramspider"
    tools_required = ["arjun"]
    fallback_tools = ["paramspider"]

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=True, tool_used="arjun")

        # Get URLs from crawling output
        urls_file = ctx.state_files.get("crawling", {})
        if isinstance(urls_file, dict):
            urls_path = urls_file.get("urls.txt", "")
        else:
            urls_path = urls_file

        target = ctx.target if ctx.target.startswith("http") else f"http://{ctx.target}"
        targets_to_scan = [target]

        if urls_path and Path(urls_path).exists():
            raw = Path(urls_path).read_text(encoding="utf-8")
            # Filter to URLs with query strings for arjun
            param_urls = [l.strip() for l in raw.splitlines()
                          if l.strip() and "?" in l][:50]
            if param_urls:
                targets_to_scan = param_urls

        all_output: list = []
        ws_path = ctx.workspace.get_workspace_path(ctx.target, ctx.session_id)

        if ctx.tool_manager.is_available("arjun"):
            for t in targets_to_scan[:20]:
                res = await ctx.tool_manager.execute(
                    f"arjun -u {t} -oT /dev/stdout --stable -q",
                    timeout=60
                )
                if res.stdout.strip():
                    all_output.append(f"# {t}\n{res.stdout.strip()}")
            result.tool_used = "arjun"

        elif ctx.tool_manager.is_available("paramspider"):
            clean = ctx.target.replace("https://", "").replace("http://", "").split("/")[0]
            res = await ctx.tool_manager.execute(
                f"paramspider -d {clean} --quiet", timeout=120
            )
            all_output.append(res.stdout)
            result.tool_used = "paramspider"

        if not all_output:
            result.errors.append("No parameters discovered")
            result.success = False
            return result

        content = "\n\n".join(all_output)
        p = ctx.workspace.write_file(ctx.target, "web", "parameters.txt", content, ctx.session_id)
        result.output_files["parameters.txt"] = str(p)

        result.add_finding(
            title="Hidden Parameters Discovered",
            evidence=content[:1500],
            severity="Info",
            vuln_type="parameter_discovery",
            recommendation="Test discovered parameters for injection and IDOR vulnerabilities.",
        )
        return result
