"""
Parameter Discovery Skill — arjun / paramspider
"""
from __future__ import annotations

import tempfile
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

        target = ctx.target if ctx.target.startswith(("http://", "https://")) else f"http://{ctx.target}"
        targets_to_scan = [target]

        if urls_path and Path(urls_path).exists():
            raw = Path(urls_path).read_text(encoding="utf-8", errors="ignore")
            param_urls = [l.strip() for l in raw.splitlines()
                          if l.strip() and "?" in l][:50]
            if param_urls:
                targets_to_scan = param_urls

        all_output: list = []
        ws_path = ctx.workspace.get_workspace_path(ctx.target, ctx.session_id)
        tool_invoked = False

        if ctx.tool_manager and ctx.tool_manager.is_available("arjun"):
            tool_invoked = True
            tmp_dir = ws_path / "web"
            tmp_dir.mkdir(parents=True, exist_ok=True)
            for idx, t in enumerate(targets_to_scan[:20]):
                tmp_out = tmp_dir / f"_arjun_out_{idx}.txt"
                try:
                    res = await ctx.tool_manager.execute(
                        ["arjun", "-u", t, "-oT", str(tmp_out), "--stable", "-q"],
                        timeout=60,
                    )
                    txt = tmp_out.read_text(encoding="utf-8", errors="ignore").strip() if tmp_out.is_file() else (res.stdout or "").strip()
                    if txt:
                        all_output.append(f"# {t}\n{txt}")
                finally:
                    tmp_out.unlink(missing_ok=True)
            result.tool_used = "arjun"

        elif ctx.tool_manager and ctx.tool_manager.is_available("paramspider"):
            tool_invoked = True
            clean = ctx.target.replace("https://", "").replace("http://", "").split("/")[0]
            res = await ctx.tool_manager.execute(
                ["paramspider", "-d", clean, "--quiet"], timeout=120
            )
            if (res.stdout or "").strip():
                all_output.append(res.stdout.strip())
            result.tool_used = "paramspider"

        if not tool_invoked:
            result.add_error("tool_missing", "No parameter discovery tool available (arjun/paramspider)")
            result.success = False
            result.metadata = {"status": "UNAVAILABLE", "reason": "tool_missing"}
            return result

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
