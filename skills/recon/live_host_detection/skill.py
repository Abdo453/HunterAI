"""
Live Host Detection Skill
يكتشف الـ Hosts الحية من قائمة Subdomains
"""
from __future__ import annotations

from pathlib import Path

from skills.base_skill import BaseSkill, SkillContext, SkillResult


class LiveHostDetectionSkill(BaseSkill):
    name = "live_host_detection"
    category = "recon"
    description = "Probe which hosts/subdomains are alive using httpx or httprobe"
    tools_required = ["httpx"]
    fallback_tools = ["httprobe", "curl"]

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=True, tool_used="httpx")

        # Read subdomains from previous skill output
        subs_file = ctx.state_files.get("subdomain_enum", {})
        if isinstance(subs_file, dict):
            subs_path = subs_file.get("subdomains_unique.txt", "")
        else:
            subs_path = subs_file

        target_clean = ctx.target.replace("https://", "").replace("http://", "").split("/")[0]

        if subs_path and Path(subs_path).exists():
            subs_content = Path(subs_path).read_text(encoding="utf-8").strip()
            hosts_to_probe = [l.strip() for l in subs_content.splitlines() if l.strip()]
        else:
            # Fallback: just use the main target
            hosts_to_probe = [target_clean]

        if not hosts_to_probe:
            result.errors.append("No hosts to probe")
            result.success = False
            return result

        # Write temp hosts list
        ws_path = ctx.workspace.get_workspace_path(ctx.target, ctx.session_id)
        tmp_file = ws_path / "recon" / "_hosts_tmp.txt"
        tmp_file.parent.mkdir(parents=True, exist_ok=True)
        tmp_file.write_text("\n".join(hosts_to_probe), encoding="utf-8")

        live_hosts = []

        if ctx.tool_manager.is_available("httpx"):
            httpx_bin = ctx.tool_manager.resolve_binary("httpx")
            res = await ctx.tool_manager.execute(
                f"{httpx_bin} -l {tmp_file} -silent -status-code -title -tech-detect -timeout 10",
                timeout=180
            )
            if res.stdout.strip():
                live_hosts = [l.strip() for l in res.stdout.splitlines() if l.strip()]
                result.raw_output["httpx"] = res.stdout[:5000]
                result.tool_used = "httpx"

        elif ctx.tool_manager.is_available("httprobe"):
            res = await ctx.tool_manager.execute(
                f"cat {tmp_file} | httprobe", timeout=120
            )
            live_hosts = [l.strip() for l in res.stdout.splitlines() if l.strip()]
            result.tool_used = "httprobe"

        else:
            # curl fallback — check each host
            import asyncio
            live_hosts = []
            for h in hosts_to_probe[:30]:  # limit for curl
                r = await ctx.tool_manager.execute(
                    f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 5 http://{h}",
                    timeout=10
                )
                if r.stdout.strip() not in ("", "000"):
                    live_hosts.append(f"http://{h} [{r.stdout.strip()}]")
            result.tool_used = "curl"

        if not live_hosts:
            result.errors.append("No live hosts found")
            result.success = False
            return result

        content = "\n".join(live_hosts)
        p = ctx.workspace.write_file(ctx.target, "recon", "live_hosts.txt", content, ctx.session_id)
        result.output_files["live_hosts.txt"] = str(p)

        result.add_finding(
            title=f"Live Hosts ({len(live_hosts)})",
            evidence="\n".join(live_hosts[:30]),
            severity="Info",
            vuln_type="live_hosts",
            recommendation="Focus testing on live hosts with interesting services.",
        )
        return result
