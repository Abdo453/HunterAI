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

        if ctx.tool_manager and ctx.tool_manager.is_available("httpx"):
            httpx_bin = ctx.tool_manager.resolve_binary("httpx")
            res = await ctx.tool_manager.execute(
                [httpx_bin, "-l", str(tmp_file), "-silent", "-status-code", "-title", "-tech-detect", "-timeout", "10"],
                timeout=180,
            )
            if (res.stdout or "").strip():
                live_hosts = [l.strip() for l in res.stdout.splitlines() if l.strip()]
                result.raw_output["httpx"] = res.stdout[:5000]
                result.tool_used = "httpx"

        elif ctx.tool_manager and ctx.tool_manager.is_available("httprobe"):
            import asyncio
            httprobe_bin = ctx.tool_manager.resolve_binary("httprobe")
            try:
                proc = await asyncio.create_subprocess_exec(
                    httprobe_bin,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                out, _ = await asyncio.wait_for(
                    proc.communicate("\n".join(hosts_to_probe).encode("utf-8")),
                    timeout=120,
                )
                live_hosts = [l.strip() for l in out.decode("utf-8", errors="replace").splitlines() if l.strip()]
            except Exception as exc:
                self.logger.warning(f"httprobe failed: {exc}")
            result.tool_used = "httprobe"

        else:
            # Cross-platform Python httpx fallback (works identically on Windows & Linux)
            import httpx as py_httpx
            from core.scope_engine import validate_http_url_target

            allow_loopback = bool(ctx.extra.get("allow_loopback", False))
            in_scope = ctx.extra.get("in_scope")
            async with py_httpx.AsyncClient(timeout=5.0, verify=False, follow_redirects=False, trust_env=False) as client:
                for h in hosts_to_probe[:30]:
                    probe_url = h if h.startswith(("http://", "https://")) else f"https://{h}"
                    ok_url, _ = validate_http_url_target(
                        probe_url,
                        in_scope=in_scope,
                        allow_loopback=allow_loopback,
                        resolve_dns=False,
                        fail_closed=False,
                    )
                    if not ok_url:
                        continue
                    for scheme_url in (probe_url, probe_url.replace("https://", "http://", 1) if probe_url.startswith("https://") else probe_url):
                        try:
                            resp = await client.head(scheme_url)
                            live_hosts.append(f"{scheme_url} [{resp.status_code}]")
                            break
                        except Exception:
                            continue
            result.tool_used = "python-httpx"

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
