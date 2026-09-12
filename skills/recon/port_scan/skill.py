"""
Port Scan Skill
يفحص المنافذ باستخدام nmap مع rustscan/masscan fallback
"""
from __future__ import annotations

import re

from skills.base_skill import BaseSkill, SkillContext, SkillResult


class PortScanSkill(BaseSkill):
    name = "port_scan"
    category = "recon"
    description = "Port scanning with service/version detection using nmap, rustscan, or masscan"
    tools_required = ["nmap"]
    fallback_tools = ["rustscan", "masscan"]

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=True, tool_used="nmap")
        target = ctx.target.replace("https://", "").replace("http://", "").split("/")[0]

        raw_output = ""
        open_ports = []
        services = []

        if ctx.tool_manager.is_available("rustscan"):
            # RustScan is much faster — use it first then pipe to nmap
            res = await ctx.tool_manager.execute(
                f"rustscan -a {target} --ulimit 5000 -- -sV -sC --open",
                timeout=300
            )
            raw_output = res.stdout + res.stderr
            result.tool_used = "rustscan"

        elif ctx.tool_manager.is_available("nmap"):
            res = await ctx.tool_manager.execute(
                f"nmap -sV -sC --open -T4 -p- --min-rate 1000 {target}",
                timeout=600
            )
            raw_output = res.stdout + res.stderr
            result.tool_used = "nmap"

        elif ctx.tool_manager.is_available("masscan"):
            res = await ctx.tool_manager.execute(
                f"masscan {target} -p0-65535 --rate=1000",
                timeout=300
            )
            raw_output = res.stdout
            result.tool_used = "masscan"

        else:
            result.errors.append("No port scanning tool available (nmap/rustscan/masscan)")
            result.success = False
            return result

        if not raw_output.strip():
            result.errors.append("Port scan returned no output")
            result.success = False
            return result

        # Parse open ports
        for line in raw_output.splitlines():
            if "/tcp" in line and "open" in line:
                open_ports.append(line.strip())
                parts = line.strip().split()
                if len(parts) >= 3:
                    services.append(f"{parts[0]} — {' '.join(parts[2:])}")

        # Write output files
        p1 = ctx.workspace.write_file(ctx.target, "nmap", "nmap.txt", raw_output, ctx.session_id)
        result.output_files["nmap.txt"] = str(p1)

        if open_ports:
            ports_content = "\n".join(open_ports)
            p2 = ctx.workspace.write_file(ctx.target, "nmap", "nmap_open_ports.txt", ports_content, ctx.session_id)
            result.output_files["nmap_open_ports.txt"] = str(p2)

        if services:
            svc_content = "\n".join(services)
            p3 = ctx.workspace.write_file(ctx.target, "nmap", "nmap_services.txt", svc_content, ctx.session_id)
            result.output_files["nmap_services.txt"] = str(p3)

        if open_ports:
            result.add_finding(
                title=f"Open Ports ({len(open_ports)})",
                evidence="\n".join(open_ports),
                severity="Info",
                vuln_type="ports",
                tool=result.tool_used,
                recommendation="Review all open services for outdated versions and misconfigurations.",
            )

        result.raw_output["scan"] = raw_output[:5000]
        return result
