"""
DNS Enumeration Skill
يجمع كل أنواع الـ DNS Records: A, AAAA, MX, NS, TXT, CNAME
"""
from __future__ import annotations

import re
from typing import List

from skills.base_skill import BaseSkill, SkillContext, SkillResult


class DnsEnumSkill(BaseSkill):
    name = "dns_enum"
    category = "recon"
    description = "Enumerate DNS records (A, AAAA, MX, NS, TXT, CNAME)"
    tools_required = ["dig"]
    fallback_tools = ["nslookup", "dnsx"]

    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=True, tool_used="dig")
        target = ctx.target.replace("https://", "").replace("http://", "").split("/")[0]

        if not re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", target):
            result.errors.append(f"Target '{target}' is not a domain")
            result.success = False
            return result

        records_output: List[str] = [f"# DNS Records for {target}\n"]

        if ctx.tool_manager.is_available("dig"):
            for rtype in self.RECORD_TYPES:
                res = await ctx.tool_manager.execute(
                    f"dig {target} {rtype} +short", timeout=15
                )
                if res.stdout.strip():
                    records_output.append(f"## {rtype}")
                    records_output.append(res.stdout.strip())
                    records_output.append("")
            result.tool_used = "dig"

        elif ctx.tool_manager.is_available("dnsx"):
            res = await ctx.tool_manager.execute(
                f"dnsx -d {target} -a -aaaa -mx -ns -txt -cname -resp-only -silent",
                timeout=60
            )
            records_output.append(res.stdout)
            result.tool_used = "dnsx"

        elif ctx.tool_manager.is_available("nslookup"):
            res = await ctx.tool_manager.execute(
                f"nslookup {target}", timeout=15
            )
            records_output.append(res.stdout)
            result.tool_used = "nslookup"

        else:
            result.errors.append("No DNS tool available (dig/dnsx/nslookup)")
            result.success = False
            return result

        content = "\n".join(records_output)
        p = ctx.workspace.write_file(ctx.target, "recon", "dns_records.txt", content, ctx.session_id)
        result.output_files["dns_records.txt"] = str(p)

        # Extract IPs from A records
        ips = [ln.strip() for ln in content.splitlines()
               if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ln.strip())]
        if ips:
            ip_content = "\n".join(sorted(set(ips)))
            p2 = ctx.workspace.write_file(ctx.target, "recon", "ips.txt", ip_content, ctx.session_id)
            result.output_files["ips.txt"] = str(p2)

        result.add_finding(
            title=f"DNS Records ({target})",
            evidence=content[:1000],
            severity="Info",
            vuln_type="dns",
            recommendation="Review DNS records for zone transfers, dangling records, and misconfigurations.",
        )
        return result
