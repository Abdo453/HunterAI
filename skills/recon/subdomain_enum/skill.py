"""
Subdomain Enumeration Skill
يجمع Subdomains من: subfinder + assetfinder + findomain + crt.sh
"""
from __future__ import annotations

import asyncio
import json
import re
from typing import List

import httpx

from skills.base_skill import BaseSkill, SkillContext, SkillResult


class SubdomainEnumSkill(BaseSkill):
    name = "subdomain_enum"
    category = "recon"
    description = "Enumerate subdomains from multiple sources"
    tools_required = ["subfinder"]
    fallback_tools = ["assetfinder", "findomain"]

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=True, tool_used="multi-source")
        target = ctx.target.replace("https://", "").replace("http://", "").split("/")[0]

        # Validate it's a domain
        if not re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", target):
            result.errors.append(f"Target '{target}' does not look like a domain — skipping subdomain enum")
            result.success = False
            return result

        all_subs: set = set()

        # 1. crt.sh (HTTP, no install needed)
        crt_subs = await self._crtsh(target)
        all_subs.update(crt_subs)
        self.logger.info(f"crt.sh found {len(crt_subs)} subdomains")

        # 2. subfinder
        if ctx.tool_manager.is_available("subfinder"):
            res = await ctx.tool_manager.execute(
                f"subfinder -d {target} -silent", timeout=120
            )
            subs = [l.strip() for l in res.stdout.splitlines() if l.strip() and target in l]
            all_subs.update(subs)
            result.raw_output["subfinder"] = res.stdout[:3000]
            result.tool_used = "subfinder"

        # 3. assetfinder
        if ctx.tool_manager.is_available("assetfinder"):
            res = await ctx.tool_manager.execute(
                f"assetfinder --subs-only {target}", timeout=90
            )
            subs = [l.strip() for l in res.stdout.splitlines() if l.strip() and target in l]
            all_subs.update(subs)

        # 4. findomain
        if ctx.tool_manager.is_available("findomain"):
            res = await ctx.tool_manager.execute(
                f"findomain -t {target} --quiet", timeout=90
            )
            subs = [l.strip() for l in res.stdout.splitlines() if l.strip() and target in l]
            all_subs.update(subs)

        if not all_subs:
            result.success = False
            result.errors.append("No subdomains found from any source")
            return result

        sorted_subs = sorted(all_subs)
        unique_subs = sorted(set(sorted_subs))

        # Write output files
        subs_content = "\n".join(sorted_subs)
        unique_content = "\n".join(unique_subs)

        p1 = ctx.workspace.write_file(ctx.target, "recon", "subdomains.txt", subs_content, ctx.session_id)
        p2 = ctx.workspace.write_file(ctx.target, "recon", "subdomains_unique.txt", unique_content, ctx.session_id)

        result.output_files = {
            "subdomains.txt": str(p1),
            "subdomains_unique.txt": str(p2),
        }

        result.add_finding(
            title=f"Subdomains Discovered ({len(unique_subs)})",
            evidence="\n".join(unique_subs[:50]),
            severity="Info",
            vuln_type="subdomains",
            recommendation="Review all subdomains for attack surface and takeover vulnerabilities.",
        )
        return result

    async def _crtsh(self, domain: str) -> List[str]:
        """يجلب Subdomains من crt.sh"""
        try:
            async with httpx.AsyncClient(timeout=20, verify=False, trust_env=False) as client:
                resp = await client.get(
                    f"https://crt.sh/?q=%.{domain}&output=json"
                )
                if resp.status_code == 200:
                    data = resp.json()
                    subs = set()
                    for entry in data:
                        name = entry.get("name_value", "")
                        for sub in name.splitlines():
                            sub = sub.strip().lstrip("*.")
                            if sub.endswith(domain):
                                subs.add(sub)
                    return list(subs)
        except Exception as exc:
            self.logger.warning(f"crt.sh failed: {exc}")
        return []
