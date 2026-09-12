"""
Endpoint Discovery Skill — ffuf / gobuster / dirsearch
"""
from __future__ import annotations

from pathlib import Path

from skills.base_skill import BaseSkill, SkillContext, SkillResult

WORDLISTS = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
]

INTERESTING_KEYWORDS = [
    "admin", "api", "login", "upload", "backup", "config", "secret",
    "token", "auth", "dashboard", "manage", "debug", "dev", "test",
    "swagger", "graphql", "actuator", "env", "health", "metrics",
]


class EndpointDiscoverySkill(BaseSkill):
    name = "endpoint_discovery"
    category = "web"
    description = "Discover hidden endpoints and directories"
    tools_required = ["ffuf"]
    fallback_tools = ["gobuster", "dirsearch"]

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=True, tool_used="ffuf")

        target = ctx.target if ctx.target.startswith("http") else f"http://{ctx.target}"

        # Find available wordlist
        wordlist = next((w for w in WORDLISTS if Path(w).exists()), None)
        if not wordlist:
            result.errors.append("No wordlist found — install seclists or dirb")
            result.success = False
            return result

        raw_output = ""

        if ctx.tool_manager.is_available("ffuf"):
            res = await ctx.tool_manager.execute(
                f"ffuf -u {target}/FUZZ -w {wordlist} -mc 200,201,204,301,302,307,401,403 "
                f"-t 40 -timeout 10 -silent",
                timeout=300
            )
            raw_output = res.stdout
            result.tool_used = "ffuf"

        elif ctx.tool_manager.is_available("gobuster"):
            res = await ctx.tool_manager.execute(
                f"gobuster dir -u {target} -w {wordlist} -q -t 30 --no-error",
                timeout=300
            )
            raw_output = res.stdout
            result.tool_used = "gobuster"

        elif ctx.tool_manager.is_available("dirsearch"):
            res = await ctx.tool_manager.execute(
                f"dirsearch -u {target} -w {wordlist} -q --format plain",
                timeout=300
            )
            raw_output = res.stdout
            result.tool_used = "dirsearch"

        if not raw_output.strip():
            result.errors.append("No endpoints found")
            result.success = False
            return result

        p = ctx.workspace.write_file(ctx.target, "web", "endpoints.txt", raw_output, ctx.session_id)
        result.output_files["endpoints.txt"] = str(p)

        # Extract interesting endpoints
        interesting = [
            line for line in raw_output.splitlines()
            if any(kw in line.lower() for kw in INTERESTING_KEYWORDS)
        ]
        if interesting:
            int_content = "\n".join(interesting)
            p2 = ctx.workspace.write_file(
                ctx.target, "web", "interesting_endpoints.txt", int_content, ctx.session_id
            )
            result.output_files["interesting_endpoints.txt"] = str(p2)
            result.add_finding(
                title=f"Interesting Endpoints ({len(interesting)})",
                evidence=int_content[:1500],
                severity="Medium",
                vuln_type="endpoint_discovery",
                recommendation="Investigate admin, API, and debug endpoints for access control issues.",
            )

        result.add_finding(
            title=f"Endpoints Discovered",
            evidence=raw_output[:1000],
            severity="Info",
            vuln_type="endpoint_discovery",
        )
        return result
