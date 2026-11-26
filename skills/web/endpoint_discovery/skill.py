"""
Endpoint Discovery Skill — ffuf / gobuster / dirsearch
"""
from __future__ import annotations

from pathlib import Path

from skills.base_skill import BaseSkill, SkillContext, SkillResult

_REPO_ROOT = Path(__file__).resolve().parents[3]

WORDLISTS = [
    str(_REPO_ROOT / "wordlists" / "common.txt"),
    str(_REPO_ROOT / "wordlists" / "endpoints.txt"),
    str(_REPO_ROOT / "bughunter" / "wordlists" / "common.txt"),
    str(Path.home() / "wordlist" / "SecLists" / "Discovery" / "Web-Content" / "common.txt"),
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

        target = ctx.target if ctx.target.startswith(("http://", "https://")) else f"http://{ctx.target}"

        custom_wl = ctx.extra.get("wordlist")
        candidates = ([str(custom_wl)] if custom_wl else []) + list(WORDLISTS)
        wordlist = next((w for w in candidates if w and Path(w).is_file()), None)
        if not wordlist:
            result.add_error("wordlist_missing", "No wordlist found — configure wordlists/ or install seclists/dirb")
            result.success = False
            result.metadata = {"status": "UNAVAILABLE", "reason": "wordlist_missing"}
            return result

        raw_output = ""
        tool_invoked = False

        if ctx.tool_manager and ctx.tool_manager.is_available("ffuf"):
            tool_invoked = True
            res = await ctx.tool_manager.execute(
                ["ffuf", "-u", f"{target.rstrip('/')}/FUZZ", "-w", wordlist,
                 "-mc", "200,201,204,301,302,307,401,403", "-t", "40", "-timeout", "10", "-silent"],
                timeout=300,
            )
            raw_output = res.stdout or ""
            result.tool_used = "ffuf"

        elif ctx.tool_manager and ctx.tool_manager.is_available("gobuster"):
            tool_invoked = True
            res = await ctx.tool_manager.execute(
                ["gobuster", "dir", "-u", target, "-w", wordlist, "-q", "-t", "30", "--no-error"],
                timeout=300,
            )
            raw_output = res.stdout or ""
            result.tool_used = "gobuster"

        elif ctx.tool_manager and ctx.tool_manager.is_available("dirsearch"):
            tool_invoked = True
            res = await ctx.tool_manager.execute(
                ["dirsearch", "-u", target, "-w", wordlist, "-q", "--format", "plain"],
                timeout=300,
            )
            raw_output = res.stdout or ""
            result.tool_used = "dirsearch"

        if not tool_invoked:
            result.add_error("tool_missing", "No endpoint discovery tool available (ffuf/gobuster/dirsearch)")
            result.success = False
            result.metadata = {"status": "UNAVAILABLE", "reason": "tool_missing"}
            return result

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
