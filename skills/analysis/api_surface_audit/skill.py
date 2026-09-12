"""
API Surface Audit Skill
Audits discovered REST, GraphQL, and Swagger endpoints against OWASP API Security standards.
"""
from __future__ import annotations

from pathlib import Path
from typing import List, Set

from skills.base_skill import BaseSkill, SkillContext, SkillResult

API_KEYWORDS = ["/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/swagger", "/openapi.json", "/actuator", "/docs"]


class ApiSurfaceAuditSkill(BaseSkill):
    name = "api_surface_audit"
    category = "analysis"
    description = "Audit API surface for GraphQL, Swagger, and exposed documentation"
    tools_required = []
    fallback_tools = []

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=True, tool_used="api_auditor")

        # Read endpoints from previous steps
        ep_file = ctx.state_files.get("endpoint_discovery", {})
        if isinstance(ep_file, dict):
            ep_path = ep_file.get("endpoints.txt", "")
        else:
            ep_path = ep_file

        discovered_api_routes: Set[str] = set()
        graphql_detected = False
        swagger_detected = False

        if ep_path and Path(ep_path).exists():
            content = Path(ep_path).read_text(encoding="utf-8")
            for line in content.splitlines():
                line = line.strip()
                if any(kw in line.lower() for kw in API_KEYWORDS):
                    discovered_api_routes.add(line)
                    if "graphql" in line.lower():
                        graphql_detected = True
                    if any(sw in line.lower() for sw in ("swagger", "openapi", "api-docs")):
                        swagger_detected = True

        lines = [
            f"# 📡 API & GraphQL Surface Audit for {ctx.target}",
            f"**Identified API Endpoints:** {len(discovered_api_routes)}",
            f"**GraphQL Detected:** {'YES' if graphql_detected else 'NO'}",
            f"**Swagger/OpenAPI Documentation Detected:** {'YES' if swagger_detected else 'NO'}",
            "",
            "---",
            "",
            "## Discovered API Endpoints & Routes",
        ]

        if not discovered_api_routes:
            lines.append("No specialized REST/GraphQL/Swagger endpoints identified in current crawl data.")
        else:
            for route in sorted(list(discovered_api_routes))[:50]:
                lines.append(f"- `{route}`")

        lines.extend([
            "",
            "---",
            "",
            "## 🛡️ Recommended API Hardening Practices",
            "1. **Disable Production Introspection:** Ensure GraphQL schema introspection is turned off on live environments.",
            "2. **Strict Object Ownership (BOLA):** Verify every request containing numeric or UUID references validates session permissions.",
            "3. **Disable Exposed API Docs:** Restrict public internet access to Swagger UI, OpenAPI JSON definitions, and Spring Actuator endpoints.",
        ])

        output_content = "\n".join(lines)
        p = ctx.workspace.write_file(
            ctx.target, "analysis", "api_surface_audit.txt", output_content, ctx.session_id
        )
        result.output_files["api_surface_audit.txt"] = str(p)

        if graphql_detected:
            result.add_finding(
                title=f"GraphQL Endpoint Identified ({ctx.target})",
                evidence="Identified active GraphQL endpoint in surface mapping.",
                severity="Info",
                vuln_type="graphql_introspection",
                recommendation="Disable introspection queries in production and enforce strict query depth limits."
            )

        if swagger_detected:
            result.add_finding(
                title=f"API Documentation / Swagger Interface Exposed ({ctx.target})",
                evidence="Identified accessible Swagger/OpenAPI documentation routes.",
                severity="Low",
                vuln_type="information_disclosure",
                recommendation="Protect API documentation behind internal VPN or authentication."
            )

        return result
