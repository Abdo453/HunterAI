"""
Browser Network Intelligence Skill
Intercepts live browser XHR/Fetch requests, extracted API endpoints, methods, and JSON payloads.
"""
from __future__ import annotations

import json
import urllib.parse
from pathlib import Path
from typing import Dict, List, Set

from core.browser.playwright_engine import PlaywrightEngine
from skills.base_skill import BaseSkill, SkillContext, SkillResult


class NetworkIntelligenceSkill(BaseSkill):
    name = "network_intelligence"
    category = "browser"
    description = "Intercept and analyze live browser XHR, Fetch, and background API traffic"
    timeout_seconds = 120.0
    max_retries = 2

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=True, tool_used="playwright_network")

        target_url = ctx.target if ctx.target.startswith("http") else f"https://{ctx.target}"
        engine = PlaywrightEngine(headless=True, timeout_seconds=45.0)

        inspection = await engine.inspect_url(
            url=target_url,
            simulate_interactions=True,
            auth_credentials=ctx.extra.get("auth", {})
        )

        requests_lines = []
        api_endpoints_set: Set[str] = set()
        parameters_set: Set[str] = set()
        responses_lines = []

        for req in inspection.network_requests:
            # 1. requests.txt
            requests_lines.append(f"[{req.method}] ({req.resource_type}) {req.url} -> Status: {req.response_status or 'N/A'}")

            # 2. Extract query parameters
            parsed = urllib.parse.urlparse(req.url)
            if parsed.query:
                params = urllib.parse.parse_qs(parsed.query)
                for p_name in params.keys():
                    parameters_set.add(f"{p_name} (in query of {parsed.path})")

            # 3. If POST body contains JSON, extract keys
            if req.post_data:
                try:
                    data = json.loads(req.post_data)
                    if isinstance(data, dict):
                        for k in data.keys():
                            parameters_set.add(f"{k} (in JSON body of {parsed.path})")
                except Exception:
                    pass

            # 4. Filter XHR/Fetch API endpoints
            if req.resource_type in ("xhr", "fetch") or "/api/" in req.url or "graphql" in req.url or req.url.endswith(".json"):
                api_endpoints_set.add(f"[{req.method}] {req.url}")
                if req.response_snippet:
                    responses_lines.append(f"### [{req.method} {req.response_status}] {req.url}\n```json\n{req.response_snippet[:400]}\n```\n")

        # Write output files to browser/network/
        p_req = ctx.workspace.write_file(
            ctx.target, "browser", "network/requests.txt",
            "\n".join(requests_lines) if requests_lines else "No requests intercepted.",
            ctx.session_id
        )
        result.output_files["requests.txt"] = str(p_req)

        p_api = ctx.workspace.write_file(
            ctx.target, "browser", "network/api_endpoints.txt",
            "\n".join(sorted(list(api_endpoints_set))) if api_endpoints_set else "No dynamic API endpoints captured.",
            ctx.session_id
        )
        result.output_files["api_endpoints.txt"] = str(p_api)

        p_params = ctx.workspace.write_file(
            ctx.target, "browser", "network/parameters.txt",
            "\n".join(sorted(list(parameters_set))) if parameters_set else "No dynamic parameters captured.",
            ctx.session_id
        )
        result.output_files["parameters.txt"] = str(p_params)

        p_resp = ctx.workspace.write_file(
            ctx.target, "browser", "network/responses.txt",
            "\n".join(responses_lines) if responses_lines else "No response bodies captured.",
            ctx.session_id
        )
        result.output_files["responses.txt"] = str(p_resp)

        if api_endpoints_set:
            result.add_finding(
                title=f"Dynamic XHR/Fetch API Endpoints Intercepted ({len(api_endpoints_set)})",
                evidence="\n".join(list(api_endpoints_set)[:15]),
                severity="Info",
                vuln_type="api_surface",
                recommendation="Audit dynamic API routes for Broken Object Level Authorization (BOLA/IDOR) and missing auth checks."
            )

        return result
