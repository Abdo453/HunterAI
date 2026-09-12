"""
JavaScript Static Analysis Skill
Analyzes JavaScript resources for sensitive endpoints, API patterns, and static secrets.
"""
from __future__ import annotations

import re
import urllib.parse
from pathlib import Path
from typing import List, Set, Tuple

import httpx

from skills.base_skill import BaseSkill, SkillContext, SkillResult

# Common patterns for API secrets, tokens, and keys
SECRET_PATTERNS = [
    (r"(?i)(?:api_key|apikey|app_key|access_token|auth_token|secret_key)[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9_\-\.]{16,})[\"']", "Potential API Key / Token"),
    (r"(?i)aws_access_key_id[\"']?\s*[:=]\s*[\"'](AKIA[0-9A-Z]{16})[\"']", "AWS Access Key ID"),
    (r"(?i)bearer\s+([a-zA-Z0-9_\-\.]{20,})", "Bearer Token"),
    (r"(?i)firebase[a-z_]*[\"']?\s*[:=]\s*[\"'](AIza[0-9A-Za-z\-_]{35})[\"']", "Firebase API Key"),
    (r"(?i)gh[pousr]_[0-9a-zA-Z]{36}", "GitHub Token Pattern"),
]

ENDPOINT_PATTERN = r"""(?:"|')((?:/[a-zA-Z0-9_\-\.]+)+|(?:https?://[a-zA-Z0-9_\-\./]+))(?:"|')"""


class JsAnalysisSkill(BaseSkill):
    name = "js_analysis"
    category = "web"
    description = "Static analysis of JavaScript files for endpoints and secrets"
    tools_required = []
    fallback_tools = ["nuclei"]

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=True, tool_used="static_js_analyzer")

        # Retrieve discovered URLs from previous crawling step if available
        urls_file = ctx.state_files.get("crawling", {})
        if isinstance(urls_file, dict):
            urls_path = urls_file.get("urls.txt", "")
        else:
            urls_path = urls_file

        js_urls: Set[str] = set()
        target = ctx.target if ctx.target.startswith("http") else f"http://{ctx.target}"

        if urls_path and Path(urls_path).exists():
            content = Path(urls_path).read_text(encoding="utf-8")
            for line in content.splitlines():
                line = line.strip()
                if line.endswith(".js") or ".js?" in line:
                    js_urls.add(line)

        # If no JS files discovered from crawl, check homepage HTML for script tags
        if not js_urls:
            try:
                async with httpx.AsyncClient(timeout=15.0, verify=False, trust_env=False) as client:
                    resp = await client.get(target)
                    if resp.status_code == 200:
                        scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', resp.text, re.IGNORECASE)
                        for s in scripts:
                            full_url = urllib.parse.urljoin(target, s)
                            js_urls.add(full_url)
            except Exception as e:
                self.logger.warning(f"Error fetching base target for script tags: {e}")

        if not js_urls:
            result.errors.append("No JavaScript URLs found to analyze")
            result.success = False
            return result

        discovered_secrets: List[Dict[str, str]] = []
        discovered_endpoints: Set[str] = set()

        async with httpx.AsyncClient(timeout=20.0, verify=False, trust_env=False) as client:
            for js_url in list(js_urls)[:25]:  # Limit to 25 JS files per run
                try:
                    resp = await client.get(js_url)
                    if resp.status_code != 200:
                        continue
                    text = resp.text

                    # 1. Search for secret patterns
                    for pattern, label in SECRET_PATTERNS:
                        matches = re.finditer(pattern, text)
                        for m in matches:
                            val = m.group(1) if m.groups() else m.group(0)
                            discovered_secrets.append({
                                "source": js_url,
                                "label": label,
                                "match": val[:60] + ("..." if len(val) > 60 else "")
                            })

                    # 2. Extract potential endpoints
                    ep_matches = re.findall(ENDPOINT_PATTERN, text)
                    for ep in ep_matches:
                        if ep.startswith("/") and len(ep) > 2 and not ep.endswith((".js", ".css", ".png", ".jpg", ".svg")):
                            discovered_endpoints.add(ep)
                        elif ep.startswith("http") and ctx.target in ep:
                            discovered_endpoints.add(ep)

                except Exception as e:
                    self.logger.debug(f"Failed to fetch JS {js_url}: {e}")

        # Save outputs
        secrets_lines = [f"[{s['label']}] in {s['source']}: {s['match']}" for s in discovered_secrets]
        p_sec = ctx.workspace.write_file(
            ctx.target, "web", "js_secrets.txt",
            "\n".join(secrets_lines) if secrets_lines else "No sensitive secret patterns detected.",
            ctx.session_id
        )
        result.output_files["js_secrets.txt"] = str(p_sec)

        endpoints_lines = sorted(list(discovered_endpoints))
        p_ep = ctx.workspace.write_file(
            ctx.target, "web", "js_endpoints.txt",
            "\n".join(endpoints_lines) if endpoints_lines else "No additional JS endpoints identified.",
            ctx.session_id
        )
        result.output_files["js_endpoints.txt"] = str(p_ep)

        if discovered_secrets:
            result.add_finding(
                title=f"Potential Hardcoded Secrets in JS ({len(discovered_secrets)})",
                evidence="\n".join(secrets_lines[:10]),
                severity="High",
                vuln_type="information_disclosure",
                recommendation="Remove hardcoded credentials and tokens from client-side bundles."
            )

        if endpoints_lines:
            result.add_finding(
                title=f"Endpoints Discovered in JavaScript ({len(endpoints_lines)})",
                evidence="\n".join(endpoints_lines[:20]),
                severity="Info",
                vuln_type="endpoint_discovery",
                recommendation="Review client-side endpoints for authorization controls."
            )

        return result
