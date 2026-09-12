"""
Browser Form Intelligence Skill
Categorizes application forms and builds an authentication and interactive action surface map.
"""
from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List

from core.browser.playwright_engine import PlaywrightEngine
from skills.base_skill import BaseSkill, SkillContext, SkillResult


class FormIntelligenceSkill(BaseSkill):
    name = "form_intelligence"
    category = "browser"
    description = "Categorize application forms and build authentication & action surface map"
    timeout_seconds = 90.0
    max_retries = 2

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=True, tool_used="form_analyzer")

        target_url = ctx.target if ctx.target.startswith("http") else f"https://{ctx.target}"
        engine = PlaywrightEngine(headless=True, timeout_seconds=30.0)

        inspection = await engine.inspect_url(
            url=target_url,
            simulate_interactions=False,
            auth_credentials=ctx.extra.get("auth", {})
        )

        forms_dict_list = [asdict(f) for f in inspection.forms]

        # Write forms_map.json
        p_json = ctx.workspace.write_file(
            ctx.target, "browser", "forms_map.json",
            json.dumps(forms_dict_list, indent=2),
            ctx.session_id
        )
        result.output_files["forms_map.json"] = str(p_json)

        # Build auth_surface.txt
        auth_forms = [f for f in inspection.forms if f.purpose_guess in ("login", "register", "password_reset")]
        auth_lines = [
            f"# Authentication & Sensitive Form Surface for {ctx.target}",
            f"**Total Auth Forms Identified:** {len(auth_forms)}",
            "",
            "---",
            "",
        ]

        if not auth_forms:
            auth_lines.append("No dedicated login / registration / password reset forms identified on root page.")
        else:
            for f in auth_forms:
                auth_lines.extend([
                    f"## [{f.purpose_guess.upper()}] Form",
                    f"- **Action Target:** `{f.action}`",
                    f"- **HTTP Method:** `{f.method}`",
                    f"- **Input Fields:**",
                ])
                for field in f.fields:
                    auth_lines.append(f"  - `{field.name}` (type={field.field_type}, required={field.required})")
                auth_lines.append("")

                result.add_finding(
                    title=f"Authentication Surface Identified: {f.purpose_guess.upper()}",
                    evidence=f"Form Action: {f.action} | Method: {f.method} | Inputs: {[fld.name for fld in f.fields]}",
                    severity="Info",
                    vuln_type="auth_surface",
                    recommendation="Ensure rate limiting, brute-force defenses, and CSRF protection are enforced on authentication routes."
                )

        p_auth = ctx.workspace.write_file(
            ctx.target, "browser", "auth_surface.txt",
            "\n".join(auth_lines),
            ctx.session_id
        )
        result.output_files["auth_surface.txt"] = str(p_auth)

        return result
