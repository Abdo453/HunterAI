"""
Browser Recon Skill
Headless browser reconnaissance extracting DOM elements, forms, links, cookies, storage, and screenshots.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import List

from core.browser.playwright_engine import PlaywrightEngine
from skills.base_skill import BaseSkill, SkillContext, SkillResult


class BrowserReconSkill(BaseSkill):
    name = "browser_recon"
    category = "browser"
    description = "Headless browser DOM, links, scripts, cookies, storage, and screenshot capture"
    timeout_seconds = 120.0
    max_retries = 2

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=True, tool_used="playwright_browser")

        target_url = ctx.target if ctx.target.startswith("http") else f"https://{ctx.target}"
        ws_path = ctx.workspace.get_workspace_path(ctx.target, ctx.session_id)
        ss_path = ws_path / "screenshots" / "initial.png"

        engine = PlaywrightEngine(headless=True, timeout_seconds=45.0)
        inspection = await engine.inspect_url(
            url=target_url,
            screenshot_destination=ss_path,
            simulate_interactions=True,
            auth_credentials=ctx.extra.get("auth", {})
        )

        if not inspection.title and inspection.status_code == 0:
            result.errors.append(f"Browser navigation to {target_url} returned no response.")
            result.success = False
            return result

        # 1. pages.txt
        pages_content = f"Title: {inspection.title}\nInitial URL: {inspection.target_url}\nFinal URL: {inspection.final_url}\nHTTP Status: {inspection.status_code}\n"
        p_pages = ctx.workspace.write_file(ctx.target, "browser", "pages.txt", pages_content, ctx.session_id)
        result.output_files["pages.txt"] = str(p_pages)

        # 2. links.txt
        links_content = "\n".join(sorted(inspection.links)) if inspection.links else "No links found."
        p_links = ctx.workspace.write_file(ctx.target, "browser", "links.txt", links_content, ctx.session_id)
        result.output_files["links.txt"] = str(p_links)

        # 3. scripts.txt
        scripts_content = "\n".join(sorted(inspection.scripts)) if inspection.scripts else "No external scripts found."
        p_scripts = ctx.workspace.write_file(ctx.target, "browser", "scripts.txt", scripts_content, ctx.session_id)
        result.output_files["scripts.txt"] = str(p_scripts)

        # 4. forms.txt
        forms_lines = []
        for f in inspection.forms:
            fields_str = ", ".join(f"{fld.name} ({fld.field_type})" for fld in f.fields)
            forms_lines.append(f"[{f.method}] Action: {f.action} | Purpose: {f.purpose_guess} | Fields: [{fields_str}]")
        forms_content = "\n".join(forms_lines) if forms_lines else "No HTML forms detected."
        p_forms = ctx.workspace.write_file(ctx.target, "browser", "forms.txt", forms_content, ctx.session_id)
        result.output_files["forms.txt"] = str(p_forms)

        # 5. inputs.txt
        inputs_lines = [f"{i.name} ({i.field_type}) id={i.id} placeholder='{i.placeholder}' required={i.required}" for i in inspection.inputs]
        inputs_content = "\n".join(inputs_lines) if inputs_lines else "No standalone input fields."
        p_inputs = ctx.workspace.write_file(ctx.target, "browser", "inputs.txt", inputs_content, ctx.session_id)
        result.output_files["inputs.txt"] = str(p_inputs)

        # 6. cookies.txt & storage.txt
        cookies_lines = [f"{c.get('name')}={c.get('value')[:30]}... (domain={c.get('domain')}, secure={c.get('secure')}, httpOnly={c.get('httpOnly')})" for c in inspection.cookies]
        p_cookies = ctx.workspace.write_file(ctx.target, "browser", "cookies.txt", "\n".join(cookies_lines) if cookies_lines else "No cookies set.", ctx.session_id)
        result.output_files["cookies.txt"] = str(p_cookies)

        storage_data = {"localStorage": inspection.local_storage, "sessionStorage": inspection.session_storage}
        p_storage = ctx.workspace.write_file(ctx.target, "browser", "storage.txt", json.dumps(storage_data, indent=2), ctx.session_id)
        result.output_files["storage.txt"] = str(p_storage)

        # Add findings
        insecure_cookies = [c for c in inspection.cookies if not c.get("secure") or not c.get("httpOnly")]
        if insecure_cookies:
            result.add_finding(
                title=f"Insecure Cookie Flags Identified ({len(insecure_cookies)})",
                evidence="\n".join(f"- {c.get('name')} (Secure={c.get('secure')}, HttpOnly={c.get('httpOnly')})" for c in insecure_cookies),
                severity="Low",
                vuln_type="cookie_misconfiguration",
                recommendation="Enforce Secure, HttpOnly, and SameSite attributes on all session cookies."
            )

        result.add_finding(
            title=f"Browser Surface Mapped: {inspection.title}",
            evidence=f"Discovered {len(inspection.links)} links, {len(inspection.forms)} forms, {len(inspection.scripts)} scripts, and {len(inspection.cookies)} cookies.",
            severity="Info",
            vuln_type="browser_surface",
            recommendation="Review discovered forms and interactive elements for access control and input validation."
        )

        return result
