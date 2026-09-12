"""
Perimeter Matrix Analysis Skill
Evaluates discovered assets against enterprise identity, SSL-VPN, and cloud metadata profiles.
"""
from __future__ import annotations

from pathlib import Path

from core.enterprise_perimeter import EnterprisePerimeterMatrix
from skills.base_skill import BaseSkill, SkillContext, SkillResult


class PerimeterMatrixSkill(BaseSkill):
    name = "perimeter_matrix"
    category = "analysis"
    description = "Enterprise perimeter and identity posture analysis"
    tools_required = []
    fallback_tools = []

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=True, tool_used="perimeter_matrix_engine")

        # Read tech detection or live hosts output
        tech_file = ctx.state_files.get("tech_detection", {})
        if isinstance(tech_file, dict):
            tech_path = tech_file.get("technologies.txt", "")
        else:
            tech_path = tech_file

        matched_profiles = []
        raw_tech = ""

        if tech_path and Path(tech_path).exists():
            raw_tech = Path(tech_path).read_text(encoding="utf-8")

        search_corpus = f"{ctx.target}\n{raw_tech}"
        for line in search_corpus.splitlines():
            line = line.strip()
            if not line:
                continue
            profile = EnterprisePerimeterMatrix.identify_profile(line)
            if profile and profile not in matched_profiles:
                matched_profiles.append(profile)

        lines = [
            f"# Enterprise Perimeter & Identity Analysis for {ctx.target}",
            f"**Total Identified Profiles:** {len(matched_profiles)}",
            "",
        ]

        if not matched_profiles:
            lines.append("No specialized enterprise SSO / SSL-VPN / Cloud Metadata signatures detected on external surface.")
        else:
            for p in matched_profiles:
                lines.extend([
                    f"## [{p.asset_type.upper()}] {p.vendor_platform}",
                    "### Audit & Security Focus:",
                ])
                for item in p.audit_focus:
                    lines.append(f"- {item}")
                lines.extend([
                    "",
                    f"**Remediation Guidance:** {p.remediation_guidance}",
                    "",
                    "---",
                ])

                result.add_finding(
                    title=f"Enterprise Asset Detected: {p.vendor_platform}",
                    evidence="\n".join(p.audit_focus),
                    severity="Medium",
                    vuln_type="enterprise_perimeter",
                    recommendation=p.remediation_guidance
                )

        output_content = "\n".join(lines)
        p = ctx.workspace.write_file(
            ctx.target, "analysis", "enterprise_perimeter_analysis.txt", output_content, ctx.session_id
        )
        result.output_files["enterprise_perimeter_analysis.txt"] = str(p)

        return result
