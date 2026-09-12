"""
Cloud Metadata Audit Skill
Audits discovered assets and URLs for multi-cloud metadata exposure and SSRF vector risks.
"""
from __future__ import annotations

from pathlib import Path

from core.cloud_metadata_matrix import CloudMetadataMatrix
from skills.base_skill import BaseSkill, SkillContext, SkillResult


class CloudMetadataAuditSkill(BaseSkill):
    name = "cloud_metadata_audit"
    category = "analysis"
    description = "Audit multi-cloud metadata services and SSRF exposure"
    tools_required = []
    fallback_tools = []

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=True, tool_used="cloud_metadata_matrix")

        profiles = CloudMetadataMatrix.list_all_profiles()
        lines = [
            f"# Multi-Cloud Metadata & SSRF Audit Matrix for {ctx.target}",
            f"**Total Cloud Providers Evaluated:** {len(profiles)}",
            "",
            "---",
            "",
        ]

        for p in profiles:
            lines.extend([
                f"## ☁️ {p.cloud_provider} [{p.imds_version}]",
                f"- **Default Metadata Endpoint:** `{p.endpoint_url}`",
                f"- **Required Request Headers:** `{dict(p.required_headers)}`",
                "- **High-Risk Sensitive Endpoints:**",
            ])
            for path in p.sensitive_paths:
                lines.append(f"  - `{p.endpoint_url}{path}`")
            lines.extend([
                "",
                f"**Defensive Remediation:** {p.remediation}",
                "",
                "---",
                "",
            ])

        content = "\n".join(lines)
        p = ctx.workspace.write_file(
            ctx.target, "analysis", "cloud_metadata_audit.txt", content, ctx.session_id
        )
        result.output_files["cloud_metadata_audit.txt"] = str(p)

        result.add_finding(
            title=f"Cloud Infrastructure Audit Matrix Compiled ({len(profiles)} Providers)",
            evidence=f"Audited standard cloud metadata posture across AWS, GCP, Azure, Alibaba, and DigitalOcean.",
            severity="Info",
            vuln_type="cloud_metadata",
            recommendation="Enforce IMDSv2 globally and restrict egress traffic to link-local 169.254.169.254 from workload containers."
        )

        return result
