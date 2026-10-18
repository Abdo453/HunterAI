"""
HunterAI Report Writer — Submission-Ready Reports
=================================================
Generates reports ready for submission to:
- HackerOne
- Bugcrowd
- Intigriti
- Immunefi

Impact-first reports that get paid, not N/A'd.
"""
from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Optional


class ReportWriter:
    PLATFORMS = {
        "hackerone": {
            "title_template": "[{severity}] {title} on {target}",
            "sections": ["summary", "impact", "steps_to_reproduce", "remediation", "references"],
        },
        "bugcrowd": {
            "title_template": "{severity}: {title} - {target}",
            "sections": ["summary", "impact", "proof_of_concept", "remediation"],
        },
        "intigriti": {
            "title_template": "{title} ({severity}) — {target}",
            "sections": ["summary", "impact", "steps_to_reproduce", "remediation"],
        },
        "immunefi": {
            "title_template": "[{severity}] {title} — {target}",
            "sections": ["summary", "impact", "steps_to_reproduce", "remediation", "references"],
        },
    }

    def __init__(self, platform: str = "hackerone"):
        if platform not in self.PLATFORMS:
            raise ValueError(f"Unknown platform: {platform}")
        self.platform = platform
        self.config = self.PLATFORMS[platform]

    def generate(
        self,
        target: str,
        finding: str | dict[str, Any],
        output_dir: str = "data/reports",
    ) -> str:
        """Generate a submission-ready report."""
        if isinstance(finding, str):
            finding = {
                "title": finding,
                "target": target,
                "severity": "medium",
                "vulnerability_type": "Other",
                "description": "",
                "steps_to_reproduce": [],
                "impact": "",
                "remediation": "",
                "evidence": {},
            }

        finding["target"] = finding.get("target", target)
        report_id = str(uuid.uuid4())[:8]
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        report = {
            "report_id": report_id,
            "platform": self.platform,
            "target": finding["target"],
            "title": self.config["title_template"].format(
                severity=finding.get("severity", "Medium"),
                title=finding.get("title", "Untitled"),
                target=finding["target"],
            ),
            "vulnerability_type": finding.get("vulnerability_type", "Other"),
            "severity": finding.get("severity", "Medium"),
            "summary": finding.get("description", ""),
            "impact": finding.get("impact", ""),
            "steps_to_reproduce": finding.get("steps_to_reproduce", []),
            "remediation": finding.get("remediation", ""),
            "evidence": finding.get("evidence", {}),
            "generated_at": timestamp,
            "report_ready": True,
        }

        Path(output_dir).mkdir(parents=True, exist_ok=True)
        path = Path(output_dir) / f"{self.platform}_{report_id}.json"
        path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

        # Also generate Markdown version
        md_path = Path(output_dir) / f"{self.platform}_{report_id}.md"
        md_path.write_text(self._to_markdown(report), encoding="utf-8")

        return str(path)

    def _to_markdown(self, report: dict[str, Any]) -> str:
        lines = [
            f"# {report['title']}",
            "",
            f"**Platform:** {report['platform']}",
            f"**Target:** {report['target']}",
            f"**Severity:** {report['severity']}",
            f"**Vulnerability Type:** {report['vulnerability_type']}",
            f"**Report ID:** {report['report_id']}",
            f"**Generated:** {report['generated_at']}",
            "",
            "## Summary",
            report["summary"],
            "",
            "## Impact",
            report["impact"],
            "",
            "## Steps to Reproduce",
        ]
        for i, step in enumerate(report["steps_to_reproduce"], 1):
            lines.append(f"{i}. {step}")
        lines.extend(
            [
                "",
                "## Remediation",
                report["remediation"],
                "",
                "## Evidence",
                json.dumps(report["evidence"], indent=2, ensure_ascii=False),
            ]
        )
        return "\n".join(lines)
