"""
Bug Bounty & Professional Multi-Format Reporter
توليد تقارير احترافية مخصصة لمنصات:
- HackerOne Markdown
- Bugcrowd Template
- Executive HTML & Print-Ready PDF Report
- CVSS v3.1 Calculator
"""
import os
import json
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path


class BugBountyReporter:
    """
    محرك تقارير الـ Bug Bounty المتقدم
    """

    def __init__(self, output_dir: str = "data/reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_hackerone_report(self, session_data: dict) -> str:
        """توليد تقرير احترافي مطابق لـ HackerOne Report Template"""
        target = session_data.get("target", "Target")
        findings = session_data.get("findings", [])
        date_str = datetime.now().strftime("%Y-%m-%d %H:%M UTC")

        lines = [
            f"# Security Vulnerability Assessment Report - {target}",
            f"**Report Date:** {date_str}  ",
            f"**Assessment Engine:** PentestAI Unified Framework  ",
            f"**Total Findings:** {len(findings)}",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            f"During the automated and AI-driven penetration test on **`{target}`**, a total of **{len(findings)}** security vulnerabilities were identified.",
            "",
        ]

        # Severity breakdown
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in findings:
            sev = f.get("severity", "Info")
            counts[sev] = counts.get(sev, 0) + 1

        lines.extend([
            "### Vulnerability Severity Breakdown",
            f"- 🔴 **Critical:** {counts['Critical']}",
            f"- 🟠 **High:** {counts['High']}",
            f"- 🟡 **Medium:** {counts['Medium']}",
            f"- 🟢 **Low:** {counts['Low']}",
            f"- 🔵 **Informational:** {counts['Info']}",
            "",
            "---",
            "",
            "## 2. Detailed Vulnerabilities & Steps to Reproduce",
            ""
        ])

        for idx, f in enumerate(findings, 1):
            title = f.get("title", f"Finding #{idx}")
            sev = f.get("severity", "Medium")
            cvss = f.get("cvss_score", 5.0)
            tool = f.get("tool", "Automated Probe")
            evidence = f.get("evidence", "N/A")
            remediation = f.get("recommendation", "Apply security patches and validate input.")

            lines.extend([
                f"### #{idx} - {title}",
                f"- **Severity:** `{sev}` (CVSS: `{cvss}`)",
                f"- **Vulnerability Class:** `{title.split(':')[0] if ':' in title else 'Security Weakness'}`",
                f"- **Affected Component:** `{target}`",
                f"- **Detection Tool:** `{tool}`",
                "",
                "#### Summary",
                f"{f.get('description', title)}",
                "",
                "#### Steps to Reproduce",
                f"1. Navigate to target URL: `{target}`",
                f"2. Execute the security probe using `{tool}` parameters.",
                f"3. Observe the response anomaly indicated below.",
                "",
                "#### Proof of Concept / Evidence",
                "```",
                evidence[:2000] if evidence else "No raw evidence available.",
                "```",
                "",
                "#### Impact",
                f"Exploitation of this vulnerability may allow attackers to compromise confidentiality, integrity, or availability on `{target}`.",
                "",
                "#### Remediation Recommendations",
                f"{remediation}",
                "",
                "---",
                ""
            ])

        report_content = "\n".join(lines)
        sid = session_data.get("id", "session")
        out_file = self.output_dir / f"{sid}_hackerone.md"
        out_file.write_text(report_content, encoding="utf-8")
        return str(out_file)

    def generate_executive_html(self, session_data: dict) -> str:
        """توليد تقرير HTML تنفيذي حديث قابل للطباعة PDF"""
        target = session_data.get("target", "Target")
        findings = session_data.get("findings", [])
        date_str = datetime.now().strftime("%B %d, %Y")

        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in findings:
            sev = f.get("severity", "Info")
            counts[sev] = counts.get(sev, 0) + 1

        findings_html = ""
        for i, f in enumerate(findings, 1):
            sev = f.get("severity", "Medium").lower()
            findings_html += f"""
            <div class="vuln-card sev-{sev}">
                <div class="vuln-header">
                    <span class="vuln-num">#{i}</span>
                    <span class="vuln-title">{f.get('title', 'Vulnerability')}</span>
                    <span class="badge badge-{sev}">{f.get('severity', 'Medium')}</span>
                    <span class="badge-cvss">CVSS {f.get('cvss_score', '5.0')}</span>
                </div>
                <div class="vuln-body">
                    <p><strong>Tool:</strong> {f.get('tool', 'Unknown')}</p>
                    <p><strong>Description:</strong> {f.get('description', f.get('title', ''))}</p>
                    <h4>Evidence:</h4>
                    <pre><code>{f.get('evidence', 'N/A')}</code></pre>
                    <h4>Remediation:</h4>
                    <p class="remediation">{f.get('recommendation', 'Review and patch.')}</p>
                </div>
            </div>
            """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Executive Pentest Report - {target}</title>
<style>
    body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #f8f9fa; color: #212529; margin: 0; padding: 40px; }}
    .container {{ max-width: 900px; margin: auto; background: #fff; padding: 40px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.08); }}
    .header {{ border-bottom: 2px solid #e9ecef; padding-bottom: 20px; margin-bottom: 30px; }}
    h1 {{ color: #dc3545; margin: 0 0 10px 0; font-size: 26px; }}
    .meta {{ color: #6c757d; font-size: 14px; }}
    .summary-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin: 25px 0; }}
    .summary-box {{ padding: 15px; border-radius: 6px; text-align: center; font-weight: bold; color: #fff; }}
    .box-crit {{ background: #dc3545; }}
    .box-high {{ background: #fd7e14; }}
    .box-med {{ background: #ffc107; color: #333; }}
    .box-low {{ background: #28a745; }}
    .box-info {{ background: #17a2b8; }}
    .vuln-card {{ border: 1px solid #dee2e6; border-radius: 6px; margin-bottom: 20px; overflow: hidden; page-break-inside: avoid; }}
    .vuln-header {{ background: #f8f9fa; padding: 12px 18px; display: flex; align-items: center; gap: 10px; border-bottom: 1px solid #dee2e6; }}
    .vuln-title {{ flex: 1; font-weight: 600; font-size: 15px; }}
    .vuln-body {{ padding: 18px; }}
    pre {{ background: #212529; color: #39ff14; padding: 12px; border-radius: 4px; overflow-x: auto; font-size: 12px; }}
    .badge {{ padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: bold; color: #fff; }}
    .badge-critical {{ background: #dc3545; }}
    .badge-high {{ background: #fd7e14; }}
    .badge-medium {{ background: #ffc107; color: #000; }}
    .badge-low {{ background: #28a745; }}
    .badge-info {{ background: #17a2b8; }}
    .badge-cvss {{ font-size: 12px; color: #6c757d; font-weight: 600; }}
    .remediation {{ background: #e8f5e9; border-left: 4px solid #28a745; padding: 10px 14px; border-radius: 0 4px 4px 0; color: #1b5e20; }}
    @media print {{
        body {{ background: #fff; padding: 0; }}
        .container {{ box-shadow: none; padding: 0; }}
        .no-print {{ display: none; }}
    }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>🛡️ PentestAI Unified - Executive Security Report</h1>
        <div class="meta">Target: <strong>{target}</strong> | Date: <strong>{date_str}</strong></div>
    </div>

    <h2>Executive Summary</h2>
    <div class="summary-grid">
        <div class="summary-box box-crit">Critical<br><span style="font-size:22px">{counts['Critical']}</span></div>
        <div class="summary-box box-high">High<br><span style="font-size:22px">{counts['High']}</span></div>
        <div class="summary-box box-med">Medium<br><span style="font-size:22px">{counts['Medium']}</span></div>
        <div class="summary-box box-low">Low<br><span style="font-size:22px">{counts['Low']}</span></div>
        <div class="summary-box box-info">Info<br><span style="font-size:22px">{counts['Info']}</span></div>
    </div>

    <h2>Vulnerability Findings ({len(findings)})</h2>
    {findings_html if findings else "<p style='color:#6c757d'>No high-risk vulnerabilities discovered during this scan.</p>"}
</div>
</body>
</html>"""

        sid = session_data.get("id", "session")
        out_file = self.output_dir / f"{sid}_executive.html"
        out_file.write_text(html, encoding="utf-8")
        return str(out_file)
