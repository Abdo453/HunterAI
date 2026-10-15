"""
HunterAI Report Engine
======================
Generates final assessment reports in Markdown, JSON, and SARIF formats.
"""
from __future__ import annotations

import json
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


class ReportEngine:
    """
    Builds structured assessment reports from:
      - FindingLifecycle or findings list
      - Attack surface metrics
      - Evidence graph summary
      - Request recorder summary
    """
    def __init__(self, target: str, scope: Optional[List[str]] = None, operator: str = "HunterAI"):
        self.target = target
        self.scope = list(scope or [target])
        self.operator = operator
        self.generated_at = datetime.now().isoformat()

    def build(
        self,
        findings: List[Dict[str, Any]],
        attack_surface: Dict[str, Any],
        evidence_summary: Any,
        request_summary: Any,
    ) -> Dict[str, Any]:
        """Builds master structured report dictionary."""
        sorted_findings = sorted(
            findings,
            key=lambda f: SEVERITY_ORDER.get(str(f.get("severity", "INFO")).upper(), 4)
        )
        critical = [f for f in sorted_findings if str(f.get("severity")).upper() == "CRITICAL"]
        high     = [f for f in sorted_findings if str(f.get("severity")).upper() == "HIGH"]
        medium   = [f for f in sorted_findings if str(f.get("severity")).upper() == "MEDIUM"]
        low      = [f for f in sorted_findings if str(f.get("severity")).upper() in ("LOW", "INFO")]

        overall_risk = "CRITICAL" if critical else ("HIGH" if high else ("MEDIUM" if medium else "LOW"))

        return {
            "meta": {
                "title": f"HunterAI Security Assessment — {self.target}",
                "target": self.target,
                "scope": self.scope,
                "operator": self.operator,
                "generated_at": self.generated_at,
                "overall_risk": overall_risk,
            },
            "executive_summary": self._generate_executive_summary(sorted_findings, overall_risk),
            "attack_surface": attack_surface,
            "findings": sorted_findings,
            "evidence": evidence_summary if isinstance(evidence_summary, dict) else {"summary": str(evidence_summary)},
            "requests": request_summary if isinstance(request_summary, dict) else {"summary": str(request_summary)},
            "counts": {
                "critical": len(critical),
                "high": len(high),
                "medium": len(medium),
                "low": len(low),
                "total": len(sorted_findings),
            },
        }

    def _generate_executive_summary(self, findings: List[Dict[str, Any]], risk: str) -> str:
        total = len(findings)
        if total == 0:
            return f"Security assessment for target '{self.target}' concluded with no confirmed vulnerabilities."
        top = findings[0]
        return (
            f"HunterAI completed an automated security assessment on target '{self.target}'. "
            f"The evaluation uncovered {total} confirmed finding(s) with an overall risk rating of {risk}. "
            f"The most severe issue identified is '{top.get('title', 'N/A')}' (Severity: {top.get('severity', 'UNKNOWN')}) "
            f"at endpoint '{top.get('endpoint', 'N/A')}'. Immediate remediation is advised."
        )

    def to_markdown(self, report: Dict[str, Any]) -> str:
        meta = report.get("meta", {})
        surf = report.get("attack_surface", {})
        findings = report.get("findings", [])
        counts = report.get("counts", {})

        lines = [
            f"# {meta.get('title', 'Security Assessment Report')}",
            f"",
            f"**Target:** `{meta.get('target', self.target)}`  ",
            f"**Operator:** {meta.get('operator', self.operator)}  ",
            f"**Date:** {meta.get('generated_at', '')}  ",
            f"**Overall Risk Rating:** **{meta.get('overall_risk', 'INFO')}**  ",
            f"",
            f"## Executive Summary",
            f"",
            f"{report.get('executive_summary', '')}",
            f"",
            f"## Findings Summary",
            f"",
            f"| Critical | High | Medium | Low | Total |",
            f"| :---: | :---: | :---: | :---: | :---: |",
            f"| {counts.get('critical', 0)} | {counts.get('high', 0)} | {counts.get('medium', 0)} | {counts.get('low', 0)} | {counts.get('total', 0)} |",
            f"",
            f"## Detailed Findings",
            f"",
        ]

        if not findings:
            lines.append("_No vulnerabilities confirmed._\n")

        for idx, f in enumerate(findings, 1):
            sev = f.get("severity", "INFO")
            lines.extend([
                f"### {idx}. [{sev}] {f.get('title', 'Finding')}",
                f"- **Finding ID:** `{f.get('finding_id', f'F-{idx:03d}')}`",
                f"- **Endpoint:** `{f.get('endpoint', 'N/A')}`",
                f"- **CVSS:** {f.get('cvss', 'N/A')}",
                f"- **Evidence / PoC:** {f.get('evidence', f.get('reproduction_steps', 'Available in Evidence Graph'))}",
                f"- **Remediation:** {f.get('recommendation', f.get('remediation', 'Apply proper authorization and input sanitization.'))}",
                f"",
            ])

        return "\n".join(lines)

    def to_json(self, report: Dict[str, Any]) -> str:
        return json.dumps(report, indent=2, default=str)

    def to_sarif(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Converts findings into standard SARIF 2.1.0 JSON format."""
        results = []
        for f in report.get("findings", []):
            level = {
                "CRITICAL": "error",
                "HIGH": "error",
                "MEDIUM": "warning",
                "LOW": "note",
            }.get(str(f.get("severity", "INFO")).upper(), "none")

            results.append({
                "ruleId": f.get("finding_id", "F-UNKNOWN"),
                "level": level,
                "message": {"text": f.get("title", "")},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.get("endpoint", "/")}
                    }
                }],
            })

        return {
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.4.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "HunterAI",
                        "version": "2.0.0",
                        "informationUri": "https://github.com/Abdo453/HunterAI",
                    }
                },
                "results": results,
            }],
        }
