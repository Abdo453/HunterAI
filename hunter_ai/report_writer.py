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
                "severity": "Medium",
                "vulnerability_type": "Other",
                "description": "",
                "steps_to_reproduce": [],
                "impact": "",
                "remediation": "",
                "evidence": {},
            }
        else:
            finding = dict(finding)

        target_val = finding.get("target") or target
        finding["target"] = target_val
        report_id = str(uuid.uuid4())[:8]
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        vuln_type = (
            finding.get("vulnerability_type")
            or finding.get("vuln_class")
            or finding.get("vuln_type")
            or finding.get("type")
            or finding.get("cwe")
            or "Other"
        )
        severity = finding.get("severity") or self._infer_severity(str(vuln_type), str(finding.get("title", "")))
        raw_title = str(finding.get("title") or "Untitled").strip()
        clean_title = raw_title
        for suffix in (f" on {target_val}", f" - {target_val}", f" — {target_val}"):
            if clean_title.endswith(suffix):
                clean_title = clean_title[: -len(suffix)].strip()

        confidence = float(finding.get("confidence", 0.9) or 0.9)
        summary = (
            finding.get("description")
            or finding.get("summary")
            or f"Verified `{vuln_type}` security finding (`{clean_title}`) affecting `{target_val}` "
               f"(verification confidence: {int(confidence * 100)}%)."
        )
        impact = finding.get("impact") or self._default_impact(str(vuln_type), target_val)
        steps = finding.get("steps_to_reproduce") or self._default_steps(target_val, str(vuln_type), finding)
        remediation = (
            finding.get("remediation")
            or finding.get("recommendation")
            or self._default_remediation(str(vuln_type))
        )

        report = {
            "report_id": report_id,
            "platform": self.platform,
            "target": target_val,
            "title": self.config["title_template"].format(
                severity=severity,
                title=clean_title,
                target=target_val,
            ),
            "vulnerability_type": vuln_type,
            "severity": severity,
            "summary": summary,
            "impact": impact,
            "steps_to_reproduce": steps,
            "remediation": remediation,
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

    @staticmethod
    def _infer_severity(vuln_type: str, title: str) -> str:
        combined = f"{vuln_type} {title}".lower()
        if any(k in combined for k in ("rce", "command_injection", "sql", "ssrf", "jwt", "secret", "aws", "stripe", "unauthenticated admin")):
            return "Critical"
        if any(k in combined for k in ("idor", "bola", "bfla", "xss", "traversal", "lfi", "smuggling", "cache_poisoning", "prototype_pollution", "mass_assignment", "oauth")):
            return "High"
        if any(k in combined for k in ("info", "banner", "header")):
            return "Low"
        return "Medium"

    @staticmethod
    def _default_impact(vuln_type: str, target: str) -> str:
        vt = vuln_type.lower()
        if "xss" in vt:
            return f"An attacker can execute arbitrary JavaScript in the victim's browser context on `{target}`, enabling session hijacking, token theft, or unauthorized state-changing actions."
        if "idor" in vt or "bola" in vt or "bfla" in vt or "auth" in vt:
            return f"An attacker can bypass authorization controls on `{target}` to access or modify resources belonging to other users or administrative roles."
        if "ssrf" in vt:
            return f"An attacker can coerce `{target}` into issuing server-side requests to internal services or cloud metadata endpoints, potentially exposing internal credentials."
        if "sql" in vt:
            return f"An attacker can manipulate backend database queries on `{target}`, risking unauthorized data extraction or authentication bypass."
        if "jwt" in vt:
            return f"An attacker can forge or tamper with JWT authentication tokens accepted by `{target}`, achieving privilege escalation or account takeover."
        if "secret" in vt or "sensitive" in vt:
            return f"Exposed credentials or sensitive keys on `{target}` allow unauthorized access to backend infrastructure or third-party services."
        return f"Exploitation of this `{vuln_type}` vulnerability on `{target}` compromises confidentiality, integrity, or access control boundaries."

    @staticmethod
    def _default_steps(target: str, vuln_type: str, finding: dict[str, Any]) -> list[str]:
        steps = [f"Navigate to or send a request to the target endpoint: `{target}`."]
        payload = finding.get("payload") or finding.get("payload_used")
        if payload:
            steps.append(f"Supply the verification payload / input: `{payload}`.")
        evidence = finding.get("evidence")
        if isinstance(evidence, str) and evidence.strip():
            first_line = evidence.strip().splitlines()[0][:180]
            steps.append(f"Observe the anomalous server/client behavior confirming `{vuln_type}`: `{first_line}`.")
        else:
            steps.append(f"Observe the response confirming `{vuln_type}` in the Evidence section below.")
        return steps

    @staticmethod
    def _default_remediation(vuln_type: str) -> str:
        vt = vuln_type.lower()
        if "xss" in vt:
            return "Contextually encode all user-supplied input before rendering, replace dangerous DOM sinks (`innerHTML`, `eval`, `document.write`) with `textContent` or `DOMPurify`, and enforce a strict Content-Security-Policy (CSP)."
        if "idor" in vt or "bola" in vt or "bfla" in vt:
            return "Enforce server-side object-level and function-level authorization checks on every request using the authenticated session identity rather than client-supplied identifiers."
        if "ssrf" in vt:
            return "Validate and allowlist permitted destination hosts/schemes, disable redirects to internal/private IP ranges (RFC 1918 / RFC 3927 / 169.254.169.254), and route outbound fetches through an egress proxy."
        if "sql" in vt:
            return "Use parameterized queries (prepared statements) for all database access and disable verbose database error messages in production."
        if "jwt" in vt:
            return "Reject the `none` algorithm, explicitly allowlist expected signing algorithms, validate cryptographic signatures server-side, and use high-entropy secrets or asymmetric keys."
        if "cors" in vt:
            return "Avoid reflecting arbitrary `Origin` headers or combining wildcard origins with `Access-Control-Allow-Credentials: true`; enforce a strict origin allowlist."
        return "Validate and sanitize all untrusted inputs, enforce strict server-side authorization and security headers, and remove sensitive debug/credential data from responses."

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
