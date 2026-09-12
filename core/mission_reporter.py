"""
Mission Reporter — منشئ التقارير الشاملة للمهمة
يجمع كل نتائج المهارات، الأدلة، والملفات المكتشفة مع حساب الـ CVSS الدقيق والـ Health Score والـ Timeline.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.cvss_calculator import CVSSCalculator
from core.evidence_manager import EvidenceManager
from core.evidence_sanitizer import EvidenceSanitizer
from core.mission_state import MissionState
from core.seven_question_gate import SevenQuestionGate
from core.vrt_mapper import VRTMapper
from core.workspace_manager import WorkspaceManager


class MissionReporter:
    """
    يولّد التقرير الختامي للمهمة المستقلة مع تنظيم النتائج والتوصيات
    """

    def __init__(self, workspace: WorkspaceManager, evidence_mgr: Optional[EvidenceManager] = None):
        self.ws = workspace
        self.evidence_mgr = evidence_mgr or EvidenceManager()

    def generate_report(self, state: MissionState) -> Path:
        """توليد ملف final_report.md وملف summary.json"""
        report_path = self.ws.get_report_path(state.target, state.session_id)
        report_path.parent.mkdir(parents=True, exist_ok=True)

        elapsed_sec = round(time.time() - state.started_at, 1)
        files = self.ws.list_files(state.target, session_id=state.session_id)

        # Categorize findings
        crit = [f for f in state.findings if f.get("severity", "").lower() == "critical" or (f.get("cvss_score") or 0.0) >= 9.0]
        high = [f for f in state.findings if f.get("severity", "").lower() == "high" or (7.0 <= (f.get("cvss_score") or 0.0) < 9.0)]
        med = [f for f in state.findings if f.get("severity", "").lower() == "medium" or (4.0 <= (f.get("cvss_score") or 0.0) < 7.0)]
        low_info = [f for f in state.findings if f not in crit and f not in high and f not in med]

        lines = [
            f"# 🛡️ Autonomous Security Assessment Report: `{state.target}`",
            "",
            "| Property | Value |",
            "|---|---|",
            f"| **Target** | `{state.target}` |",
            f"| **Session ID** | `{state.session_id}` |",
            f"| **Execution Mode** | `{state.mode}` |",
            f"| **Status** | `{state.status.upper()}` |",
            f"| **Health Score** | `{state.health_score:.1f}%` |",
            f"| **Elapsed Time** | {elapsed_sec}s |",
            f"| **Completed Skills** | {len(state.completed_skills)} |",
            f"| **Failed Skills** | {len(state.failed_skills)} |",
            f"| **Total Findings** | {state.findings_count} |",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            f"An automated security assessment was performed against `{state.target}` using the modular Autonomous Mission Agent pipeline.",
            f"Mission achieved a **{state.health_score:.1f}%** health rating over **{len(state.completed_skills)}** completed skills.",
            f"- 🔴 **Critical (CVSS >= 9.0):** {len(crit)}",
            f"- 🟠 **High (CVSS 7.0-8.9):** {len(high)}",
            f"- 🟡 **Medium (CVSS 4.0-6.9):** {len(med)}",
            f"- 🔵 **Low / Info (CVSS < 4.0):** {len(low_info)}",
            "",
            "---",
            "",
            "## 2. Mission Phases & Execution Status",
        ]

        for s in state.completed_skills:
            retries = state.retry_counts.get(s, 0)
            retry_tag = f" *(Retried {retries}x)*" if retries > 0 else ""
            lines.append(f"- [x] `{s}`{retry_tag}")
        for s in state.failed_skills:
            retries = state.retry_counts.get(s, 0)
            lines.append(f"- [ ] `[FAILED] {s}` *(Attempts: {retries + 1})*")

        if state.timeline:
            lines.extend([
                "",
                "### 2.1 Execution Timeline",
                "| Time | Event | Details |",
                "|---|---|---|",
            ])
            for ev in state.timeline[-15:]:  # show recent 15 events
                t_str = ev.get("time_str", "-")
                e_type = ev.get("event", "-")
                dt = ev.get("details", {})
                detail_str = ", ".join(f"{k}={v}" for k, v in dt.items())
                lines.append(f"| {t_str} | `{e_type}` | {detail_str[:60]} |")

        lines.extend([
            "",
            "---",
            "",
            "## 3. Findings & Security Observations",
        ])

        if not state.findings:
            lines.append("*No security findings or informational observations recorded.*")
        else:
            for idx, f in enumerate(state.findings, 1):
                vuln_type = f.get("type", "general")
                vrt = VRTMapper.lookup(vuln_type)
                gate_eval = SevenQuestionGate.evaluate_finding(f)

                cvss_val = f.get("cvss_score") or CVSSCalculator.derive_from_vrt(vrt.vrt_id, f.get("severity", "Info"))
                sev = f.get("severity", VRTMapper.priority_to_severity(vrt.priority)).upper()
                title = f.get("title", "Observation")
                tool = f.get("tool", "AutonomousAgent")
                evidence = EvidenceSanitizer.sanitize(f.get("evidence", "").strip())
                rec = f.get("recommendation", "")

                lines.extend([
                    f"### 3.{idx}. [{sev} / {vrt.priority} / CVSS {cvss_val:.1f}] {title}",
                    f"- **VRT Taxonomy:** `{vrt.vrt_id}` ({vrt.subcategory})",
                    f"- **CWE Classification:** `{vrt.cwe}`",
                    f"- **CVSS v3.1 Score:** `{cvss_val:.1f}`",
                    f"- **7-Question Gate Score:** `{gate_eval.score:.0%}` ({'PASSED' if gate_eval.passed else 'FLAGGED'})",
                    f"- **Tool / Source:** `{tool}`",
                ])
                if f.get("url"):
                    lines.append(f"- **URL:** `{EvidenceSanitizer.sanitize(f['url'])}`")
                if evidence:
                    lines.extend([
                        "",
                        "**Evidence (Sanitized):**",
                        "```",
                        evidence[:1500],
                        "```",
                    ])
                if rec:
                    lines.extend([
                        "",
                        f"**Remediation Recommendation:** {rec}",
                    ])
                lines.append("")

        lines.extend([
            "---",
            "",
            "## 4. Generated Artifacts & File Workspace",
            "| Category | File Name | Size (Bytes) |",
            "|---|---|---|",
        ])
        for file_info in files:
            lines.append(f"| {file_info.get('category', '-')} | `{file_info.get('name', '-')}` | {file_info.get('size', 0)} |")

        lines.extend([
            "",
            "---",
            "",
            "## 5. Strategic Hardening Recommendations",
            "1. **Defense-in-Depth:** Enforce strict access control policies on all identified internal/administrative endpoints.",
            "2. **Headers & Banners:** Disable software version headers (e.g. `Server`, `X-Powered-By`) across all HTTP services.",
            "3. **Secrets Hygiene:** Regularly audit JavaScript codebases and repository check-ins for inadvertently exposed credentials or keys.",
            "",
            "---",
            f"*Report compiled automatically by PentestAI Unified Framework at {time.strftime('%Y-%m-%d %H:%M:%S')}.*",
        ])

        content = "\n".join(lines)
        report_path.write_text(content, encoding="utf-8")

        # Also write summary.json
        summary_path = report_path.parent / "summary.json"
        summary_data = {
            "session_id": state.session_id,
            "target": state.target,
            "mode": state.mode,
            "status": state.status,
            "health_score": state.health_score,
            "elapsed_seconds": elapsed_sec,
            "skills_completed": state.completed_skills,
            "skills_failed": state.failed_skills,
            "retry_counts": state.retry_counts,
            "findings_count": state.findings_count,
            "findings": state.findings,
            "artifacts_count": len(files),
        }
        summary_path.write_text(json.dumps(summary_data, indent=2, ensure_ascii=False), encoding="utf-8")

        return report_path
