"""
Network Report Generator — Phase 5 (Court / Reports)

يُنتج تقارير نهائية من نتائج محكمة الشبكة (NetworkCourtReport):
* JSON — تقرير هيكلي آلي المعالجة
* Markdown — تقرير تقني نمط تقارير المكافآت (Bug Bounty)
* SARIF v2.1.0 — متوافق مع GitHub Code Scanning
* HTML — تقرير تنفيذي تفاعلي مع مساحة سلبية وختم تشفيري

مبدأ الإ inclusion: لا يُدرج إلا الاكتشافات المؤكدة (CONFIRMED + DERIVED proof).
كل ما دون ذلك يُذكر في قسم "مستغرق للتحقق" وليس كثغرة مؤكدة.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.reporting.network_court_adjudicator import (
    CourtAdjudicationResult,
    NegativeSpaceEntry,
    NetworkCourtReport,
)
from core.reporting.bounty_and_sarif_exporter import (
    BountyReportGenerator,
    SARIFExporter,
)
from core.reporting.cvss_report_engine import CVSSReportEngine, CVSSv31Calculator
from core.reporting.html_reporter import HTMLReportGenerator
from core.security.report_signer import ReportSignature, ReportSigner


def _cvss_for_severity(severity: str) -> Dict[str, Any]:
    """يحول درجة خطورة نصية إلى حساب CVSS v3.1 افتراضي (إن لم يُزوّد المكتشف بقيمة)."""
    sev = (severity or "MEDIUM").upper()
    if sev == "CRITICAL":
        return CVSSv31Calculator.calculate_base_score(
            av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H"
        )
    if sev == "HIGH":
        return CVSSv31Calculator.calculate_base_score(
            av="N", ac="L", pr="N", ui="N", s="U", c="H", i="L", a="N"
        )
    if sev == "MEDIUM":
        return CVSSv31Calculator.calculate_base_score(
            av="N", ac="L", pr="N", ui="R", s="U", c="L", i="L", a="N"
        )
    if sev == "LOW":
        return CVSSv31Calculator.calculate_base_score(
            av="N", ac="H", pr="L", ui="R", s="U", c="L", i="N", a="N"
        )
    return {"score": 0.0, "severity": "Info", "vector": "N/A"}


class NetworkReportGenerator:
    """
    يولّد تقارير نهائية من تقرير محكمة الشبكة.
    """

    def __init__(self, output_dir: str = "data/reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.signer = ReportSigner()

    # ── public API ────────────────────────────────────────────────────────────

    def generate(
        self,
        report: NetworkCourtReport,
        target_name: str,
        formats: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        يُنتج التق렬 بالصيغ المطلوبة (افتراضيًا: json + markdown + sarif + html).
        يعيد مسارات الملفات المُنشأة والبيانات المجمعة للتوقيع.
        """
        formats = formats or ["json", "markdown", "sarif", "html"]
        produced: Dict[str, str] = {}

        confirmed = report.confirmed
        unconfirmed = report.unconfirmed
        false_positives = report.false_positive_list
        negative_space = report.negative_space

        # بيانات التجميع للتوقيع
        aggregate_data = {
            "target": report.target,
            "confirmed_count": len(confirmed),
            "unconfirmed_count": len(unconfirmed),
            "false_positive_count": len(false_positives),
            "negative_space_count": len(negative_space),
            "confirmation_rate": report.confirmation_rate,
            "generated_at": report.generated_at,
        }

        if "json" in formats:
            produced["json"] = self._write_json(report, target_name)
        if "markdown" in formats:
            produced["markdown"] = self._write_markdown(report, target_name)
        if "sarif" in formats:
            produced["sarif"] = self._write_sarif(report, target_name)
        if "html" in formats:
            produced["html"] = self._write_html(report, target_name, aggregate_data)

        # ختم تشفيري على البيانات المجمعة
        signature = self.signer.sign_report(aggregate_data)
        produced["signature"] = {
            "algorithm": signature.algorithm,
            "digest": signature.digest,
            "signed_at": signature.signed_at,
            "item_count": signature.item_count,
            "signer_identity": signature.signer_identity,
        }

        return {
            "target": report.target,
            "formats": produced,
            "summary": aggregate_data,
            "signature": produced["signature"],
        }

    # ── writers ──────────────────────────────────────────────────────────────

    def _write_json(self, report: NetworkCourtReport, target_name: str) -> str:
        safe = self._safe_name(target_name)
        path = self.output_dir / f"{safe}_network_report.json"
        payload = report.to_dict()
        # إضافة CVSS لكل اكتشاف مؤكد
        for item in payload.get("confirmed", []):
            item["cvss"] = _cvss_for_severity(item["severity"])
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return str(path)

    def _write_markdown(self, report: NetworkCourtReport, target_name: str) -> str:
        safe = self._safe_name(target_name)
        path = self.output_dir / f"{safe}_network_report.md"

        lines: List[str] = []
        lines.append(f"# HunterAI Network Assessment Report — {target_name}")
        lines.append("")
        lines.append(f"- **التاريخ:** {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(report.generated_at))}")
        lines.append(f"- **إجمالي الاكتشافات:** {report.total_findings}")
        lines.append(f"- **مؤكد:** {report.confirmed_findings}")
        lines.append(f"- **غير مؤكد:** {report.unconfirmed_findings}")
        lines.append(f"- **إيجابيات زائفة:** {report.false_positives}")
        lines.append(f"- **مدخلات مساحة سلبية:** {report.negative_space_entries}")
        lines.append(f"- **معدل التثبيت:** {report.confirmation_rate}%")
        lines.append("")

        lines.append("## 🛡️ الاكتشافات المؤكدة (Confirmed)")
        if not report.confirmed:
            lines.append("_لا توجد اكتشافات مؤكدة بدليل أدلة قابلة لإعادة التقييم._")
        else:
            for r in report.confirmed:
                cvss = _cvss_for_severity(r.severity)
                lines.append(f"### {r.title}")
                lines.append(f"- **المضيف:** `{r.host}`{f' port {r.port}' if r.port else ''}")
                lines.append(f"- **البروتوكول:** `{r.protocol}`")
                lines.append(f"- **فئة الثغرة:** `{r.vuln_class}`")
                lines.append(f"- **الخطورة:** `{r.severity}` (CVSS {cvss['score']} / 10 — {cvss['severity']})")
                lines.append(f"- **ثقة المُكتشف:** `{r.confidence:.2f}`")
                lines.append(f"- **قوة الدليل:** `{r.proof_strength}`")
                lines.append(f"- **حالة المعرفة:** `{r.epistemic_state}`")
                lines.append(f"- **الحُكم القضائي:** {r.rationale}")
                lines.append("")

        lines.append("## ⏳ الاكتشافات المستغرقة للتحقق (Unconfirmed / Candidates)")
        if not report.unconfirmed:
            lines.append("_لا توجد اكتشافات غير مؤكدة._")
        else:
            lines.append("_تُذكر شفافيةً ولا تُدرج كثغرات مؤكدة في التقرير النهائي._")
            for r in report.unconfirmed:
                lines.append(f"- **{r.title}** — `{r.host}`{f' port {r.port}' if r.port else ''} — `{r.vuln_class}` — الحكم: {r.rationale}")
            lines.append("")

        lines.append("## 🚫 مساحة سلبية (Negative Space)")
        if not report.negative_space:
            lines.append("_جميع النقاط المكتشفة في النطاق تم استكشافها بالكامل._")
        else:
            for e in report.negative_space:
                lines.append(f"- **{e.host}**{f' port {e.port}' if e.port else ''} — السبب: `{e.reason}` — {e.detail}")
            lines.append("")

        lines.append("## ❌ إيجابيات زائفة (False Positives)")
        if not report.false_positive_list:
            lines.append("_لا توجد إيجابيات زائفة مُحددة._")
        else:
            for r in report.false_positive_list:
                lines.append(f"- **{r.title}** — `{r.host}` — السبب: {r.rationale}")
            lines.append("")

        path.write_text("\n".join(lines), encoding="utf-8")
        return str(path)

    def _write_sarif(self, report: NetworkCourtReport, target_name: str) -> str:
        safe = self._safe_name(target_name)
        path = self.output_dir / f"{safe}_network_report.sarif.json"

        findings_for_sarif: List[Dict[str, Any]] = []
        for r in report.confirmed:
            cvss = _cvss_for_severity(r.severity)
            findings_for_sarif.append({
                "title": r.title,
                "cwe_id": r.vuln_class or "CWE-20",
                "severity": r.severity.upper(),
                "cvss_score": cvss["score"],
                "cvss_vector": cvss["vector"],
                "evidence": r.rationale,
                "remediation": "انظر التوصية في نتيجة المحاكمة القضائية.",
                "file_path": f"{r.host}:{r.port or ''}",
                "line_number": 1,
            })

        sarif_doc = SARIFExporter.export_sarif(findings_for_sarif, output_file=path)
        return str(path)

    def _write_html(
        self,
        report: NetworkCourtReport,
        target_name: str,
        aggregate_data: Dict[str, Any],
    ) -> str:
        safe = self._safe_name(target_name)
        path = self.output_dir / f"{safe}_network_report.html"

        # تحويل نتائج المحكمة إلى Finding objects لـ HTML reporter
        from core.finding_model import (
            Finding,
            FindingSeverity,
            HttpExchangeRecord,
            ReproducibilityRecord,
            VerificationRecord,
        )

        findings: List[Finding] = []
        for r in report.confirmed:
            sev = FindingSeverity[r.severity.upper()] if r.severity.upper() in {
                s.name for s in FindingSeverity
            } else FindingSeverity.MEDIUM
            findings.append(
                Finding(
                    vulnerability_type=r.vuln_class or "network",
                    title=r.title,
                    severity=r.severity,
                    confidence=r.confidence,
                    target=r.host,
                    endpoint=f"{r.protocol}://{r.host}:{r.port}" if r.port else f"{r.protocol}://{r.host}",
                    parameter="",
                    evidence=r.rationale,
                    remediation="انظر التوصية في نتيجة المحاكمة القضائية.",
                    cwe=r.vuln_class or "",
                    verification=VerificationRecord(
                        verified=(r.verdict == "CONFIRMED"),
                        verifier_name="HunterAI Evidence Court",
                        methodology="DERIVED proof re-evaluation",
                        proof_token=r.court_judgment_id,
                        reproduced_count=1 if r.verdict == "CONFIRMED" else 0,
                    ),
                    reproducibility=ReproducibilityRecord(
                        is_reproducible=(r.verdict == "CONFIRMED"),
                        reproduction_steps=[f"تشغيل أمر الإثبات: {r.title}"],
                    ),
                )
            )

        coverage_summary = {
            "coverage_percentage": round(
                (len(report.confirmed) / max(report.total_findings, 1)) * 100, 2
            ),
            "probed_items": report.total_findings,
            "skipped_breakdown": {
                e.reason: sum(
                    1 for x in report.negative_space if x.reason == e.reason
                )
                for e in report.negative_space
            },
        }

        signature = self.signer.sign_report(aggregate_data)
        HTMLReportGenerator.generate_html(
            target_name=target_name,
            findings=findings,
            coverage_summary=coverage_summary,
            signature=signature,
            output_path=path,
        )
        return str(path)

    # ── helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _safe_name(name: str) -> str:
        safe = (
            name.replace("https://", "")
            .replace("http://", "")
            .replace("/", "_")
            .replace(":", "_")
        )
        return safe or "target"
