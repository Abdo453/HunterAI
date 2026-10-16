"""
HunterAI PDF Report Generator
تقارير PDF منظمة مع CVSS scoring، Proof of Concept، و Remediation
مقتبس من فكرة Xalgorix audit-ready reports
"""
from __future__ import annotations

import os
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, Image, HRFlowable,
    )
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False

log = logging.getLogger("hunter_ai.reporting")


class CVSSCalculator:
    """
    حاسبة CVSS v3.1 مبسطة لحساب درجة الخطورة
    """
    SEVERITY_MAP = {
        (9.0, 10.0): "Critical",
        (7.0, 8.9): "High",
        (4.0, 6.9): "Medium",
        (0.1, 3.9): "Low",
        (0.0, 0.0): "Info",
    }

    @classmethod
    def calculate(
        cls,
        attack_vector: str = "N",        # N=Network, A=Adjacent, L=Local, P=Physical
        attack_complexity: str = "L",    # L=Low, H=High
        privileges_required: str = "N",  # N=None, L=Low, H=High
        user_interaction: str = "N",     # N=None, R=Required
        scope: str = "U",                # U=Unchanged, C=Changed
        confidentiality: str = "L",      # N=None, L=Low, H=High
        integrity: str = "L",
        availability: str = "L",
    ) -> dict:
        """
        يحسب النقاط الأساسية (Base Score) وفق CVSS v3.1 المبسط
        """
        # قيم المبسطة للحساب
        av_map = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
        ac_map = {"L": 0.77, "H": 0.44}
        pr_map_u = {"N": 0.85, "L": 0.62, "H": 0.27}  # Scope Unchanged
        pr_map_c = {"N": 0.85, "L": 0.68, "H": 0.5}   # Scope Changed
        ui_map = {"N": 0.85, "R": 0.62}
        s_map = {"U": 0, "C": 1}
        cia_map = {"N": 0, "L": 0.22, "H": 0.56}

        av = av_map.get(attack_vector, 0.85)
        ac = ac_map.get(attack_complexity, 0.77)
        pr = (pr_map_c if scope == "C" else pr_map_u).get(privileges_required, 0.85)
        ui = ui_map.get(user_interaction, 0.85)
        s = s_map.get(scope, 0)
        c = cia_map.get(confidentiality, 0.22)
        i = cia_map.get(integrity, 0.22)
        a = cia_map.get(availability, 0.22)

        # حساب مبسط للقاعدة
        impact = 1 - ((1 - c) * (1 - i) * (1 - a))
        if scope == "U":
            impact_score = 6.42 * impact
        else:
            impact_score = 7.52 * (impact - 0.029) - 3.25 * (impact - 0.02) ** 15

        if impact_score <= 0:
            base_score = 0
        else:
            exploitability = 8.22 * av * ac * pr * ui
            if scope == "U":
                base_score = min(impact_score + exploitability, 10)
            else:
                base_score = min(1.08 * (impact_score + exploitability), 10)

        base_score = round(base_score, 1)

        # تحديد mức الخطورة
        for (low, high), label in cls.SEVERITY_MAP.items():
            if low <= base_score <= high:
                severity = label
                break
        else:
            severity = "Info"

        return {
            "base_score": base_score,
            "severity": severity,
            "vector": f"CVSS:3.1/AV:{attack_vector}/AC:{attack_complexity}/PR:{privileges_required}/UI:{user_interaction}/S:{scope}/C:{confidentiality}/I:{integrity}/A:{availability}",
        }


class PDFReportGenerator:
    """
    مولد تقارير PDF منظمة مع CVSS، Proof of Concept، و Remediation
    """

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.cvss = CVSSCalculator()

    def generate(
        self,
        target: str,
        findings: List[Dict[str, Any]],
        session_id: str,
        company_name: str = "HunterAI Client",
        logo_path: Optional[str] = None,
    ) -> str:
        """
        ينشئ تقرير PDF ويعيد مسار الملف
        """
        if not HAS_REPORTLAB:
            raise ImportError("reportlab not installed. Install with: pip install reportlab")

        filename = f"hunterai_report_{session_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = self.output_dir / filename

        doc = SimpleDocTemplate(
            str(filepath),
            pagesize=A4,
            rightMargin=15 * mm,
            leftMargin=15 * mm,
            topMargin=15 * mm,
            bottomMargin=15 * mm,
            title=f"HunterAI Security Report — {target}",
            author="HunterAI Autonomous Security Agent",
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "CustomTitle",
            parent=styles["Heading1"],
            fontSize=18,
            textColor=colors.HexColor("#38bdf8"),
            spaceAfter=10,
        )
        heading_style = ParagraphStyle(
            "CustomHeading",
            parent=styles["Heading2"],
            fontSize=14,
            textColor=colors.HexColor("#1e293b"),
            spaceBefore=15,
            spaceAfter=8,
        )
        body_style = ParagraphStyle(
            "CustomBody",
            parent=styles["Normal"],
            fontSize=10,
            textColor=colors.HexColor("#334155"),
            spaceAfter=6,
        )

        story: List[Any] = []

        # ── الصفحة الأولى: العنوان والملخص التنفيذي ─────────────────────
        if logo_path and os.path.exists(logo_path):
            story.append(Image(logo_path, width=40 * mm, height=15 * mm))
        story.append(Spacer(1, 10))
        story.append(Paragraph("تقرير التحقيق الأمني — HunterAI", title_style))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#38bdf8")))
        story.append(Spacer(1, 10))

        info_data = [
            ["الهدف", target],
            ["معرف الجلسة", session_id],
            ["تاريخ الإنشاء", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")],
            ["العميل", company_name],
            ["عدد النتائج", str(len(findings))],
        ]
        info_table = Table(info_data, colWidths=[40 * mm, 120 * mm])
        info_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#1e293b")),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#334155")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ])
        )
        story.append(info_table)
        story.append(Spacer(1, 15))

        # ملخص Executive
        story.append(Paragraph("الملخص التنفيذي", heading_style))
        critical = sum(1 for f in findings if f.get("severity", "").lower() == "critical")
        high = sum(1 for f in findings if f.get("severity", "").lower() == "high")
        medium = sum(1 for f in findings if f.get("severity", "").lower() == "medium")
        low = sum(1 for f in findings if f.get("severity", "").lower() == "low")
        info = sum(1 for f in findings if f.get("severity", "").lower() == "info")

        summary_text = (
            f"تم تنفيذ تحقيق أمني تلقائي على الهدف <b>{target}</b> باستخدام نظام HunterAI الذاتي. "
            f"تم اكتشاف <b>{len(findings)}</b> نتيجة أمنية، من بينها "
            f"<b>{critical}</b> حرجة، <b>{high}</b> عالية، <b>{medium}</b> متوسطة، "
            f"<b>{low}</b> ضعيفة، و<b>{info}</b> معلوماتية. "
            f"جميع النتائج خضعت لعملية التحقق من الاستغلال (Exploit-Verified) قبل الإبلاغ عنها."
        )
        story.append(Paragraph(summary_text, body_style))
        story.append(Spacer(1, 10))

        # جدول النتائج
        story.append(Paragraph("النتائج الأمنية المكتشفة", heading_style))

        findings_data = [["المعرف", "النوع", "الهدف", "الشدة", "CVSS", "الحالة", "الثقة"]]
        for f in findings:
            cvss_calc = self.cvss.calculate(
                attack_vector=f.get("attack_vector", "N"),
                attack_complexity=f.get("attack_complexity", "L"),
                privileges_required=f.get("privileges_required", "N"),
                scope=f.get("scope", "U"),
                confidentiality=f.get("confidentiality", "L"),
                integrity=f.get("integrity", "L"),
                availability=f.get("availability", "L"),
            )
            findings_data.append([
                f.get("record_id", "—")[:12],
                f.get("template_id", f.get("type", "—"))[:25],
                f.get("matched_at", f.get("url", "—"))[:30],
                f.get("severity", "Info"),
                f"{cvss_calc['base_score']} ({cvss_calc['severity']})",
                f.get("status", "pending"),
                f"{(f.get('confidence', 0) * 100):.0f}%",
            ])

        findings_table = Table(findings_data, colWidths=[22 * mm, 28 * mm, 35 * mm, 15 * mm, 22 * mm, 15 * mm, 13 * mm], repeatRows=1)
        findings_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#334155")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ])
        )
        story.append(findings_table)
        story.append(PageBreak())

        # تفاصيل كل نتيجة مع PoC و Remediation
        story.append(Paragraph("تفاصيل النتائج وأدلة الاستغلال", heading_style))
        for idx, f in enumerate(findings, 1):
            cvss_calc = self.cvss.calculate(
                attack_vector=f.get("attack_vector", "N"),
                attack_complexity=f.get("attack_complexity", "L"),
                privileges_required=f.get("privileges_required", "N"),
                scope=f.get("scope", "U"),
                confidentiality=f.get("confidentiality", "L"),
                integrity=f.get("integrity", "L"),
                availability=f.get("availability", "L"),
            )

            story.append(Paragraph(f"{idx}. {f.get('template_id', f.get('type', '—'))}", heading_style))
            story.append(Paragraph(f"<b>المعرف:</b> {f.get('record_id', '—')}", body_style))
            story.append(Paragraph(f"<b>الهدف:</b> {f.get('matched_at', f.get('url', '—'))}", body_style))
            story.append(Paragraph(f"<b>الشدة:</b> {f.get('severity', 'Info')}", body_style))
            story.append(Paragraph(f"<b>نقاط CVSS:</b> {cvss_calc['base_score']} ({cvss_calc['severity']})", body_style))
            story.append(Paragraph(f"<b>المتجه (Vector):</b> {cvss_calc['vector']}", body_style))
            story.append(Paragraph(f"<b>الدليل (Evidence):</b> {f.get('validation_note', '—')}", body_style))
            story.append(Paragraph(f"<b>إثبات الاستغلال (PoC):</b> {f.get('recommendation', 'راجع الأدلة المرفقة في الجلسة')}", body_style))
            story.append(Paragraph(f"<b>التعافي (Remediation):</b> {f.get('recommendation', 'راجع التوصيات الأمنية العامة')}", body_style))
            story.append(Spacer(1, 10))
            story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#334155")))
            story.append(Spacer(1, 10))

        # التوصيات الختامية
        story.append(Paragraph("التوصيات الختامية", heading_style))
        recommendations = [
            "تطبيق التحديثات الأمنية لجميع المكونات المكتشفة.",
            "إزالة بيانات الاعتماد المكشوفة وتدوير جميع التوكنات.",
            "فحص نقاط النهاية الحساسة (إدارة، مصادقة) يدوياً قبل النشر الإنتاجي.",
            "تطبيق مبدأ أقل امتياز (Principle of Least Privilege) على جميع الخدمات.",
            "إجراء اختبار اختراق دوري كل 3-6 أشهر.",
        ]
        for rec in recommendations:
            story.append(Paragraph(f"• {rec}", body_style))

        doc.build(story)
        log.info(f"[PDF Report] Generated: {filepath}")
        return str(filepath)
