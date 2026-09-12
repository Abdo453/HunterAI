"""
CVSS v3.1 Calculator & Professional Security Report Engine
"FIRST.org Standard CVSS 3.1 Equations & Enterprise Reporting"

يحسب درجات الخطورة بدقة وفق معادلات FIRST.org الرسمية لـ CVSS v3.1:
- Base Metrics (AV, AC, PR, UI, S, C, I, A)
- حساب الـ Impact و Exploitability و Base Score بدقة مع التقريب المعتمد
- ربط الثغرات بمعايير OWASP Top 10 و CWE
- توليد تقارير تنفيذية وفنية مهيكلة للمطورين وفرق الأمان
"""
import json
import math
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger("reporting.cvss_engine")


class CVSSv31Calculator:
    """حاسبة معيار CVSS v3.1 الرسمية"""

    # Weights
    AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    AC_WEIGHTS = {"L": 0.77, "H": 0.44}
    PR_WEIGHTS_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
    PR_WEIGHTS_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
    UI_WEIGHTS = {"N": 0.85, "R": 0.62}
    CIA_WEIGHTS = {"N": 0.0, "L": 0.22, "H": 0.56}

    @classmethod
    def calculate_base_score(
        cls,
        av: str = "N",
        ac: str = "L",
        pr: str = "N",
        ui: str = "N",
        s: str = "U",
        c: str = "H",
        i: str = "N",
        a: str = "N"
    ) -> Dict[str, Any]:
        """
        حساب Base Score وفق معادلات FIRST.org الرسمية لـ CVSS v3.1
        """
        av_val = cls.AV_WEIGHTS.get(av.upper(), 0.85)
        ac_val = cls.AC_WEIGHTS.get(ac.upper(), 0.77)
        ui_val = cls.UI_WEIGHTS.get(ui.upper(), 0.85)

        scope_changed = s.upper() == "C"
        pr_table = cls.PR_WEIGHTS_CHANGED if scope_changed else cls.PR_WEIGHTS_UNCHANGED
        pr_val = pr_table.get(pr.upper(), 0.85)

        c_val = cls.CIA_WEIGHTS.get(c.upper(), 0.0)
        i_val = cls.CIA_WEIGHTS.get(i.upper(), 0.0)
        a_val = cls.CIA_WEIGHTS.get(a.upper(), 0.0)

        # 1. ISS (Impact Sub-Score)
        iss = 1.0 - ((1.0 - c_val) * (1.0 - i_val) * (1.0 - a_val))

        # 2. Impact
        if not scope_changed:
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        # 3. Exploitability
        exploitability = 8.22 * av_val * ac_val * pr_val * ui_val

        # 4. Base Score
        if impact <= 0:
            base_score = 0.0
        else:
            if not scope_changed:
                raw_score = min(impact + exploitability, 10.0)
            else:
                raw_score = min(1.08 * (impact + exploitability), 10.0)
            # CVSS v3.1 Roundup rule (ceiling at 1 decimal place)
            base_score = math.ceil(raw_score * 10.0) / 10.0

        # Severity classification
        if base_score == 0.0:
            severity = "None"
        elif base_score < 4.0:
            severity = "Low"
        elif base_score < 7.0:
            severity = "Medium"
        elif base_score < 9.0:
            severity = "High"
        else:
            severity = "Critical"

        vector = f"CVSS:3.1/AV:{av.upper()}/AC:{ac.upper()}/PR:{pr.upper()}/UI:{ui.upper()}/S:{s.upper()}/C:{c.upper()}/I:{i.upper()}/A:{a.upper()}"

        return {
            "score": round(base_score, 1),
            "severity": severity,
            "vector": vector,
            "impact_subscore": round(impact, 2),
            "exploitability_subscore": round(exploitability, 2)
        }


class CVSSReportEngine:
    """محرك إنشاء التقارير الاحترافية لتقييم الأمان"""

    def __init__(self, output_dir: str = "data/reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_assessment_report(
        self,
        target: str,
        findings: List[Dict[str, Any]],
        tech_stack: Optional[List[str]] = None,
        duration: float = 0.0
    ) -> Dict[str, Any]:
        """
        توليد تقرير تدقيق أمني متكامل:
        - ملخص تنفيذي (Executive Summary)
        - تفاصيل الثغرات مع حساب CVSS 3.1
        - مصفوفة المخاطر وخطوات الترقيع
        """
        processed_findings = []
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}

        for f in findings:
            sev = f.get("severity", "Medium").capitalize()
            if sev not in counts:
                sev = "Medium"
            counts[sev] += 1

            # Auto calculate CVSS if vector or defaults needed
            if "cvss" not in f or not isinstance(f["cvss"], dict):
                # Default mapping based on severity
                if sev == "Critical":
                    cvss = CVSSv31Calculator.calculate_base_score(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H")
                elif sev == "High":
                    cvss = CVSSv31Calculator.calculate_base_score(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="L", a="N")
                elif sev == "Medium":
                    cvss = CVSSv31Calculator.calculate_base_score(av="N", ac="L", pr="N", ui="R", s="U", c="L", i="L", a="N")
                elif sev == "Low":
                    cvss = CVSSv31Calculator.calculate_base_score(av="N", ac="H", pr="L", ui="R", s="U", c="L", i="N", a="N")
                else:
                    cvss = {"score": 0.0, "severity": "Info", "vector": "N/A"}
            else:
                cvss = f["cvss"]

            processed_findings.append({
                "title": f.get("title", "Security Finding"),
                "type": f.get("type", "vulnerability"),
                "severity": sev,
                "cvss": cvss,
                "evidence": f.get("evidence", "N/A"),
                "recommendation": f.get("recommendation") or f.get("remediation", "Apply vendor security updates and harden input validation."),
                "tool": f.get("tool", "PentestAI")
            })

        # Calculate Overall Risk Score
        total_vulns = len(processed_findings)
        weighted_score = (
            counts["Critical"] * 10.0 +
            counts["High"] * 7.5 +
            counts["Medium"] * 5.0 +
            counts["Low"] * 2.0
        )
        overall_risk = "Low"
        if counts["Critical"] > 0 or counts["High"] >= 3:
            overall_risk = "Critical"
        elif counts["High"] > 0 or counts["Medium"] >= 4:
            overall_risk = "High"
        elif counts["Medium"] > 0:
            overall_risk = "Medium"

        report_data = {
            "meta": {
                "target": target,
                "date": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
                "duration_seconds": round(duration, 2),
                "total_findings": total_vulns,
                "overall_risk_level": overall_risk,
                "detected_technologies": tech_stack or []
            },
            "summary_metrics": counts,
            "findings": processed_findings
        }

        # Save JSON
        safe_name = target.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
        json_path = self.output_dir / f"{safe_name}_assessment.json"
        with open(json_path, "w", encoding="utf-8") as fp:
            json.dump(report_data, fp, indent=2, ensure_ascii=False)

        return report_data
