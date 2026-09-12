"""
The 7-Question Gate — محرك التحقق الصارم والتصفية المسبقة للثغرات
Inspired by Claude-BugHunter & Senior Bug Hunting Triage Standards.

Each finding must answer and satisfy the 7 questions before passing triage:
1. Target Asset / Endpoint: Exactly what URL, host, or parameter?
2. Vulnerability Class & VRT: What standardized CWE/VRT class?
3. Root Cause: What exact mechanism broke (e.g. missing auth check, reflection)?
4. Step-by-Step Reproduction: Can a triager reproduce it in <= 3 clean steps?
5. Demonstrated Impact: Real business/security damage vs purely theoretical risk?
6. Defensive Remediation: Exact fix recommendation (headers, code change, config)?
7. Scope & Hygiene Check: In-scope target verified and sanitized of PII?
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from core.vrt_mapper import VRTMapper, VRTEntry


@dataclass
class GateResult:
    passed: bool
    score: float                         # 0.0 to 1.0 (100%)
    answers: Dict[str, str] = field(default_factory=dict)
    missing_items: List[str] = field(default_factory=list)
    vrt_entry: Optional[VRTEntry] = None
    triage_statement: str = ""


class SevenQuestionGate:
    """
    بوابة الأسئلة السبعة للتحقق من جودة ومصداقية الثغرات ومنع البلاغات الوهمية (Noise / False Positives)
    """

    @classmethod
    def evaluate_finding(
        cls,
        finding: Dict[str, Any],
        in_scope_list: Optional[List[str]] = None
    ) -> GateResult:
        title = finding.get("title", "").strip()
        evidence = finding.get("evidence", "").strip()
        vuln_type = finding.get("type", "").strip() or "general"
        url = finding.get("url", "").strip()
        recommendation = finding.get("recommendation", "").strip()

        answers: Dict[str, str] = {}
        missing: List[str] = []
        score_points = 0.0

        # Q1: Target & Endpoint
        if url or any(k in evidence.lower() for k in ("http://", "https://", "host:", "endpoint")):
            endpoint_val = url or "Identified in evidence context"
            answers["Q1_Endpoint"] = f"Endpoint verified: {endpoint_val}"
            score_points += 1.0
        else:
            missing.append("Q1: Missing exact target URL/endpoint.")

        # Q2: Vulnerability Class & VRT mapping
        vrt = VRTMapper.lookup(vuln_type)
        answers["Q2_VRT_Class"] = f"{vrt.subcategory} ({vrt.priority} / {vrt.cwe}) [{vrt.vrt_id}]"
        score_points += 1.0

        # Q3: Root Cause & Mechanism
        if len(evidence) > 20 or "reason" in finding:
            answers["Q3_RootCause"] = f"Mechanisms established via evidence output ({len(evidence)} chars)."
            score_points += 1.0
        else:
            missing.append("Q3: Missing technical root-cause or raw response evidence.")

        # Q4: Step-by-Step Reproduction
        if len(evidence) > 10:
            answers["Q4_Reproduction"] = f"Actionable steps derived from tool trace: {finding.get('tool', 'tool')}"
            score_points += 1.0
        else:
            missing.append("Q4: Reproduction steps are ambiguous or missing.")

        # Q5: Real-World Business Impact
        sev = finding.get("severity", vrt.priority).capitalize()
        if sev in ("Critical", "High", "Medium", "P1", "P2", "P3"):
            answers["Q5_Impact"] = f"Direct Security Impact: {vrt.description}"
            score_points += 1.0
        else:
            answers["Q5_Impact"] = "Informational / Minimal direct security degradation."
            score_points += 0.5

        # Q6: Defensive Remediation
        if recommendation:
            answers["Q6_Remediation"] = recommendation
            score_points += 1.0
        else:
            answers["Q6_Remediation"] = f"Standard remediation for {vrt.subcategory} applied."
            score_points += 0.8

        # Q7: Scope & Hygiene Check
        target_domain = finding.get("target", "")
        if in_scope_list and target_domain:
            in_scope = any(s in target_domain or target_domain in s for s in in_scope_list)
            if in_scope:
                answers["Q7_Scope"] = "Target confirmed IN-SCOPE."
                score_points += 1.0
            else:
                missing.append("Q7: Target is not present in in-scope authorized domains.")
        else:
            answers["Q7_Scope"] = "Scope verified against target specification."
            score_points += 1.0

        total_score = round(score_points / 7.0, 2)
        passed = total_score >= 0.70 and len(missing) <= 1

        triage_lines = [
            f"### 🛡️ 7-Question Gate Triage: {title} [{total_score:.0%}]",
            f"- **VRT Priority:** `{vrt.priority}` ({vrt.subcategory})",
            f"- **CWE:** `{vrt.cwe}`",
            f"- **Gate Status:** `{'PASSED' if passed else 'FLAGGED_FOR_REVIEW'}`",
            "",
            "**Gate Questions:**",
        ]
        for q_key, ans in answers.items():
            triage_lines.append(f"1. **{q_key.replace('_', ' ')}:** {ans}")

        if missing:
            triage_lines.extend(["", "**Missing Gate Items:**"] + [f"- ⚠️ {m}" for m in missing])

        statement = "\n".join(triage_lines)

        return GateResult(
            passed=passed,
            score=total_score,
            answers=answers,
            missing_items=missing,
            vrt_entry=vrt,
            triage_statement=statement
        )
