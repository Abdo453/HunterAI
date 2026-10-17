"""Trivy Dependency Risk Analyzer — L3 Context Intelligence + L4 Adaptive Advisor"""
from __future__ import annotations

import logging
from typing import List, Dict, Any, Optional
from core.trivy.schemas import TrivyVulnerabilityRecord

log = logging.getLogger("trivy.context")


class ContextEnricher:
    def enrich(self, record: TrivyVulnerabilityRecord) -> Dict[str, Any]:
        context: Dict[str, Any] = {
            "is_critical_severity": False,
            "is_exploitable": False,
            "has_fix": False,
            "package_type": "unknown",
            "notes": [],
        }

        sev_lower = record.severity.lower()
        pkg_lower = record.package_name.lower()

        if sev_lower in ("critical", "high"):
            context["is_critical_severity"] = True
            context["notes"].append("ثغرة خطيرة — أولوية تحديث فورية")

        if record.fixed_version:
            context["has_fix"] = True
            context["notes"].append(f"إصدار مصحح متاح: {record.fixed_version}")
        else:
            context["notes"].append("لا يوجد إصدار مصحح — مراقبة يدوية مطلوبة")

        pkg_lower = record.package_name.lower()
        if any(k in pkg_lower for k in ["openssl", "log4j", "spring", "django", "rails", "express"]):
            context["is_exploitable"] = True
            context["notes"].append("حزمة معروفة بالاستغلال — خطورة أعلى")

        return context


class AdaptiveTestAdvisor:
    def advise(
        self,
        record: TrivyVulnerabilityRecord,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        context = context or {}
        suggestions: List[str] = []

        if context.get("is_critical_severity"):
            suggestions.append("trivy --severity CRITICAL,HIGH")
        if context.get("has_fix"):
            suggestions.append(f"تحديث {record.package_name} إلى {record.fixed_version}")
        if context.get("is_exploitable"):
            suggestions.append("مراقبة الاستغلال النشط عبر CISA KEV")

        seen = set()
        unique = []
        for s in suggestions:
            if s not in seen:
                seen.add(s)
                unique.append(s)

        return unique[:8]
