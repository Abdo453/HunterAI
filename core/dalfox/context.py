"""Dalfox XSS Context Analyzer — L3 Context Intelligence + L4 Adaptive Advisor"""
from __future__ import annotations

import logging
from typing import List, Dict, Any, Optional
from core.dalfox.schemas import DalfoxFindingRecord

log = logging.getLogger("dalfox.context")


class ContextEnricher:
    def enrich(self, record: DalfoxFindingRecord) -> Dict[str, Any]:
        context: Dict[str, Any] = {
            "is_reflected": False,
            "is_stored": False,
            "is_dom": False,
            "injection_context": "unknown",
            "notes": [],
        }

        ip_lower = record.injection_point.lower()
        type_lower = record.type.lower()

        if "reflected" in type_lower or "reflect" in ip_lower:
            context["is_reflected"] = True
        if "stored" in type_lower:
            context["is_stored"] = True
        if "dom" in type_lower:
            context["is_dom"] = True

        if "param" in ip_lower:
            context["injection_context"] = "parameter"
        elif "header" in ip_lower:
            context["injection_context"] = "header"
        elif "path" in ip_lower:
            context["injection_context"] = "path"
        elif "body" in ip_lower:
            context["injection_context"] = "body"

        context["notes"].append(f"سياق الحقن: {context['injection_context']}")
        return context


class AdaptiveTestAdvisor:
    def advise(
        self,
        record: DalfoxFindingRecord,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        context = context or {}
        suggestions: List[str] = []

        if context.get("is_reflected"):
            suggestions.append("dalfox --level 3")
        if context.get("is_stored"):
            suggestions.append("dalfox --level 4")
        if context.get("is_dom"):
            suggestions.append("dalfox --dom")
        if context.get("injection_context") == "parameter":
            suggestions.append("dalfox --method GET")

        seen = set()
        unique = []
        for s in suggestions:
            if s not in seen:
                seen.add(s)
                unique.append(s)

        return unique[:8]
