"""Subjack Subdomain Takeover — L3 Context Intelligence + L4 Adaptive Advisor"""
from __future__ import annotations

import logging
from typing import List, Dict, Any, Optional, Set
from core.subjack.schemas import SubdomainTakeoverRecord

log = logging.getLogger("subjack.context")


class ContextEnricher:
    def __init__(
        self,
        katana_endpoints: Optional[List[str]] = None,
        httpx_results: Optional[Dict[str, List[str]]] = None,
    ):
        self.katana_endpoints = set(katana_endpoints or [])
        self.httpx_results = httpx_results or {}

    def enrich(self, record: SubdomainTakeoverRecord) -> Dict[str, Any]:
        context: Dict[str, Any] = {
            "service_category": "web",
            "is_administration": False,
            "is_api": False,
            "related_urls": [],
            "notes": [],
        }

        sub = record.subdomain.lower()

        admin_keywords = ["admin", "administrator", "manage", "dashboard", "panel", "config", "setup", "root"]
        api_keywords = ["api", "graphql", "rest", "webhook", "svc", "service"]
        if any(k in sub for k in admin_keywords):
            context["is_administration"] = True
            context["service_category"] = "administration"
            context["notes"].append("نطاق فرعي إداري — تأثير محتمل أعلى في حال الاستيلاء")
        if any(k in sub for k in api_keywords):
            context["is_api"] = True
            context["service_category"] = "api"
            context["notes"].append("نطاق فرعي API — قد يكشف بيانات منظمة")

        katana_matches = [ep for ep in self.katana_endpoints if sub in ep]
        if katana_matches:
            context["notes"].append(f"النطاق موجود في Katana endpoints ({len(katana_matches)} مسار)")

        # الربط مع نتائج HTTPx — مطابقة مباشرة ثم نطاق أبوي (admin.dev.target.local → dev.target.local)
        matched_sub = sub if sub in self.httpx_results else None
        if matched_sub is None:
            parts = sub.split(".")
            for i in range(1, len(parts) - 1):
                parent = ".".join(parts[i:])
                if parent in self.httpx_results:
                    matched_sub = parent
                    break
        if matched_sub:
            context["related_urls"] = self.httpx_results[matched_sub]
            context["notes"].append(f"روابط مرتبطة من HTTPx: {', '.join(self.httpx_results[matched_sub][:3])}")

        return context


class AdaptiveTestAdvisor:
    def advise(
        self,
        record: SubdomainTakeoverRecord,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        context = context or {}
        suggestions: List[str] = []

        if record.takeover_risk.lower() == "high":
            suggestions.append("nuclei -t http/takeovers")
            suggestions.append("ffuf -u http://<subdomain>/FUZZ")
        if record.takeover_risk.lower() == "medium":
            suggestions.append("nuclei -t http/misconfig")

        if context.get("is_administration"):
            suggestions.append("ffuf -u http://<subdomain>/admin/FUZZ")
        if context.get("is_api"):
            suggestions.append("katana -js")

        seen = set()
        unique = []
        for s in suggestions:
            if s not in seen:
                seen.add(s)
                unique.append(s)

        return unique[:8]
