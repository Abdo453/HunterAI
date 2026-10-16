"""Burp Suite Traffic Intelligence — L3 Context + L4 Adaptive"""
from __future__ import annotations

import logging
from typing import List, Dict, Any, Optional
from core.burp.schemas import BurpTrafficRecord

log = logging.getLogger("burp.context")


class ContextEnricher:
    def enrich(self, record: BurpTrafficRecord) -> Dict[str, Any]:
        context: Dict[str, Any] = {
            "is_auth_request": False,
            "is_admin_request": False,
            "is_api_request": False,
            "has_parameters": False,
            "notes": [],
        }

        url_lower = record.request_url.lower()
        method = record.request_method.upper()

        auth_kw = ["login", "auth", "signin", "token", "oauth", "sso", "password"]
        admin_kw = ["admin", "administrator", "manage", "dashboard", "panel", "config"]
        api_kw = ["/api/", "/graphql", "/rest/"]

        if any(k in url_lower for k in auth_kw):
            context["is_auth_request"] = True
            context["notes"].append("طلب مصادقة — زيادة الأولوية الأمنية")
        if any(k in url_lower for k in admin_kw):
            context["is_admin_request"] = True
            context["notes"].append("طلب إدارة — تأثير محتمل أعلى")
        if any(k in url_lower for k in api_kw):
            context["is_api_request"] = True
            context["notes"].append("طلب API — قد يكشف بيانات منظمة")

        if "?" in record.request_url or record.request_body:
            context["has_parameters"] = True
            context["notes"].append("يحتوي على معاملات — قد يكون عرضة للحقن")

        return context


class AdaptiveAdvisor:
    def advise(self, record: BurpTrafficRecord, context: Optional[Dict[str, Any]] = None) -> List[str]:
        context = context or {}
        suggestions: List[str] = []

        if context.get("is_auth_request"):
            suggestions.extend(["nuclei -t http/default-credentials", "ffuf"])
        if context.get("is_admin_request"):
            suggestions.extend(["nuclei -t http/exposed-panels"])
        if context.get("is_api_request"):
            suggestions.extend(["katana -js", "nuclei -t http/misconfig"])
        if context.get("has_parameters"):
            suggestions.extend(["nuclei -t http/sqli", "nuclei -t http/xss"])

        seen = set()
        unique = []
        for s in suggestions:
            if s not in seen:
                seen.add(s)
                unique.append(s)
        return unique[:8]
