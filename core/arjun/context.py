"""Arjun Parameter Intelligence — L3 Context Intelligence + L4 Adaptive Advisor"""
from __future__ import annotations

import logging
from typing import List, Dict, Any, Optional
from core.arjun.schemas import ArjunParameterRecord

log = logging.getLogger("arjun.context")


class ContextEnricher:
    def enrich(self, record: ArjunParameterRecord) -> Dict[str, Any]:
        context: Dict[str, Any] = {
            "is_auth_parameter": False,
            "is_id_parameter": False,
            "is_search_parameter": False,
            "method_category": "standard",
            "notes": [],
        }

        param_lower = record.parameter.lower()
        method = record.method.upper()

        auth_kw = ["id", "user", "username", "email", "token", "session", "auth", "login", "pass"]
        id_kw = ["id", "uid", "pid", "oid", "cid", "item_id", "product_id"]
        search_kw = ["q", "query", "search", "keyword", "filter", "name"]

        if any(k in param_lower for k in auth_kw):
            context["is_auth_parameter"] = True
            context["notes"].append("معلمة مصادقة — أولوية أعلى")
        if any(k in param_lower for k in id_kw):
            context["is_id_parameter"] = True
            context["notes"].append("معلمة معرّف — قد تكون عرضة لـ IDOR")
        if any(k in param_lower for k in search_kw):
            context["is_search_parameter"] = True
            context["notes"].append("معلمة بحث — قد تكشف بيانات")

        if method in ("POST", "PUT", "DELETE", "PATCH"):
            context["method_category"] = "mutating"
            context["notes"].append("طريقة ناجحة للبيانات — تأثير محتمل أعلى")

        return context


class AdaptiveTestAdvisor:
    def advise(
        self,
        record: ArjunParameterRecord,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        context = context or {}
        suggestions: List[str] = []

        if context.get("is_auth_parameter"):
            suggestions.append("sqlmap --level 2 --risk 1")
            suggestions.append("nuclei -t http/default-credentials")
        if context.get("is_id_parameter"):
            suggestions.append("nuclei -t http/idor")
        if context.get("is_search_parameter"):
            suggestions.append("nuclei -t http/xss")
        if context.get("method_category") == "mutating":
            suggestions.append("sqlmap --method POST")

        seen = set()
        unique = []
        for s in suggestions:
            if s not in seen:
                seen.add(s)
                unique.append(s)

        return unique[:8]
