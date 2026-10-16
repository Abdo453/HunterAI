"""SQLmap Result Interpreter — L3 Context + L4 Adaptive"""
from __future__ import annotations

import logging
from typing import List, Dict, Any, Optional
from core.sqlmap.schemas import SQLmapFindingRecord

log = logging.getLogger("sqlmap.context")


class ContextEnricher:
    def enrich(self, record: SQLmapFindingRecord) -> Dict[str, Any]:
        context: Dict[str, Any] = {
            "is_auth_parameter": False,
            "is_id_parameter": False,
            "is_search_parameter": False,
            "dbms_family": "unknown",
            "notes": [],
        }

        param_lower = record.parameter.lower()
        dbms_lower = (record.dbms or "").lower()

        auth_kw = ["id", "user", "username", "email", "token", "session", "auth", "login", "pass"]
        id_kw = ["id", "uid", "pid", "oid", "cid", "item_id", "product_id"]
        search_kw = ["q", "query", "search", "keyword", "filter", "name"]

        if any(k in param_lower for k in auth_kw):
            context["is_auth_parameter"] = True
            context["notes"].append("معلمة مصادقة — تأثير محتمل أعلى")
        if any(k in param_lower for k in id_kw):
            context["is_id_parameter"] = True
            context["notes"].append("معلمة معرّف — قد تكون عرضة لـ IDOR")
        if any(k in param_lower for k in search_kw):
            context["is_search_parameter"] = True
            context["notes"].append("معلمة بحث — قد تكشف بيانات組织ية")

        if "mysql" in dbms_lower:
            context["dbms_family"] = "mysql"
        elif "postgresql" in dbms_lower:
            context["dbms_family"] = "postgresql"
        elif "microsoft" in dbms_lower or "mssql" in dbms_lower:
            context["dbms_family"] = "mssql"
        elif "oracle" in dbms_lower:
            context["dbms_family"] = "oracle"

        return context


class AdaptiveAdvisor:
    def advise(self, record: SQLmapFindingRecord, context: Optional[Dict[str, Any]] = None) -> List[str]:
        context = context or {}
        suggestions: List[str] = []

        if context.get("is_auth_parameter"):
            suggestions.append("sqlmap --level 3 --risk 2")
        if context.get("is_id_parameter"):
            suggestions.append("sqlmap --technique U")
        if context.get("is_search_parameter"):
            suggestions.append("sqlmap --tamper=between,randomcase")
        if context.get("dbms_family") != "unknown":
            suggestions.append(f"sqlmap --dbms={context['dbms_family']}")

        if not suggestions:
            suggestions.append("sqlmap --level 2 --risk 1")

        seen = set()
        unique = []
        for s in suggestions:
            if s not in seen:
                seen.add(s)
                unique.append(s)
        return unique[:8]
