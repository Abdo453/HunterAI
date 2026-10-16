"""Semgrep Code Finding Analyzer — L3 Context + L4 Adaptive"""
from __future__ import annotations

import logging
from typing import List, Dict, Any, Optional
from core.semgrep.schemas import SemgrepFindingRecord

log = logging.getLogger("semgrep.context")


class ContextEnricher:
    def enrich(self, record: SemgrepFindingRecord) -> Dict[str, Any]:
        context: Dict[str, Any] = {
            "is_security_rule": False,
            "is_input_handling": False,
            "is_auth_rule": False,
            "language": "unknown",
            "notes": [],
        }

        rule_lower = record.rule_id.lower()
        file_lower = record.file_path.lower()

        sec_kw = ["xss", "sqli", "ssti", "ssrf", "rce", "lfi", "rfi", "injection", "deserialization"]
        input_kw = ["input", "param", "query", "request", "post", "get", "cookie", "header"]
        auth_kw = ["auth", "login", "session", "token", "permission", "role", "access"]

        if any(k in rule_lower for k in sec_kw):
            context["is_security_rule"] = True
            context["notes"].append("قاعدة أمنية — زيادة الأولوية")
        if any(k in rule_lower for k in input_kw) or any(k in file_lower for k in input_kw):
            context["is_input_handling"] = True
            context["notes"].append("معالجة مدخلات — قد تكون عرضة للحقن")
        if any(k in rule_lower for k in auth_kw) or any(k in file_lower for k in auth_kw):
            context["is_auth_rule"] = True
            context["notes"].append("قاعدة مصادقة — تأثير محتمل أعلى")

        if file_lower.endswith((".py", ".pyw")):
            context["language"] = "python"
        elif file_lower.endswith((".js", ".jsx", ".ts", ".tsx")):
            context["language"] = "javascript/typescript"
        elif file_lower.endswith((".java", ".kt")):
            context["language"] = "java/kotlin"
        elif file_lower.endswith((".php", ".phtml")):
            context["language"] = "php"
        elif file_lower.endswith((".go",)):
            context["language"] = "go"
        elif file_lower.endswith((".rb",)):
            context["language"] = "ruby"

        return context


class AdaptiveAdvisor:
    def advise(self, record: SemgrepFindingRecord, context: Optional[Dict[str, Any]] = None) -> List[str]:
        context = context or {}
        suggestions: List[str] = []

        if context.get("is_security_rule"):
            suggestions.append("semgrep --config auto")
        if context.get("is_input_handling"):
            suggestions.append("nuclei -t http/sqli")
            suggestions.append("nuclei -t http/xss")
        if context.get("is_auth_rule"):
            suggestions.append("nuclei -t http/idor")
        if context.get("language") == "python":
            suggestions.append("bandit")
        if context.get("language") == "javascript/typescript":
            suggestions.append("eslint-plugin-security")

        seen = set()
        unique = []
        for s in suggestions:
            if s not in seen:
                seen.add(s)
                unique.append(s)
        return unique[:8]
