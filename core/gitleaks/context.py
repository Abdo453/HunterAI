"""Gitleaks Secret Context Analyzer — L3 Context Intelligence + L4 Adaptive Advisor"""
from __future__ import annotations

import logging
from typing import List, Dict, Any, Optional
from core.gitleaks.schemas import GitleaksFindingRecord

log = logging.getLogger("gitleaks.context")


class ContextEnricher:
    def enrich(self, record: GitleaksFindingRecord) -> Dict[str, Any]:
        context: Dict[str, Any] = {
            "is_credential_file": False,
            "is_config_file": False,
            "is_source_code": False,
            "is_high_risk_secret": False,
            "notes": [],
        }

        file_lower = record.file_path.lower()
        type_lower = record.secret_type.lower()

        cred_kw = [".env", "credentials", "creds", "secrets", "password", "key.pem", "id_rsa"]
        config_kw = ["config", "settings", "ini", "yaml", "yml", "json", "toml"]
        source_kw = [".py", ".js", ".ts", ".java", ".go", ".rb", ".php"]

        if any(k in file_lower for k in cred_kw):
            context["is_credential_file"] = True
            context["notes"].append("ملف بيانات اعتماد — خطورة عالية")
        if any(k in file_lower for k in config_kw):
            context["is_config_file"] = True
            context["notes"].append("ملف إعدادات — قد يحتوي على أسرار")
        if any(k in file_lower for k in source_kw):
            context["is_source_code"] = True
            context["notes"].append("كود مصدر — secret قد يكون مضمنًا")

        if any(kw in record.secret_type.lower().replace(" ", "_") for kw in {"api_key", "aws_access_key", "private_key", "password", "token", "database_url"}):
            context["is_high_risk_secret"] = True
            context["notes"].append("نوع سر عالي الخطر — تدوير فوري مطلوب")

        return context


class AdaptiveTestAdvisor:
    def advise(
        self,
        record: GitleaksFindingRecord,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        context = context or {}
        suggestions: List[str] = []

        if context.get("is_credential_file"):
            suggestions.append("gitleaks --verbose")
        if context.get("is_high_risk_secret"):
            suggestions.append("aws iam rotate-secret")
            suggestions.append("git filter-branch")
        if context.get("is_source_code"):
            suggestions.append("semgrep --config auto")

        seen = set()
        unique = []
        for s in suggestions:
            if s not in seen:
                seen.add(s)
                unique.append(s)

        return unique[:8]
