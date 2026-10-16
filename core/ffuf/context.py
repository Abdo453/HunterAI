"""ffuf Response Intelligence — L3 Context Intelligence + L4 Adaptive Advisor"""
from __future__ import annotations

import logging
from typing import List, Dict, Any, Optional, Set
from core.ffuf.schemas import FfufResultRecord

log = logging.getLogger("ffuf.context")


class ContextEnricher:
    """
    L3: يضيف سياقًا لكل نتيجة ffuf:
      - الربط بين المسار ونتائج Katana endpoints (إن توفرت)
      - تصنيف المسار حسب نوعه (ملف، دليل، واجهة API، لوحة إدارة)
      - تحديد إن كان المسار مرتبطاً بالمصادقة أو الإدارة
    """

    def __init__(
        self,
        katana_endpoints: Optional[List[str]] = None,
        interesting_extensions: Optional[Set[str]] = None,
    ):
        self.katana_endpoints = set(katana_endpoints or [])
        self.interesting_extensions = interesting_extensions or {
            ".php", ".asp", ".aspx", ".jsp", ".py", ".cgi", ".pl",
            ".json", ".xml", ".config", ".env", ".bak", ".old", ".zip",
            ".sql", ".db", ".log", ".conf", ".ini", ".yml", ".yaml",
        }

    def enrich(self, record: FfufResultRecord) -> Dict[str, Any]:
        context: Dict[str, Any] = {
            "is_on_known_endpoint": False,
            "path_category": "unknown",
            "interesting_extension": False,
            "auth_sensitive": False,
            "admin_sensitive": False,
            "file_type": "unknown",
            "notes": [],
        }

        url_lower = record.url.lower()

        # التحقق إن كان المسار على نهاية معروفة من Katana
        if any(url_lower == ep.lower() or url_lower.startswith(ep.lower().rstrip("/") + "/") for ep in self.katana_endpoints):
            context["is_on_known_endpoint"] = True

        # امتداد الملف
        for ext in self.interesting_extensions:
            if url_lower.endswith(ext):
                context["interesting_extension"] = True
                context["file_type"] = ext.lstrip(".")
                break

        # تصنيف المسار
        sensitive_keywords = ["admin", "administrator", "manage", "dashboard", "panel", "config", "setup", "login", "auth", "user"]
        for kw in sensitive_keywords:
            if kw in url_lower:
                if kw in ["admin", "administrator", "manage", "dashboard", "panel", "config", "setup"]:
                    context["admin_sensitive"] = True
                    context["path_category"] = "administration"
                elif kw in ["login", "auth", "user"]:
                    context["auth_sensitive"] = True
                    if context["path_category"] == "unknown":
                        context["path_category"] = "authentication"
                break

        if context["path_category"] == "unknown":
            # إذا لم يُصنف بعد، ننظر إلى الامتداد
            if context["interesting_extension"]:
                context["path_category"] = "file"
            else:
                context["path_category"] = "directory"

        # ملاحظات
        if context["admin_sensitive"]:
            context["notes"].append("مسار إداري — تأثير محتمل أعلى في حال الاختراق")
        if context["auth_sensitive"]:
            context["notes"].append("مسار مصادقة — زيادة أولوية التحليل الأمني")
        if context["interesting_extension"]:
            context["notes"].append(f"ملف بامتداد حساس ({context['file_type']})")
        if context["is_on_known_endpoint"]:
            context["notes"].append("المسار موجود في مخرجات Katana — مُعترف به مسبقاً")
        if record.category == "soft_404":
            context["notes"].append("تُحتمل Soft-404 — قد تكون نتيجة مضللة")

        return context


class AdaptiveWordlistAdvisor:
    """
    L4: يقترح قوائم كلمات مناسبة للسياق بناءً على النتائج الفعلية.
    """

    CONTEXT_WORDLISTS: Dict[str, List[str]] = {
        "administration": [
            "admin", "administrator", "manage", "dashboard", "panel", "config",
            "setup", "wp-admin", "administrator", "moderator", "superuser",
        ],
        "authentication": [
            "login", "signin", "sign-in", "auth", "oauth", "sso", "register",
            "signup", "forgot-password", "reset-password", "account",
        ],
        "file": [
            "backup", "bak", "old", "config", "conf", "env", ".env",
            "database", "db", "sql", "log", "logs", "tmp", "temp",
        ],
        "directory": [
            "images", "css", "js", "assets", "static", "media", "uploads",
            "downloads", "files", "docs", "api", "v1", "v2",
        ],
    }

    def advise(
        self,
        record: FfufResultRecord,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        """
        يُترح قائمة بكلمات مفتاحية مقترحة للفحص التكيفي التالي.
        """
        context = context or {}
        suggestions: List[str] = []

        # بناءً على فئة المسار
        category = context.get("path_category", "directory")
        if category in self.CONTEXT_WORDLISTS:
            suggestions.extend(self.CONTEXT_WORDLISTS[category])

        # بناءً على الامتداد المكتشف
        file_type = context.get("file_type", "")
        if file_type == "php":
            suggestions.extend(["php", "php3", "php4", "phtml", "phar"])
        elif file_type in ["asp", "aspx"]:
            suggestions.extend(["asp", "aspx", "ashx", "asmx"])
        elif file_type == "env":
            suggestions.extend(["env", "env.bak", "env.example", ".env", ".env.local"])

        # بناءً على حالة الاستجابة
        if record.status_code in (301, 302):
            suggestions.extend(["backup", "old", "test", "dev", "staging"])

        # إزالة التكرار مع الحفاظ على الترتيب
        seen = set()
        unique = []
        for s in suggestions:
            if s not in seen:
                seen.add(s)
                unique.append(s)

        return unique[:10]
